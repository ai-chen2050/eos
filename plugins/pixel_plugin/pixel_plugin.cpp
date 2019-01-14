#include "include/eosio/pixel_plugin/pixel_plugin.hpp"
#include "include/eosio/pixel_plugin/protocol.hpp"

#include <eosio/chain/types.hpp>

#include <eosio/chain/controller.hpp>
#include <eosio/chain/exceptions.hpp>
#include <eosio/chain/block.hpp>
#include <eosio/chain/plugin_interface.hpp>
#include <eosio/producer_plugin/producer_plugin.hpp>
#include <eosio/utilities/key_conversion.hpp>
#include <eosio/chain/contract_types.hpp>
#include <eosio/http_plugin/http_plugin.hpp>

#include <fc/network/message_buffer.hpp>
#include <fc/network/ip.hpp>
#include <fc/io/json.hpp>
#include <fc/io/raw.hpp>
#include <fc/log/appender.hpp>
#include <fc/container/flat.hpp>
#include <fc/reflect/variant.hpp>
#include <fc/crypto/rand.hpp>
#include <fc/exception/exception.hpp>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/host_name.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/intrusive/set.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

using namespace eosio::chain::plugin_interface::compat;

namespace fc {
   extern std::unordered_map<std::string,logger>& get_logger_map();
}

namespace eosio {
   static appbase::abstract_plugin& _pixel_plugin = app().register_plugin<pixel_plugin>();

   using std::vector;
   using std::deque;
   using std::shared_ptr;

   using boost::asio::ip::tcp;
   using boost::asio::ip::address_v4;
   using boost::asio::ip::host_name;
   using boost::intrusive::rbtree;
   using boost::multi_index_container;

   using fc::time_point;
   using fc::time_point_sec;
   using chain::block_state_ptr;


   class psession;

   using psession_ptr = std::shared_ptr<psession>;
   using psession_wptr = std::weak_ptr<psession>;
   using response_func = std::function<void(int,string)>;
   using socket_ptr = shared_ptr<tcp::socket>;

   class pixel_plugin_impl {
   public:
      unique_ptr<tcp::acceptor>        acceptor;
      tcp::endpoint                    listen_endpoint;
      uint32_t                         num_clients = 0;

      std::map<chain::public_key_type,
               chain::private_key_type> private_keys; ///< overlapping with producer keys, also authenticating non-producing nodes


      psession_ptr find_connection( string host )const;

      std::set< psession_ptr >       connections;
      bool                             done = false;

      unique_ptr<boost::asio::steady_timer> transaction_check;
      boost::asio::steady_timer::duration   resp_expected_period;

      chain_plugin*                 chain_plug = nullptr;
      int                           started_sessions = 0;
      shared_ptr<tcp::resolver>     resolver;

      bool start_session( psession_ptr c );
      void start_listen_loop( );
      void start_read_message( psession_ptr c);

      void   close( psession_ptr c );


      void accepted_block_header(const block_state_ptr&);
      void accepted_block(const block_state_ptr&);
      void irreversible_block(const block_state_ptr&);
      void accepted_transaction(const transaction_metadata_ptr&);
      void applied_transaction(const transaction_trace_ptr&);
      void accepted_confirmation(const header_confirmation&);

      bool is_valid( const handshake_message &msg);

      void handle_message( psession_ptr c, const handshake_message &msg);

      void is_transaction_success(psession_ptr c);

      struct transcation_info {
         uint64_t count;
         uint32_t block_num;
         string id;
         string type;
         psession_wptr s;
         bool operator<(const transcation_info &other) const {
            return block_num < other.block_num;
         }
      };
      std::multiset<transcation_info> transcation_infos;

      std::multiset<transcation_info>& get_transcation_infos() { return transcation_infos; }
      boost::optional<std::pair<uint32_t, string>> transction_info_form_msg(const string& msg);
   };

   const fc::string logger_name("pixel_plugin_impl");
   fc::logger plogger;
   std::string plog_format;

#define peer_dlog( PEER, FORMAT, ... ) \
  FC_MULTILINE_MACRO_BEGIN \
   if( plogger.is_enabled( fc::log_level::debug ) ) \
      plogger.log( FC_LOG_MESSAGE( debug, plog_format + FORMAT, __VA_ARGS__ (PEER->get_logger_variant()) ) ); \
  FC_MULTILINE_MACRO_END

#define peer_ilog( PEER, FORMAT, ... ) \
  FC_MULTILINE_MACRO_BEGIN \
   if( plogger.is_enabled( fc::log_level::info ) ) \
      plogger.log( FC_LOG_MESSAGE( info, plog_format + FORMAT, __VA_ARGS__ (PEER->get_logger_variant()) ) ); \
  FC_MULTILINE_MACRO_END

#define peer_wlog( PEER, FORMAT, ... ) \
  FC_MULTILINE_MACRO_BEGIN \
   if( plogger.is_enabled( fc::log_level::warn ) ) \
      plogger.log( FC_LOG_MESSAGE( warn, plog_format + FORMAT, __VA_ARGS__ (PEER->get_logger_variant()) ) ); \
  FC_MULTILINE_MACRO_END

#define peer_elog( PEER, FORMAT, ... ) \
  FC_MULTILINE_MACRO_BEGIN \
   if( plogger.is_enabled( fc::log_level::error ) ) \
      plogger.log( FC_LOG_MESSAGE( error, plog_format + FORMAT, __VA_ARGS__ (PEER->get_logger_variant())) ); \
  FC_MULTILINE_MACRO_END

   static pixel_plugin_impl *my_impl;

   /**
    * default value initializers
    */
   constexpr auto     def_send_buffer_size_mb = 4;
   constexpr auto     def_send_buffer_size = 1024*1024*def_send_buffer_size_mb;
   constexpr auto     def_max_clients = 25; // 0 for unlimited clients
   constexpr auto     def_max_nodes_per_host = 1;
   constexpr auto     def_conn_retry_wait = 30;
   constexpr auto     def_txn_expire_wait = std::chrono::seconds(3);
   constexpr auto     def_resp_expected_wait = std::chrono::seconds(5);
   constexpr auto     def_sync_fetch_span = 100;
   constexpr uint32_t  def_max_just_send = 1500; // roughly 1 "mtu"
   constexpr bool     large_msg_notify = false;

   constexpr auto     message_length_size = 4;
   constexpr auto     message_counter_size = 8;
   constexpr auto     message_header_size = message_length_size + message_counter_size;

   class psession : public std::enable_shared_from_this<psession> {
   public:
      explicit psession( string endpoint );

      explicit psession( socket_ptr s );
      ~psession();
      void initialize();

      socket_ptr              socket;

      fc::message_buffer<1024*1024>    pending_message_buffer;
      fc::optional<std::size_t>        outstanding_read_bytes;
      vector<char>                     rcv_buffer;

      string                  peer_addr;
      unique_ptr<boost::asio::steady_timer> response_expected;

      /** @} */

      const string peer_name() {return peer_addr;}
      bool connected();
      void close();

//      void enqueue( const net_message &msg, bool trigger_send = true );
//      void cancel_sync(go_away_reason);
        void flush_queues();

//      void sync_timeout(boost::system::error_code ec);
//      void fetch_timeout(boost::system::error_code ec);
//
//      void queue_write(std::shared_ptr<vector<char>> buff,
//                       bool trigger_send,
//                       std::function<void(boost::system::error_code, std::size_t)> callback);
//      void do_queue_write();

      /** \brief Process the next message from the pending message buffer
       *
       * Process the next message from the pending_message_buffer.
       * message_length is the already determined length of the data
       * part of the message and impl in the net plugin implementation
       * that will handle the message.
       * Returns true is successful. Returns false if an error was
       * encountered unpacking or processing the message.
       */
      bool process_next_message(pixel_plugin_impl& impl, uint64_t count, uint32_t message_length);
      bool send_response(uint64_t count, const string& msg);

      fc::optional<fc::variant_object> _logger_variant;
      const fc::variant_object& get_logger_variant()  {
         if (!_logger_variant) {
            boost::system::error_code ec;
            auto rep = socket->remote_endpoint(ec);
            string ip = ec ? "<unknown>" : rep.address().to_string();
            string port = ec ? "<unknown>" : std::to_string(rep.port());

            auto lep = socket->local_endpoint(ec);
            string lip = ec ? "<unknown>" : lep.address().to_string();
            string lport = ec ? "<unknown>" : std::to_string(lep.port());

            _logger_variant.emplace(fc::mutable_variant_object()
               ("_name", peer_name())
               ("_ip", ip)
               ("_port", port)
               ("_lip", lip)
               ("_lport", lport)
            );
         }
         return *_logger_variant;
      }
   };

   //---------------------------------------------------------------------------

   psession::psession( string endpoint )
      : socket( std::make_shared<tcp::socket>( std::ref( app().get_io_service() ))),
        peer_addr(endpoint),
        response_expected()
   {
      wlog( "created connection to ${n}", ("n", endpoint) );
      initialize();
   }

   psession::psession( socket_ptr s )
      : socket( s ),
        peer_addr(),
        response_expected()
   {
      wlog( "accepted network connection" );
      initialize();
   }

   psession::~psession() {}

   void psession::initialize() {
      response_expected.reset(new boost::asio::steady_timer(app().get_io_service()));
   }

   bool psession::connected() {
      return (socket && socket->is_open());
   }

   void psession::close() {
      if(socket) {
         socket->close();
      }
      else {
         wlog("no socket to close!");
      }
      pending_message_buffer.reset();
   }

   bool psession::process_next_message(pixel_plugin_impl& impl, uint64_t count, uint32_t message_length) {
      try {
         auto index = pending_message_buffer.read_index();
         rcv_buffer.resize(message_length);

         pending_message_buffer.peek(rcv_buffer.data(), message_length, index);
         pending_message_buffer.advance_read_ptr(message_length);

         string s(rcv_buffer.data(), rcv_buffer.size());
         std::cout << "rev_message_body = " << s << std::endl;
         fc::variant cmd = fc::json::from_string(s);

          message_handle* handle = get_pixel_message_handle(cmd["type"].as_string());
         
         string type_string = cmd["type"].as_string();         

          psession_wptr session(shared_from_this());
          handle->handle_message(cmd, [count, session, type_string, this](const string& msg ) {
             try {
                auto s = session.lock();
                if(!s) throw fc::exception();
                auto info = my_impl->transction_info_form_msg(msg);
               
               if((type_string == string("transfer")) && info) 
                     // std::cout <<"msg is = " << msg << std::endl;
                     std::cout << "[ inserting: block_num  =" << info->first << "\t txs_id = "<< info->second << std::endl;

                if(info) {
                   my_impl->get_transcation_infos().insert(pixel_plugin_impl::transcation_info{count, info->first, info->second, type_string, s});

                   string ret = string("{\"code\":\"0\",\"cmd_type\":\"") + type_string + "\",\"transaction_id\":\"" + info->second + "\",\"confirmed\":\"waitting\"}";
                   s->send_response(count, ret);
                }else {
                   s->send_response(count, msg);
                }
             }
             catch(const std::exception &ex) {
                elog("Exception in pixel handle_message to ${s}", ("s",ex.what()));
                close();
             }
             catch(const fc::exception &ex) {
                elog("Exception in pixel handle_message to ${s}", ("s",ex.to_string()));
                close();
             }
             catch(...) {
                elog("Exception in pixel handle_message." );
                close();
             }
          });
      } catch(  const fc::exception& e ) {
         edump((e.to_detail_string() ));
         impl.close( shared_from_this() );
         return false;
      }
      return true;
   }

   bool psession::send_response(const uint64_t count, const string& msg) {
       if(msg.empty()) {
          elog("Send msg is empty." );
          return false;
       }

       int len = msg.size();
       shared_ptr<vector<char>> buf = make_shared<vector<char>>();
       buf->reserve(message_header_size+len);

       for( int i = 0; i < message_length_size; ++i) { buf->push_back(char(len >> (i*8) & 0xff)); }
       for( int i = 0; i < message_counter_size; ++i) { buf->push_back(char(count >> (i*8) & 0xff)); }
       for(auto& c : msg) buf->push_back(c);

       boost::asio::async_write( *socket,
          boost::asio::buffer( buf->data(), buf->size()),
          [buf](const boost::system::error_code& ec, size_t bytes_transferred) {
             if(ec) {
                dlog("psession send error. the send len size: ${size}, ${error}, ${buf_size}",
                      ("size", bytes_transferred)("error",ec.message())("buf_size", buf->size()));
                return;
             }
          }
       );

      return true;
   }

   boost::optional<std::pair<uint32_t, string>> pixel_plugin_impl::transction_info_form_msg(const string& msg) {
      boost::optional<std::pair<uint32_t, string>> info;

      std::stringstream ss(msg);
      boost::property_tree::ptree root;
      boost::property_tree::ptree processed;
      boost::property_tree::read_json<boost::property_tree::ptree>(ss, root);

      if(root.find("transaction_id") != root.not_found() && root.find("processed") != root.not_found()) {
         string id = root.get<string>("transaction_id");

         processed = root.get_child("processed");
         if(processed.find("block_num") != processed.not_found()) {
            uint32_t block_num = processed.get<uint32_t>("block_num");
            info.emplace(std::make_pair(block_num, id));
         }
      }

      return info;
   }

   bool pixel_plugin_impl::start_session( psession_ptr con ) {
      boost::asio::ip::tcp::no_delay nodelay( true );
      boost::system::error_code ec;
      con->socket->set_option( nodelay, ec );
      if (ec) {
         elog( "connection failed to ${peer}: ${error}",
               ( "peer", con->peer_name())("error",ec.message()));
         close(con);
         return false;
      }
      else {
         start_read_message( con );
         ++started_sessions;
         return true;
      }
   }

   void pixel_plugin_impl::start_listen_loop( ) {
      auto socket = std::make_shared<tcp::socket>( std::ref( app().get_io_service() ) );
      acceptor->async_accept( *socket, [socket,this]( boost::system::error_code ec ) {
            if( !ec ) {
               uint32_t visitors = 0;
               uint32_t from_addr = 0;
               auto paddr = socket->remote_endpoint(ec).address();
               if (ec) {
                  fc_elog(plogger,"Error getting remote endpoint: ${m}",("m", ec.message()));
               }
               else {
                  ++num_clients;
                  psession_ptr c = std::make_shared<psession>( socket );
                  connections.insert( c );
                  start_session( c );
               }
            } else {
               elog( "Error accepting connection: ${m}",( "m", ec.message() ) );
               // For the listed error codes below, recall start_listen_loop()
               switch (ec.value()) {
                  case ECONNABORTED:
                  case EMFILE:
                  case ENFILE:
                  case ENOBUFS:
                  case ENOMEM:
                  case EPROTO:
                     break;
                  default:
                     return;
               }
            }
            start_listen_loop();
         });
   }

   void pixel_plugin_impl::start_read_message( psession_ptr conn ) {

      try {
         if(!conn->socket) {
            return;
         }
         psession_wptr weak_conn = conn;

         std::size_t minimum_read = conn->outstanding_read_bytes ? *conn->outstanding_read_bytes : message_header_size;
         auto completion_handler = [minimum_read](boost::system::error_code ec, std::size_t bytes_transferred) -> std::size_t {
            if (ec || bytes_transferred >= minimum_read ) {
               return 0;
            } else {
               return minimum_read - bytes_transferred;
            }
         };

         boost::asio::async_read(*conn->socket,
            conn->pending_message_buffer.get_buffer_sequence_for_boost_async_read(), completion_handler,
            [this,weak_conn]( boost::system::error_code ec, std::size_t bytes_transferred ) {
               auto conn = weak_conn.lock();
               if (!conn) {
                  return;
               }

               conn->outstanding_read_bytes.reset();

               try {
                  if( !ec ) {
                     if (bytes_transferred > conn->pending_message_buffer.bytes_to_write()) {
                        elog("async_read_some callback: bytes_transfered = ${bt}, buffer.bytes_to_write = ${btw}",
                             ("bt",bytes_transferred)("btw",conn->pending_message_buffer.bytes_to_write()));
                     }

                     conn->pending_message_buffer.advance_write_ptr(bytes_transferred);
                     while (conn->pending_message_buffer.bytes_to_read() > 0) {
                        uint32_t bytes_in_buffer = conn->pending_message_buffer.bytes_to_read();

                        if (bytes_in_buffer < message_header_size) {
                           conn->outstanding_read_bytes.emplace(message_header_size - bytes_in_buffer);
                           break;
                        } else {
                           uint32_t message_length;
                           auto index = conn->pending_message_buffer.read_index();
                           conn->pending_message_buffer.peek(&message_length, sizeof(message_length), index);
                           if(message_length > def_send_buffer_size*2 || message_length == 0) {
                              boost::system::error_code ec;
                              elog("incoming message length unexpected (${i}), from ${p}", ("i", message_length)("p",boost::lexical_cast<std::string>(conn->socket->remote_endpoint(ec))));
                              close(conn);
                              return;
                           }

                           auto total_message_bytes = message_length + message_header_size;

                           if (bytes_in_buffer >= total_message_bytes) {
                              conn->pending_message_buffer.advance_read_ptr(message_length_size);

                              uint64_t count;
                              auto index = conn->pending_message_buffer.read_index();
                              conn->pending_message_buffer.peek(&count, sizeof(count), index);

                              conn->pending_message_buffer.advance_read_ptr(message_counter_size);
                              if (!conn->process_next_message(*this, count, message_length)) {
                                 return;
                              }
                           } else {
                              auto outstanding_message_bytes = total_message_bytes - bytes_in_buffer;
                              auto available_buffer_bytes = conn->pending_message_buffer.bytes_to_write();
                              if (outstanding_message_bytes > available_buffer_bytes) {
                                 conn->pending_message_buffer.add_space( outstanding_message_bytes - available_buffer_bytes );
                              }

                              conn->outstanding_read_bytes.emplace(outstanding_message_bytes);
                              break;
                           }
                        }
                     }
                     start_read_message(conn);
                  } else {
                     auto pname = conn->peer_name();
                     if (ec.value() != boost::asio::error::eof) {
                        elog( "Error reading message from ${p}: ${m}",("p",pname)( "m", ec.message() ) );
                     } else {
                        ilog( "Peer ${p} closed connection",("p",pname) );
                     }
                     close( conn );
                  }
               }
               catch(const std::exception &ex) {
                  string pname = conn ? conn->peer_name() : "no connection name";
                  elog("Exception in handling read data from ${p} ${s}",("p",pname)("s",ex.what()));
                  close( conn );
               }
               catch(const fc::exception &ex) {
                  string pname = conn ? conn->peer_name() : "no connection name";
                  elog("Exception in handling read data ${s}", ("p",pname)("s",ex.to_string()));
                  close( conn );
               }
               catch (...) {
                  string pname = conn ? conn->peer_name() : "no connection name";
                  elog( "Undefined exception hanlding the read data from connection ${p}",( "p",pname));
                  close( conn );
               }
            } );
      } catch (...) {
         string pname = conn ? conn->peer_name() : "no connection name";
         elog( "Undefined exception handling reading ${p}",("p",pname) );
         close( conn );
      }
   }

   void pixel_plugin_impl::is_transaction_success(psession_ptr c) {
      transaction_check->expires_from_now( resp_expected_period);
      transaction_check->async_wait( [this](boost::system::error_code ec) {
         if( !ec) {

         }
         else {
            elog( "Error connection: ${m}",( "m", ec.message()));
         }
      });
   }

   void pixel_plugin_impl::accepted_block_header(const block_state_ptr& block) {
      //cout << "accepted_block_header id = " <<  block->block_num << std::endl;
   }

   void pixel_plugin_impl::accepted_block(const block_state_ptr& block) {
      uint32_t flag = 0;
      static uint32_t send_succeed_num = 0;
      static uint32_t send_fail_num = 0;
      static uint32_t transaction_num = 0;
      uint32_t irr_num = chain_plug->chain().last_irreversible_block_num();
      auto upper_bound = transcation_infos.upper_bound({0, block->block_num, "", "", psession_wptr()});
      for (auto elem : transcation_infos)
      {
         std::cout << "block num is " << elem.block_num << "\t type is " << elem.type << std::endl; 
      }
      for(auto it =  transcation_infos.begin(); it != upper_bound;) {
         // std::cout << "1-----------" << std::endl;
         std::cout << "The transcation_info size = " << transcation_infos.size() << std::endl;
         std::cout << "*it block id = " << it->block_num << "\tComing block_id =" << block->block_num << "\t irr_block_num = " << irr_num <<  std::endl;
         if(it->block_num <= irr_num) {
            std::cout << "1 -----------" << std::endl;
            const transcation_info& info = *it;
            auto conn = info.s.lock();
            if(conn) {
            std::cout << "2 -----------" << std::endl;
            signed_block_ptr sb = chain_plug->chain().fetch_block_by_number(info.block_num);
               if (sb){
                  std::cout << "3 -----------" << std::endl;
                  if( !sb->transactions.empty())
                  {
                     for(auto& transaction: sb->transactions) {
                           transaction_num ++;
                           std::cout << "[transaction_num ] = " << transaction_num << std::endl;
                           if((transaction.trx.contains<packed_transaction>() && info.id == transaction.trx.get<packed_transaction>().id().str())||
                              (transaction.trx.contains<transaction_id_type>() && info.id == transaction.trx.get<transaction_id_type>().str())) {
                           string ret = string("{\"code\":\"0\",\"cmd_type\":\"") + info.type + "\",\"transaction_id\":\"" + info.id + "\",\"confirmed\":\"successed\"}";

                           if(info.type == string("create_system_acct"))
                           {
                              ret = string("{\"code\":\"0\",\"cmd_type\":\"") + info.type + "\",\"transaction_id\":\"" + info.id + "\",\"account_confirmed\":\"successed\"}";
                           } 
                           conn->send_response(info.count, ret);
                           send_succeed_num ++;
                           flag ++;
                           // std::cout << "4 -----------" << std::endl;
                           std::cout << "[send_succeed_num = ]" << send_succeed_num << std::endl;
                           std::cout << ret << std::endl;
                           // it = transcation_infos.erase(it);
                        } else {
                              cout << "\n into fixed next block ---------------- 3 \n";
                              signed_block_ptr sb_next = chain_plug->chain().fetch_block_by_number(info.block_num + 1);
                              if(sb_next){
                                  for(auto& transaction_next: sb_next->transactions) {                          
                                    if((transaction_next.trx.contains<packed_transaction>() && info.id == transaction_next.trx.get<packed_transaction>().id().str())||
                                       (transaction_next.trx.contains<transaction_id_type>() && info.id == transaction_next.trx.get<transaction_id_type>().str())) {
                                       cout << "\n fixed next block succeed ---------------- 4 \n";
                                       string ret = string("{\"code\":\"0\",\"cmd_type\":\"") + info.type + "\",\"transaction_id\":\"" + info.id + "\",\"confirmed\":\"successed\"}";
                                       conn->send_response(info.count, ret);
                                       send_succeed_num ++;
                                       // std::cout << "4 -----------" << std::endl;
                                       std::cout << "[send_succeed_num = ]" << send_succeed_num << std::endl;
                                       std::cout << ret << std::endl;
                                    }else{
                                          // next block not contain trx  
                                          string ret = string("{\"code\":\"0\",\"cmd_type\":\"") + info.type + "\",\"transaction_id\":\"" + info.id + "\",\"confirmed\":\"failed\"}";
                                          conn->send_response(info.count, ret);
                                          send_fail_num ++;
                                          std::cout << "[send_fail_num = ]" << send_fail_num << std::endl;
                                          // std::cout << "5-----------" << std::endl;
                                          std::cout << ret << std::endl;
                                    }
                                 }
                              }   
                        }
                     } 
                  } else{
                     cout << "\n into fixed next block ---------------- 1 \n";
                     signed_block_ptr sb_next = chain_plug->chain().fetch_block_by_number(info.block_num + 1);
                     if(sb_next){
                        cout << "\n into fixed next block ---------------- 2 \n";
                        for(auto& transaction_next: sb_next->transactions) {                          
                           if((transaction_next.trx.contains<packed_transaction>() && info.id == transaction_next.trx.get<packed_transaction>().id().str())||
                              (transaction_next.trx.contains<transaction_id_type>() && info.id == transaction_next.trx.get<transaction_id_type>().str())) {
                              cout << "\n fixed next block succeed ---------------- \n";
                              string ret = string("{\"code\":\"0\",\"cmd_type\":\"") + info.type + "\",\"transaction_id\":\"" + info.id + "\",\"confirmed\":\"successed\"}";
                              conn->send_response(info.count, ret);
                              send_succeed_num ++;
                              // std::cout << "4 -----------" << std::endl;
                              std::cout << "[send_succeed_num = ]" << send_succeed_num << std::endl;
                              std::cout << ret << std::endl;
                           } 
                        }
                     }   
                  } 
               } 
            }   

            it = transcation_infos.erase(it);
         } else {
               ++it;
         } 
      }
   }

   void pixel_plugin_impl::accepted_transaction(const transaction_metadata_ptr& md) {
      //cout << "accepted_transaction id = " <<  md->id.str() << std::endl;
   }

   void pixel_plugin_impl::applied_transaction(const transaction_trace_ptr& txn) {
      //cout << "applied_transaction id = " <<  txn->id.str() << std::endl;
   }

   void pixel_plugin_impl::accepted_confirmation(const header_confirmation& head) {
      //cout << "accepted_confirmation id = " <<  head.block_id.str() << std::endl;
   }

   void pixel_plugin_impl::irreversible_block(const block_state_ptr&block) {}

   void pixel_plugin_impl::close( psession_ptr c ) {
      if( c->peer_addr.empty( ) && c->socket->is_open() ) {
         if (num_clients == 0) {
            fc_wlog( plogger, "num_clients already at 0");
         }
         else {
            --num_clients;
         }
      }
      c->close();
   }

   void pixel_plugin::plugin_initialize( const variables_map& options ) {
      ilog("Initialize pixel plugin");
      try {
          if( options.count( "pixel-contract-name" ))
            contract_name = options.at( "pixel-contract-name" ).as<string>();

          my->resp_expected_period = def_resp_expected_wait;
          my->resolver = std::make_shared<tcp::resolver>( std::ref( app().get_io_service()));

          tcp::resolver::query query( tcp::v4(), "0.0.0.0", "9527");
          // Note: need to add support for IPv6 too?

         my->listen_endpoint = *my->resolver->resolve( query );

         my->acceptor.reset( new tcp::acceptor( app().get_io_service()));
         my->chain_plug = app().find_plugin<chain_plugin>();

      } FC_LOG_AND_RETHROW()
   }

   void pixel_plugin::plugin_startup() {
      if( my->acceptor ) {
         my->acceptor->open(my->listen_endpoint.protocol());
         my->acceptor->set_option(tcp::acceptor::reuse_address(true));
         try {
           my->acceptor->bind(my->listen_endpoint);
         } catch (const std::exception& e) {
           ilog("pixel_plugin::plugin_startup failed to bind to port ${port}",
             ("port", my->listen_endpoint.port()));
           throw e;
         }
         my->acceptor->listen();
         ilog("starting listener...");
         my->start_listen_loop();
      }
      chain::controller&cc = my->chain_plug->chain();
      {
//           cc.accepted_block_header.connect( boost::bind(&pixel_plugin_impl::accepted_block_header, my.get(), _1));
             cc.accepted_block.connect(  boost::bind(&pixel_plugin_impl::accepted_block, my.get(), _1));
//           cc.irreversible_block.connect( boost::bind(&pixel_plugin_impl::irreversible_block, my.get(), _1));
//           cc.accepted_transaction.connect( boost::bind(&pixel_plugin_impl::accepted_transaction, my.get(), _1));
//           cc.applied_transaction.connect( boost::bind(&pixel_plugin_impl::applied_transaction, my.get(), _1));
//           cc.accepted_confirmation.connect( boost::bind(&pixel_plugin_impl::accepted_confirmation, my.get(), _1));
      }
   }

   void pixel_plugin::plugin_shutdown() {
      try {
         ilog( "shutdown.." );
         my->done = true;
         if( my->acceptor ) {
            ilog( "close acceptor" );
            my->acceptor->close();

            ilog( "close ${s} connections",( "s",my->connections.size()) );
            auto cons = my->connections;
            for( auto con : cons ) {
               my->close( con);
            }

            my->acceptor.reset(nullptr);
         }
         ilog( "exit shutdown" );
      }
      FC_CAPTURE_AND_RETHROW()
   }

   void pixel_plugin::handle_exception(const char *call_name, const string& cmd, response_callback cb ) {
      static bool verbose_errors = false;
      try {
         try {
            throw;
         } catch (chain::unsatisfied_authorization& e) {
            error_results results{401, "UnAuthorized", error_results::error_info(e, verbose_errors)};
            cb( fc::json::to_string( results ));
         } catch (chain::tx_duplicate& e) {
            error_results results{409, "Conflict", error_results::error_info(e, verbose_errors)};
            cb(fc::json::to_string( results ));
         } catch (fc::eof_exception& e) {
            error_results results{422, "Unprocessable Entity", error_results::error_info(e, verbose_errors)};
            cb(fc::json::to_string( results ));
            dlog("Bad arguments: ${cmd}", ("cmd", cmd));
         } catch (fc::exception& e) {
            error_results results{500, "Internal Service Error", error_results::error_info(e, verbose_errors)};
            cb(fc::json::to_string( results ));
            if (e.code() != chain::greylist_net_usage_exceeded::code_value/* && e.code() != chain::greylist_cpu_usage_exceeded::code_value*/) {
               elog( "FC Exception encountered while processing pixel.${call}", ( "call", call_name ));
               dlog( "Exception Details: ${e}", ("e", e.to_detail_string()));
            }
         } catch (std::exception& e) {
            error_results results{500, "Internal Service Error", error_results::error_info(fc::exception( FC_LOG_MESSAGE( error, e.what())), verbose_errors)};
            cb( fc::json::to_string( results ));
            elog( "STD Exception encountered while processing pixel.${call}", ( "call", call_name ));
            dlog( "Exception Details: ${e}", ("e", e.what()));
         } catch (...) {
            error_results results{500, "Internal Service Error",
               error_results::error_info(fc::exception( FC_LOG_MESSAGE( error, "Unknown Exception" )), verbose_errors)};
            cb(fc::json::to_string( results ));
            elog( "Unknown Exception encountered while processing ${call}", ( "call", call_name ));
         }
      } catch (...) {
         error_results results{500, "Internal Service Error", error_results::error_info(fc::exception( FC_LOG_MESSAGE( error, "unknow")), verbose_errors)};
         cb(fc::json::to_string( results ));
         std::cerr << "Exception attempting to handle exception for pixel." << call_name << std::endl;
      }
   }


   pixel_plugin::pixel_plugin():my( new pixel_plugin_impl ) { my_impl = my.get();}
   pixel_plugin::~pixel_plugin() {}

   void pixel_plugin::set_program_options( options_description& /*cli*/, options_description& cfg )
   {
      cfg.add_options()( "pixel-contract-name", bpo::value<string>()->default_value( "eospixels" ), "The name of pixel contract.");
      cfg.add_options()( "pixel-team-name", bpo::value<string>()->default_value( "magicsteam11" ), "The name of pixel team.");
   }
}
