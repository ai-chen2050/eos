#include <eosio/plugin_lib/plugin_lib.hpp>
#include <eosio/wallet_plugin/wallet_plugin.hpp>
#include <eosio/wallet_plugin/wallet_manager.hpp>
#include <eosio/chain/abi_serializer.hpp>

#include <regex>

#include <fc/static_variant.hpp>
#include <fc/exception/exception.hpp>
#include <fc/variant.hpp>
#include <fc/io/json.hpp>
#include <fc/crypto/private_key.hpp>

#pragma push_macro("N")
#undef N

#include <boost/process.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/range/algorithm/copy.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/dll/runtime_symbol_info.hpp>

#pragma pop_macro("N")

#include "httpc.hpp"


using namespace std;
using namespace eosio;
using namespace eosio::chain;
using namespace eosio::client::http;
using namespace eosio::chain::plugin_interface;
//using namespace eosio::utilities;
//using namespace eosio::client::localize;
////using namespace eosio::client::config;
//using namespace boost::filesystem;
namespace {

string url = "http://127.0.0.1:8888/";
string wallet_url = "http://127.0.0.1:8900/";

bool no_verify = false;
const string key_store_executable_name = "keosd";
vector<string> headers;
bool   print_request = false;
bool   print_response = false;

eosio::client::http::http_context context;

template<typename T>
fc::variant call( const std::string& url,
                  const std::string& path,
                  const T& v ) {
   try {
      auto sp = std::make_unique<eosio::client::http::connection_param>(context, parse_url(url) + path, no_verify ? false : true, headers);
      return eosio::client::http::do_http_call(*sp, fc::variant(v), print_request, print_response );
   }
   catch(boost::system::system_error& e) {
      if(url == ::url)
         std::cerr << "Failed to connect to nodeos at " << url << "; is nodeos running?" << std::endl;
      else if(url == wallet_url)
         std::cerr << "Failed to connect to keosd at " << url << "; is keosd running?"<< std::endl;
      throw connection_exception(fc::log_messages{FC_LOG_MESSAGE(error, e.what())});
   }
}

template<typename T>
fc::variant call( const std::string& path,
                  const T& v ) { return call( url, path, fc::variant(v) ); }

template<>
fc::variant call( const std::string& url,
                  const std::string& path) { return call( url, path, fc::variant() ); }

uint64_t string_to_name(const string& str) {
   return eosio::chain::string_to_name(str.data());
}
}

namespace eosio {
class plugin_lib_impl {
 public:
   plugin_lib_impl() {
      ensure_keosd_running();
   }

   //resolver for ABI serializer to decode actions in proposed transaction in multisig contract
   optional<abi_serializer> abi_serializer_resolver(const name& account) {
      static unordered_map<account_name, optional<abi_serializer> > abi_cache;
      auto it = abi_cache.find( account );
      if ( it == abi_cache.end() ) {
         auto ro_api = app().get_plugin<chain_plugin>().get_read_only_api();
         auto abi_results = ro_api.get_abi({account});

         optional<abi_serializer> abis;
         if( abi_results.abi.valid() ) {
            abis.emplace( *abi_results.abi, abi_serializer_max_time );
        } else {
          std::cerr << "ABI for contract " << account.to_string() << " not found. Action data will be shown in hex only." << std::endl;
        }
        abi_cache.emplace( account, abis );

        return abis;
      }

      return it->second;
   }

   bytes variant_to_bin( const account_name& account, const action_name& action, const fc::variant& action_args_var ) {
      auto abis = abi_serializer_resolver( account );
      FC_ASSERT( abis.valid(), "No ABI found for ${contract}", ("contract", account));

      auto action_type = abis->get_action_type( action );
      FC_ASSERT( !action_type.empty(), "Unknown action ${action} in contract ${contract}", ("action", action)( "contract", account ));
      return abis->variant_to_binary( action_type, action_args_var, abi_serializer_max_time );
   }

   chain::action generate_nonce_action() {
      return chain::action( {}, config::null_account_name, "nonce", fc::raw::pack(fc::time_point::now().time_since_epoch().count()));
   }

   flat_set<public_key_type> determine_required_keys(const signed_transaction& trx) {
      // TODO better error checking
      //wdump((trx));
      const auto& public_keys = call(wallet_url, wallet_public_keys);
      fc::variant args = fc::mutable_variant_object
            ("transaction", (transaction)trx)
            ("available_keys", public_keys);

      //ro_api.validate();
      auto ro_api = app().get_plugin<chain_plugin>().get_read_only_api();
      auto required_keys = ro_api.get_required_keys(args.as<chain_apis::read_only::get_required_keys_params>());
      return required_keys.required_keys;
   }

   bool local_port_used(const string& lo_address, uint16_t port) {
      using namespace boost::asio;

      io_service ios;
      boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::address::from_string(lo_address), port);
      boost::asio::ip::tcp::socket socket(ios);
      boost::system::error_code ec = error::would_block;
      //connecting/failing to connect to localhost should be always fast - don't care about timeouts
      socket.async_connect(endpoint, [&](const boost::system::error_code& error) { ec = error; } );
      do {
         ios.run_one();
      } while (ec == error::would_block);
      return !ec;
   }

   void try_local_port( const string& lo_address, uint16_t port, uint32_t duration ) {
      using namespace std::chrono;
      auto start_time = duration_cast<std::chrono::milliseconds>( system_clock::now().time_since_epoch() ).count();
      while ( !local_port_used(lo_address, port)) {
        if (duration_cast<std::chrono::milliseconds>( system_clock::now().time_since_epoch()).count() - start_time > duration ) {
          std::cerr << "Unable to connect to keosd, if keosd is running please kill the process and try again.\n";
          throw connection_exception(fc::log_messages{FC_LOG_MESSAGE(error, "Unable to connect to keosd")});
        }
      }
   }

   void ensure_keosd_running() {
      context = eosio::client::http::create_http_context();
      auto parsed_url = parse_url(wallet_url);
      auto resolved_url = resolve_url(context, parsed_url);

      if (!resolved_url.is_loopback)
         return;

      for (const auto& addr: resolved_url.resolved_addresses)
         if (local_port_used(addr, resolved_url.resolved_port))  // Hopefully taken by keosd
           return;

      boost::filesystem::path binPath = boost::dll::program_location();
      binPath.remove_filename();
      // This extra check is necessary when running cleos like this: ./cleos ...
      if (binPath.filename_is_dot())
         binPath.remove_filename();
      binPath.append(key_store_executable_name); // if cleos and keosd are in the same installation directory
      if (!boost::filesystem::exists(binPath)) {
         binPath.remove_filename().remove_filename().append("keosd").append(key_store_executable_name);
      }

      const auto& lo_address = resolved_url.resolved_addresses.front();
      if (boost::filesystem::exists(binPath)) {
         namespace bp = boost::process;
         binPath = boost::filesystem::canonical(binPath);

         std::vector<std::string> pargs;
         pargs.push_back("--http-server-address=" + lo_address + ":" + std::to_string(resolved_url.resolved_port));

         ::boost::process::child keos(binPath, pargs,
                               bp::std_in.close(),
                               bp::std_out > bp::null,
                               bp::std_err > bp::null);
         if (keos.running()) {
            std::cerr << binPath << " launched" << std::endl;
            keos.detach();
            try_local_port(lo_address, resolved_url.resolved_port, 2000);
         } else {
            std::cerr << "No wallet service listening on " << lo_address << ":"
                    << std::to_string(resolved_url.resolved_port) << ". Failed to launch " << binPath << std::endl;
         }
      } else {
         std::cerr << "No wallet service listening on " << lo_address << ":" << std::to_string(resolved_url.resolved_port)
                 << ". Cannot automatically start keosd because keosd was not found." << std::endl;
      }
   }

   //flat_set<public_key_type> determine_required_keys(const signed_transaction& trx) {
   //   // TODO better error checking
   //   //wdump((trx));
   //   auto& wallet_mgr = app().get_plugin<wallet_plugin>().get_wallet_manager();
   //   const auto& public_keys = wallet_mgr.get_public_keys();
   //
   //   auto get_arg = fc::mutable_variant_object
   //           ("transaction", (transaction)trx)
   //           ("available_keys", public_keys);
   //
   //   auto ro_api = app().get_plugin<chain_plugin>().get_read_only_api();
   //   //ro_api.validate();
   //   auto required_keys = ro_api.get_required_keys(fc::variant(get_arg).as<chain_apis::read_only::get_required_keys_params>());
   //   return required_keys.required_keys;
   //}


   void sign_transaction(signed_transaction& trx, flat_set<public_key_type>& required_keys, const chain_id_type& chain_id) {
      fc::variants sign_args = {fc::variant(trx), fc::variant(required_keys), fc::variant(chain_id)};
      const auto& signed_trx = call(wallet_url, wallet_sign_trx, sign_args);
      trx = signed_trx.as<signed_transaction>();
   }

   fc::variant push_transaction( signed_transaction& trx, next_function<chain_apis::read_write::push_transaction_results> next,
         int32_t extra_kcpu = 1000, packed_transaction::compression_type compression = packed_transaction::none ) {
      auto ro_api = app().get_plugin<chain_plugin>().get_read_only_api();
      chain_apis::read_only::get_info_results info = ro_api.get_info(chain_apis::read_only::get_info_params());

      if (trx.signatures.size() == 0) { // #5445 can't change txn content if already signed
        trx.expiration = info.head_block_time + tx_expiration;

        // Set tapos, default to last irreversible block if it's not specified by the user
        block_id_type ref_block_id = info.last_irreversible_block_id;
        trx.set_reference_block(ref_block_id);

        if (tx_force_unique) {
          trx.context_free_actions.emplace_back( generate_nonce_action());
        }

        trx.max_cpu_usage_ms = tx_max_cpu_usage;
        trx.max_net_usage_words = (tx_max_net_usage + 7)/8;
        trx.delay_sec = delaysec;
      }

      if (!tx_skip_sign) {
        auto required_keys = determine_required_keys(trx);
        sign_transaction(trx, required_keys, info.chain_id);
      }

      if (!tx_dont_broadcast) {
        //rw_api.validate();
        fc::variant params = fc::variant(packed_transaction(trx, compression));
        auto rw_api = app().get_plugin<chain_plugin>().get_read_write_api();
        rw_api.push_transaction(params.as<chain_apis::read_write::push_transaction_params>(), next);
        return params;
      } else {
        if (!tx_return_packed) {
         return fc::variant(trx);
        } else {
         return fc::variant(packed_transaction(trx, compression));
        }
      }
   }

   fc::variant push_actions(std::vector<chain::action>& actions, next_function<chain_apis::read_write::push_transaction_results> next,
         int32_t extra_kcpu = 1000, packed_transaction::compression_type compression = packed_transaction::none ) {
      signed_transaction trx;
      trx.actions = std::forward<decltype(actions)>(actions);

      return push_transaction(trx, next, extra_kcpu, compression);
   }

   private:
      fc::microseconds tx_expiration = fc::seconds(30);
      const fc::microseconds abi_serializer_max_time = fc::seconds(10); // No risk to client side serialization taking a long time
      bool tx_force_unique = false;
      bool tx_dont_broadcast = false;
      bool tx_return_packed = false;
      bool tx_skip_sign = false;
      uint8_t  tx_max_cpu_usage = 0;
      uint32_t tx_max_net_usage = 0;

      uint32_t delaysec = 0;
      const string wallet_func_base = "/v1/wallet";
      const string wallet_public_keys = wallet_func_base + "/get_public_keys";
   };

   plugin_lib::plugin_lib():my(new plugin_lib_impl()){
   }
   plugin_lib::~plugin_lib(){}

   plugin_lib& plugin_lib::instance() {
      static plugin_lib _app;
      return _app;
   }

   vector<chain::permission_level> plugin_lib::get_account_permissions(const vector<string>& permissions) {
      auto fixedPermissions = permissions | boost::adaptors::transformed([](const string& p) {
        vector<string> pieces;
        split(pieces, p, boost::algorithm::is_any_of("@"));
        if( pieces.size() == 1 ) pieces.push_back( "active" );
        return chain::permission_level{ .actor = pieces[0], .permission = pieces[1] };
      });
      vector<chain::permission_level> accountPermissions;
      boost::range::copy(fixedPermissions, back_inserter(accountPermissions));
      return accountPermissions;
   }

   fc::variant plugin_lib::push_action(const vector<string>& permissions, const string& contract_account,
            const string& action,  const fc::variant& action_args_var, next_function<chain_apis::read_write::push_transaction_results> next) {
      //auto arg = fc::mutable_variant_object
      //    ("code", contract_account)
      //    ("action", action)
      //    ("args", action_args_var);
      //auto ro_api = app().get_plugin<chain_plugin>().get_read_only_api();
      //auto result = ro_api.abi_json_to_bin(fc::variant(arg).as<chain_apis::read_only::abi_json_to_bin_params>());
      //vector<chain::action> acts = {{chain::action{accountPermissions, contract_account, action, result.binargs} }};
      auto accountPermissions = get_account_permissions(permissions);
      vector<chain::action> acts = {{chain::action{accountPermissions, contract_account, action,  my->variant_to_bin( string_to_name(contract_account), string_to_name(action), action_args_var)} }};

      fc::variant v;
      to_variant(acts, v);
      fc::variant ret = my->push_actions( acts, next);

      return ret;
   }

   fc::variant plugin_lib::create_account(const vector<string>& permissions, const fc::variant& creat_acct_arg,
            chain::plugin_interface::next_function<chain_apis::read_write::push_transaction_results> next) {
      
      string creator = creat_acct_arg["creator"].as_string();
      string name = creat_acct_arg["account_name"].as_string();
      string ownerKey_str = creat_acct_arg["ownerKey"].as_string();
      string activeKey_str = creat_acct_arg["activeKey"].as_string();

      if(!ownerKey_str.size())
         elog("missing ownerKey of creating");
      if( !activeKey_str.size() )
            activeKey_str = ownerKey_str;

      public_key_type owner_key, active_key;
      try {
            owner_key = public_key_type(ownerKey_str);
         } EOS_RETHROW_EXCEPTIONS(public_key_type_exception, "Invalid owner public key: ${public_key}", ("public_key", ownerKey_str));
         try {
            active_key = public_key_type(activeKey_str);
         } EOS_RETHROW_EXCEPTIONS(public_key_type_exception, "Invalid active public key: ${public_key}", ("public_key", activeKey_str));
         
      auto accountPermissions = get_account_permissions(permissions);
      vector<chain::action> acts = {{chain::action{accountPermissions,eosio::chain::newaccount{string_to_name(creator),string_to_name(name),
                                                      eosio::chain::authority{1, {{owner_key, 1}}, {}}, eosio::chain::authority{1, {{active_key, 1}}, {}} }  } }};

      fc::variant v;
      to_variant(acts, v);
      fc::variant ret = my->push_actions( acts, next);

      return ret;
   }

   fc::variant plugin_lib::get_table(const chain_apis::read_only::get_table_rows_params& params) {
      auto ro_api = app().get_plugin<chain_plugin>().get_read_only_api();
      return fc::variant(ro_api.get_table_rows(params));
   }

   fc::variant plugin_lib::create_wallet(string& wallet_name)
   {
      fc::variant wallet = call(wallet_url, wallet_create, wallet_name);
      return wallet;
   }

   void plugin_lib::import_privkey(string& wallet_name,string& wallet_key_str)
   {
      private_key_type wallet_key;
      try {
         wallet_key = private_key_type( wallet_key_str );
      } catch (...) {
         EOS_THROW(private_key_type_exception, "Invalid private key: ${private_key}", ("private_key", wallet_key_str))
      }
      fc::variants vs = {fc::variant(wallet_name), fc::variant(wallet_key)};
      call(wallet_url, wallet_import_key, vs);
   }

   void plugin_lib::unlock_wallet(string& wallet_name,string& wallet_key)
   {
      fc::variants vs = {fc::variant(wallet_name), fc::variant(wallet_key)};
      call(wallet_url, wallet_unlock, vs);
   }

   void plugin_lib::lock_wallet(string& wallet_name)
   {
      call(wallet_url, wallet_lock, wallet_name);
   }
}

