#pragma once

#include <eosio/chain/types.hpp>
#include <eosio/plugin_lib/plugin_lib.hpp>
#include <eosio/chain/action.hpp>
#include <regex>
#include <string>
#include <map>

#include <eosio/wallet_plugin/wallet_plugin.hpp>
#include <eosio/wallet_plugin/wallet_manager.hpp>
#include <fc/static_variant.hpp>
#include <fc/exception/exception.hpp>
#include <fc/variant.hpp>
#include <fc/io/json.hpp>
#include <fc/crypto/private_key.hpp>
#include <fc/crypto/public_key.hpp>


namespace {

 namespace pixel_message_t {
   struct init{};
   struct refresh{};
   struct changedur{};
   struct end{};
   struct createacct{};
   struct withdraw{};
   struct clearpixels{};
   struct clearaccts{};
   struct clearcanvs{};
   struct resetquota{};
   struct dump_tables{};
   struct transfer{};
   struct create_system_acct{};
   struct create_key{};
   struct create_wallet{};
   struct import_privkey{};
   struct unlock_wallet{};
   struct lock_wallet{};
};
}

namespace eosio {

struct async_result_visitor : public fc::visitor<std::string> {
   template<typename T>
   std::string operator()(const T& v) const {
      return fc::json::to_string(v);
   }
};

#define PIXEL_SYNC_CALL(call_name)\
   pixel_plugin::handle_exception(#call_name, fc::json::to_string(cmd), cb)

#define PIXEL_ASYNC_CALL(call_name, call_result)\
[cb, &cmd](const fc::static_variant<fc::exception_ptr, call_result>& result){\
   if (result.contains<fc::exception_ptr>()) {\
      try {\
         result.get<fc::exception_ptr>()->dynamic_rethrow_exception();\
      } catch (...) {\
         pixel_plugin::handle_exception(#call_name, fc::json::to_string(cmd), cb);\
      }\
   } else {\
      cb(result.visit(async_result_visitor()));\
   }\
}

using response_callback = std::function<void(const string&)>;

namespace cmd {
const string init = "init";
const string refresh = "refresh";
const string changedur = "changedur";
const string end = "end";
const string createacct = "createacct";
const string withdraw = "withdraw";
const string clearpixels = "clearpixels";
const string clearaccts = "clearaccts";
const string clearcanvs = "clearcanvs";
const string resetquota = "resetquota";
const string dump_tables = "dump_tables";
const string transfer = "transfer";
const string create_key = "create_key";
const string create_system_acct = "create_system_acct";
const string create_wallet = "create_wallet";
const string import_privkey = "import_privkey";
const string unlock_wallet = "unlock_wallet";
const string lock_wallet = "lock_wallet";
const string unknow = "unknow";

}

using namespace std;
struct message_handle {
   virtual ~message_handle() {}
   message_handle() {
      contract_name = pixel_plugin::contract_name;
   }

   virtual bool handle_message(fc::variant& cmd, response_callback cb) {
      cb("{\"code\":\"500\",\"what\":\"unsupport type of message.\"}");
      throw fc::exception(unspecified_exception_code, "pixel exception", "unknow type of message.");
      return false;
   };
   static string contract_name;
   static string team_name;
};

string message_handle::contract_name = "eospixels";
string message_handle::team_name     = "magicsteam11";
template<typename T>
struct pixel_message_handle: public message_handle {};

template<>
struct pixel_message_handle<pixel_message_t::init>: public message_handle {

   bool handle_message(fc::variant& cmd, response_callback cb) {
      cout << "hello init." << endl;
      try{
         plugin_lib::instance().push_action({contract_name}, contract_name, cmd::init, fc::variant{vector<string>{}},
               PIXEL_ASYNC_CALL(init, chain_apis::read_write::push_transaction_results));
      } catch(  const fc::exception& e ) {
         elog( "pixel init message error!!!");
         PIXEL_SYNC_CALL(init);
         return false;
      }
      return true;
   }

};

template<>
struct pixel_message_handle<pixel_message_t::refresh>: public message_handle {

   bool handle_message(fc::variant& cmd, response_callback cb) {
      cout << "hello refresh." << endl;
     try{
        plugin_lib::instance().push_action({team_name}, contract_name, cmd::refresh, fc::variant{vector<string>{}},
              PIXEL_ASYNC_CALL(refresh, chain_apis::read_write::push_transaction_results));
     } catch(  const fc::exception& e ) {
         elog( "pixel refresh message error!!!");
         PIXEL_SYNC_CALL(refresh);
         return false;
      }
      return true;
   }

};

template<>
struct pixel_message_handle<pixel_message_t::changedur>: public message_handle {

   bool handle_message(fc::variant& cmd, response_callback cb) {
      cout << "hello changedur." << endl;
     try{
        string duration =  cmd["duration"].as_string();

        fc::variant action_args_var{vector<string>{duration}};
        plugin_lib::instance().push_action({team_name}, contract_name, cmd::changedur, action_args_var,
              PIXEL_ASYNC_CALL(changedur, chain_apis::read_write::push_transaction_results));
     } catch(  const fc::exception& e ) {
         elog( "pixel changedur message error!!!");
         PIXEL_SYNC_CALL(changedur);
         return false;
      }
      return true;
   }

};

template<>
struct pixel_message_handle<pixel_message_t::end>: public message_handle {

   bool handle_message(fc::variant& cmd, response_callback cb) {
      cout << "hello end." << endl;
     try{
        string account_name = cmd["account_name"].as_string();

        fc::variant action_args_var{vector<string>{account_name}};
        plugin_lib::instance().push_action({account_name}, contract_name, cmd::end, action_args_var,
              PIXEL_ASYNC_CALL(end, chain_apis::read_write::push_transaction_results));
     } catch(  const fc::exception& e ) {
         elog( "pixel end message error!!!");
         PIXEL_SYNC_CALL(end);
         return false;
      }
      return true;
   }

};

template<>
struct pixel_message_handle<pixel_message_t::createacct>: public message_handle {

   bool handle_message(fc::variant& cmd, response_callback cb) {
      cout << "hello createacct." << endl;
     try{
        string account_name = cmd["account_name"].as_string();

        fc::variant action_args_var{vector<string>{account_name}};
        plugin_lib::instance().push_action({account_name}, contract_name, cmd::createacct, action_args_var,
              PIXEL_ASYNC_CALL(createacct, chain_apis::read_write::push_transaction_results));
     } catch(  const fc::exception& e ) {
         elog( "pixel createacct message error!!!");
         PIXEL_SYNC_CALL(createacct);
         return false;
      }
      return true;
   }

};

template<>
struct pixel_message_handle<pixel_message_t::withdraw>: public message_handle {

   bool handle_message(fc::variant& cmd, response_callback cb) {
      cout << "hello withdraw." << endl;
     try{
        string account_name = cmd["account_name"].as_string();

        fc::variant action_args_var{vector<string>{account_name}};
        plugin_lib::instance().push_action({account_name}, contract_name, cmd::withdraw, action_args_var,
              PIXEL_ASYNC_CALL(withdraw, chain_apis::read_write::push_transaction_results));
     } catch(  const fc::exception& e ) {
         elog( "pixel withdraw message error!!!");
         PIXEL_SYNC_CALL(withdraw);
         return false;
      }
      return true;
   }

};

template<>
struct pixel_message_handle<pixel_message_t::clearpixels>: public message_handle {

   bool handle_message(fc::variant& cmd, response_callback cb) {
      cout << "hello clearpixels." << endl;
     try{
        string count = cmd["count"].as_string();
        string nonce = cmd["nonce"].as_string();

        fc::variant action_args_var{vector<string>{count, nonce}};
        plugin_lib::instance().push_action({team_name}, contract_name, cmd::clearpixels, action_args_var,
              PIXEL_ASYNC_CALL(clearpixels, chain_apis::read_write::push_transaction_results));
     } catch(  const fc::exception& e ) {
         elog( "pixel message error!!!");
         PIXEL_SYNC_CALL(clearpixels);
         return false;
      }
      return true;
   }

};

template<>
struct pixel_message_handle<pixel_message_t::clearaccts>: public message_handle {

   bool handle_message(fc::variant& cmd, response_callback cb) {
      cout << "hello clearaccts." << endl;
     try{
        string count = cmd["count"].as_string();
        string nonce = cmd["nonce"].as_string();

        fc::variant action_args_var{vector<string>{count, nonce}};
        plugin_lib::instance().push_action({team_name}, contract_name, cmd::clearaccts, action_args_var,
              PIXEL_ASYNC_CALL(clearaccts, chain_apis::read_write::push_transaction_results));
     } catch(  const fc::exception& e ) {
         elog( "pixel clearaccts message error!!!");
         PIXEL_SYNC_CALL(clearaccts);
         return false;
      }
      return true;
   }

};

template<>
struct pixel_message_handle<pixel_message_t::clearcanvs>: public message_handle {

   bool handle_message(fc::variant& cmd, response_callback cb) {
      cout << "hello clearcanvs." << endl;
     try{
        string count = cmd["count"].as_string();
        string nonce = cmd["nonce"].as_string();

        fc::variant action_args_var{vector<string>{count, nonce}};
        plugin_lib::instance().push_action({team_name}, contract_name, cmd::clearcanvs, action_args_var,
              PIXEL_ASYNC_CALL(clearcanvs, chain_apis::read_write::push_transaction_results));
     } catch(  const fc::exception& e ) {
         elog( "pixel clearcanvs message error!!!");
         PIXEL_SYNC_CALL(clearcanvs);
         return false;
      }
      return true;
   }

};

template<>
struct pixel_message_handle<pixel_message_t::resetquota>: public message_handle {

   bool handle_message(fc::variant& cmd, response_callback cb) {
      cout << "hello resetquota." << endl;
      try{
         plugin_lib::instance().push_action({team_name}, contract_name, cmd::resetquota, fc::variant{vector<string>{}},
              PIXEL_ASYNC_CALL(resetquota, chain_apis::read_write::push_transaction_results));
      } catch(  const fc::exception& e ) {
         elog( "pixel resetquota message error!!!");
         PIXEL_SYNC_CALL(resetquota);
         return false;
      }
      return true;
   }

};

template<>
struct pixel_message_handle<pixel_message_t::dump_tables>: public message_handle {

   bool handle_message(fc::variant& cmd, response_callback cb) {
      cout << "hello dump_tables." << endl;
      try{
         auto ret = plugin_lib::instance().get_table(cmd.as<chain_apis::read_only::get_table_rows_params>());
         cb(fc::json::to_string(ret));
      } catch(  const fc::exception& e ) {
         elog( "pixel dump_tables message error!!!");
         PIXEL_SYNC_CALL(dump_tables);
         return false;
      }
      return true;
   }

};

template<>
struct pixel_message_handle<pixel_message_t::transfer>: public message_handle {

   bool handle_message(fc::variant& cmd, response_callback cb) {
      cout << "hello transfer." << endl;
      try{
         string from = cmd["from"].as_string();
         string to = cmd["to"].as_string();
         string quantity = cmd["quantity"].as_string();
         string referrer = cmd["referrer"].as_string();
         const auto& pixels = cmd["pixels"].get_array();

         string memo;
         for(const auto& pixel : pixels)
           memo.append(pixel.as_string()+",");

         if(!pixels.empty()) memo.erase(memo.end()-1);
         if(!referrer.empty()) memo.append(string(";") + referrer);

         fc::variant action_args_var{vector<string>{from, to, quantity, memo}};
         plugin_lib::instance().push_action({from}, "eosio.token", cmd::transfer, action_args_var,
               PIXEL_ASYNC_CALL(transfer, chain_apis::read_write::push_transaction_results));
      } catch(  const fc::exception& e ) {
         elog( "pixel message error!!!");
         PIXEL_SYNC_CALL(transfer);
         return false;
      }
      return true;
   }
};

template<>
struct pixel_message_handle<pixel_message_t::create_key>: public message_handle {
   using public_key_type = fc::crypto::public_key;
   using private_key_type = fc::crypto::private_key;
   bool handle_message(fc::variant& cmd, response_callback cb) {
      cout << "hello create_key." << endl;
      try{
            auto pk    = private_key_type::generate();
            auto privs = string(pk);
            auto pubs  = string(pk.get_public_key());
            string resp_key = string("{\"code\":\"0\",\"type\":\"create_key\",\"Public_key\":\"") + pubs + string("\",") + string("\"Private_key\":\"") + privs + string("\"}");
            std::cout << resp_key <<std::endl;
            cb(resp_key);
      } catch(  const fc::exception& e ) {
         elog( "pixel message error!!!");
         PIXEL_SYNC_CALL(create_key);
         return false;
      }
      return true;
   }
};

template<>
struct pixel_message_handle<pixel_message_t::create_system_acct>: public message_handle {
   bool handle_message(fc::variant& cmd, response_callback cb) {
      cout << "hello create_system_acct." << endl;
      try{
         string creator = cmd["creator"].as_string();
         string permission = cmd["permission"].as_string();
         if (! permission.empty())
         {
            creator = permission;
         }

         plugin_lib::instance().create_account({creator}, fc::variant(cmd),
               PIXEL_ASYNC_CALL(create_system_acct, chain_apis::read_write::push_transaction_results));
      } catch(  const fc::exception& e ) {
         elog( "pixel message error!!!");
         PIXEL_SYNC_CALL(create_system_acct);
         return false;
      }
      return true;
   }
};

template<>
struct pixel_message_handle<pixel_message_t::create_wallet>: public message_handle {
   bool handle_message(fc::variant& cmd, response_callback cb) {
      cout << "hello create_wallet." << endl;
      try{
         string name = cmd["wallet_name"].as_string();
         const auto& v = plugin_lib::instance().create_wallet(name);
         string priv_key = v.get_string();
         string ret = string("{\"type\":\"create_wallet\",\"wallet_name\":\"") + name + string("\",") + string("\"Wallet_key\":\"") + priv_key + string("\"}");
         cb(ret);
      } catch(  const fc::exception& e ) {
         elog( "pixel message error!!!");
         PIXEL_SYNC_CALL(create_wallet);
         return false;
      }
      return true;
   }
};

template<>
struct pixel_message_handle<pixel_message_t::import_privkey>: public message_handle {
   bool handle_message(fc::variant& cmd, response_callback cb) {
      cout << "hello import_privkey." << endl;
      try{
         string name = cmd["wallet_name"].as_string();
         string wallet_key_str = cmd["priv_key"].as_string();
         plugin_lib::instance().import_privkey(name,wallet_key_str);
         string resp_key = string("{\"code\":\"0\",\"type\":\"import_privkey\",\"wallet_name\":\"") + name + string("\",") + string("\"memoInfo\":\"") + string("import success") + string("\"}");
         cb(resp_key);
      } catch(  const fc::exception& e ) {
         elog( "pixel message error!!!");
         PIXEL_SYNC_CALL(import_privkey);
         return false;
      }
      return true;
   }
};

template<>
struct pixel_message_handle<pixel_message_t::unlock_wallet>: public message_handle {
   bool handle_message(fc::variant& cmd, response_callback cb) {
      cout << "hello unlock_wallet." << endl;
      try{
         string name = cmd["wallet_name"].as_string();
         string wallet_key_str = cmd["priv_key"].as_string();
         plugin_lib::instance().unlock_wallet(name,wallet_key_str);
         string resp_key = string("{\"code\":\"0\",\"type\":\"unlock_wallet\",\"wallet_name\":\"") + name + string("\",") + string("\"memoInfo\":\"") + string("unlock success") + string("\"}");
         cb(resp_key);
      } catch(  const fc::exception& e ) {
         elog( "pixel message error!!!");
         PIXEL_SYNC_CALL(unlock_wallet);
         return false;
      }
      return true;
   }
};

template<>
struct pixel_message_handle<pixel_message_t::lock_wallet>: public message_handle {
   bool handle_message(fc::variant& cmd, response_callback cb) {
      cout << "hello lock_wallet." << endl;
      try{
         string name = cmd["wallet_name"].as_string();
         plugin_lib::instance().lock_wallet(name);
         string resp_key = string("{\"code\":\"0\",\"type\":\"lock_wallet\",\"wallet_name\":\"") + name + string("\",") + string("\"memoInfo\":\"") + string("lock success") + string("\"}");
         cb(resp_key);
      } catch(  const fc::exception& e ) {
         elog( "pixel message error!!!");
         PIXEL_SYNC_CALL(lock_wallet);
         return false;
      }
      return true;
   }
};

message_handle* get_pixel_message_handle(const string&& s) {
   static map<string, message_handle*> handle = {
      {cmd::init, new pixel_message_handle<pixel_message_t::init>()},
      {cmd::refresh, new pixel_message_handle<pixel_message_t::refresh>()},
      {cmd::changedur, new pixel_message_handle<pixel_message_t::changedur>()},
      {cmd::end, new pixel_message_handle<pixel_message_t::end>()},
      {cmd::createacct, new pixel_message_handle<pixel_message_t::createacct>()},
      {cmd::withdraw, new pixel_message_handle<pixel_message_t::withdraw>()},
      {cmd::clearpixels, new pixel_message_handle<pixel_message_t::clearpixels>()},
      {cmd::clearaccts, new pixel_message_handle<pixel_message_t::clearaccts>()},
      {cmd::clearcanvs, new pixel_message_handle<pixel_message_t::clearcanvs>()},
      {cmd::resetquota, new pixel_message_handle<pixel_message_t::resetquota>()},
      {cmd::dump_tables, new pixel_message_handle<pixel_message_t::dump_tables>()},
      {cmd::transfer, new pixel_message_handle<pixel_message_t::transfer>()},
      {cmd::create_key, new pixel_message_handle<pixel_message_t::create_key>()},
      {cmd::create_system_acct, new pixel_message_handle<pixel_message_t::create_system_acct>()},
      {cmd::create_wallet, new pixel_message_handle<pixel_message_t::create_wallet>()},
      {cmd::import_privkey, new pixel_message_handle<pixel_message_t::import_privkey>()},
      {cmd::unlock_wallet, new pixel_message_handle<pixel_message_t::unlock_wallet>()},
      {cmd::lock_wallet, new pixel_message_handle<pixel_message_t::lock_wallet>()},
      {cmd::unknow, new message_handle()}
   };

   return handle.find(s) != handle.end() ? handle.at(s): handle.at(cmd::unknow);
}

} // namespace eosio
