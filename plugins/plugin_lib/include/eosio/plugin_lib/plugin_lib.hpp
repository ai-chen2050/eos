#include <eosio/chain_plugin/chain_plugin.hpp>
#include <eosio/chain/plugin_interface.hpp>

namespace fc{ class variant;}
namespace eosio {

class plugin_lib {
   public:
   ~plugin_lib();

   fc::variant push_action(const vector<string>& permissions, const string& contract_account,
            const string& action,  const fc::variant& action_args_var, chain::plugin_interface::next_function<chain_apis::read_write::push_transaction_results> next);
   
   // create account
   fc::variant create_account(const vector<string>& permissions, const fc::variant& creat_acct_arg,
            chain::plugin_interface::next_function<chain_apis::read_write::push_transaction_results> next);

   fc::variant get_table(const chain_apis::read_only::get_table_rows_params& params);

   fc::variant create_wallet(string& wallet_name);

   void import_privkey(string& wallet_name,string& wallet_key_str);

   void unlock_wallet(string& wallet_name,string& wallet_key);

   void lock_wallet(string& wallet_name);

   static plugin_lib& instance();

   private:
   plugin_lib();
   plugin_lib(plugin_lib&) = delete;
   void operator=(plugin_lib&) = delete;

   vector<chain::permission_level> get_account_permissions(const vector<string>& permissions);


   std::unique_ptr<class plugin_lib_impl> my;
};


}

