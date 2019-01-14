file(GLOB HEADERS "include/eosio/plugin_lib/*.hpp" )
add_library( plugin_lib
             plugin_lib.cpp
             httpc.cpp
             ${HEADERS} )

target_link_libraries( plugin_lib chain_plugin producer_plugin appbase fc )
target_include_directories( plugin_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include 
${CMAKE_CURRENT_SOURCE_DIR}/../chain_interface/include
${CMAKE_CURRENT_SOURCE_DIR}/../../libraries/appbase/include
${CMAKE_CURRENT_SOURCE_DIR}/../wallet_plugin/include
${CMAKE_CURRENT_SOURCE_DIR}/../http_plugin/include)
