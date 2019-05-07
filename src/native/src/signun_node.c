#include <node_api.h>
#include <js_native_api.h>


static napi_value init_signun_module(napi_env env, napi_value exports) {
    napi_value result;
    
    napi_create_object(env, &result);

    return result;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init_signun_module)
