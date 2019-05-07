#include <node_api.h>

#include "signun.h"


static napi_value init_signun(napi_env env, napi_value exports) {
    return create_signun_addon(env);
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init_signun)
