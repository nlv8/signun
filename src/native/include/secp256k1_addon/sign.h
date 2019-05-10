#ifndef __SIGNUN_SECP256K1_ADDON_SIGN_H
#define __SIGNUN_SECP256K1_ADDON_SIGN_H

#include <js_native_api.h>
#include <node_api.h>


napi_value secp256k1_addon_sign_sync(napi_env env, napi_callback_info info);

napi_value secp256k1_addon_sign_async(napi_env env, napi_callback_info info);

#endif
