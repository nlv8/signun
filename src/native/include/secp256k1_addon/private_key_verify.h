#ifndef __SIGNUN_SECP256K1_ADDON_PRIVATE_KEY_VERIFY_H
#define __SIGNUN_SECP256K1_ADDON_PRIVATE_KEY_VERIFY_H

#include <js_native_api.h>
#include <node_api.h>

napi_value secp256k1_addon_private_key_verify_sync(napi_env env, napi_callback_info info);

napi_value secp256k1_addon_private_key_verify_async(napi_env env, napi_callback_info info);

#endif
