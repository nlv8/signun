#ifndef __SIGNUN_SECP256K1_ADDON_SYNC_H
#define __SIGNUN_SECP256K1_ADDON_SYNC_H

#include <js_native_api.h>
#include <node_api.h>

#include "secp256k1.h"


napi_value secp256k1_addon_private_key_verify_sync(napi_env env, napi_callback_info info);

napi_value secp256k1_addon_public_key_create_sync(napi_env env, napi_callback_info info);

napi_value secp256k1_addon_sign_sync(napi_env env, napi_callback_info info);

napi_value secp256k1_addon_verify_sync(napi_env env, napi_callback_info info);

#endif
