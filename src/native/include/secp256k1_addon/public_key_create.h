#ifndef __SIGNUN_SECP256K1_ADDON_PUBLIC_KEY_CREATE_H
#define __SIGNUN_SECP256K1_ADDON_PUBLIC_KEY_CREATE_H

#include <node_api.h>


napi_value secp256k1_addon_public_key_create_sync(napi_env env, napi_callback_info info);

napi_value secp256k1_addon_public_key_create_async(napi_env env, napi_callback_info info);

#endif
