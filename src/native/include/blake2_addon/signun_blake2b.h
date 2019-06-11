#ifndef __SIGNUN_BLAKE2_ADDON_SIGNUN_BLAKE2B_H
#define __SIGNUN_BLAKE2_ADDON_SIGNUN_BLAKE2B_H

#include <node_api.h>


napi_value blake2_addon_blake2b_hash_async(napi_env env, napi_callback_info info);

napi_value blake2_addon_blake2b_keyed_hash_async(napi_env env, napi_callback_info info);

#endif
