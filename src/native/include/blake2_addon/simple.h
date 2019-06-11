#ifndef __SIGNUN_BLAKE2_ADDON_SIMPLE_H
#define __SIGNUN_BLAKE2_ADDON_SIMPLE_H

#include <node_api.h>


napi_value blake2_addon_hash_async(napi_env env, napi_callback_info info);

napi_value blake2_addon_keyed_hash_async(napi_env env, napi_callback_info info);

#endif
