#ifndef __SIGNUN_SECP256K1_ADDON_UTIL_H
#define __SIGNUN_SECP256K1_ADDON_UTIL_H

#include <node_api.h>

#include "secp256k1.h"

#include "signun_util.h"


#define DATA_LENGTH 32
#define MESSAGE_LENGTH 32
#define KEY_LENGTH 32
#define ALGORITHM_LENGTH 16
#define NONCE_LENGTH 32
#define SIGNATURE_LENGTH 64
#define SERIALIZED_PUBLIC_KEY_LENGTH 65

#define NONCE_FAILED 0
#define NONCE_SUCCESS 1

typedef struct {
    napi_ref private_key_verify;
    napi_ref public_key_create;
    napi_ref sign;
    napi_ref verify;
} async_resource_name_cache_t;

typedef struct
{
    signun_js_value_cache_t js_value_cache;

    async_resource_name_cache_t async_resource_name_cache;

    secp256k1_context *secp256k1context;
} secp256k1_addon_callback_data_t;

#endif
