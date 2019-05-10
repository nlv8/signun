#ifndef __SIGNUN_SECP256K1_ADDON_UTIL_H
#define __SIGNUN_SECP256K1_ADDON_UTIL_H

#include "secp256k1.h"


#define DATA_LENGTH 32
#define MESSAGE_LENGTH 32
#define KEY_LENGTH 32
#define ALGORITHM_LENGTH 16
#define NONCE_LENGTH 32
#define SIGNATURE_LENGTH 64
#define SERIALIZED_PUBLIC_KEY_LENGTH 65

#define NONCE_FAILED 0
#define NONCE_SUCCESS 1

typedef struct
{
    secp256k1_context *secp256k1context;
} secp256k1_addon_callback_data_t;

#endif
