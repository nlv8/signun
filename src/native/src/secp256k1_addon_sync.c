#include "secp256k1_addon_sync.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "secp256k1_recovery.h"

#include "secp256k1_addon_util.h"
#include "signun_util.h"


#define DATA_LENGTH 32
#define MESSAGE_LENGTH 32
#define KEY_LENGTH 32
#define ALGORITHM_LENGTH 16
#define NONCE_LENGTH 32

#define NONCE_FAILED 0
#define NONCE_SUCCESS 1


typedef struct
{
    void *original_data;
    napi_env env;
    napi_value js_noncefn;
} custom_nonce_closure_t;

napi_value secp256k1_addon_private_key_verify_sync(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[1];
    secp256k1_addon_callback_data_t *callback_data;
    THROW_ON_FAILURE(
        napi_get_cb_info(env, info, &argc, argv, NULL, (void **) &callback_data),
        env, "Could not read function arguments."
    );

    size_t private_key_length;
    const unsigned char *private_key;
    THROW_ON_FAILURE(
        napi_get_buffer_info(env, argv[0], (void **) &private_key, &private_key_length),
        env, "Invalid buffer was passed as a private key."
    );

    napi_value js_result;
    const int verify_result = secp256k1_ec_seckey_verify(callback_data->secp256k1context, private_key);
    THROW_ON_FAILURE(
        napi_get_boolean(env, verify_result, &js_result),
        env, "Could not set the result."
    );

    return js_result;
}

napi_value secp256k1_addon_public_key_create_sync(napi_env env, napi_callback_info info)
{
    size_t argc = 2;
    napi_value argv[2];
    secp256k1_addon_callback_data_t *callback_data;
    THROW_ON_FAILURE(
        napi_get_cb_info(env, info, &argc, argv, NULL, (void **) &callback_data),
        env, "Could not read function arguments."
    );

    size_t private_key_length;
    const unsigned char *private_key;
    THROW_ON_FAILURE(
        napi_get_buffer_info(env, argv[0], (void **) &private_key, &private_key_length),
        env, "Invalid buffer was passed as a private key."
    );

    bool is_compressed;
    THROW_ON_FAILURE(
        napi_get_value_bool(env, argv[1], &is_compressed),
        env, "Invalid bool was passed as compressed flag."
    );

    unsigned int serializationFlags = is_compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;

    secp256k1_pubkey public_key;
    if (0 == secp256k1_ec_pubkey_create(callback_data->secp256k1context, &public_key, private_key))
    {
        napi_throw_error(env, NULL, "Could not create the public key.");
    }

    size_t serialized_public_key_length = 65;
    unsigned char serialized_public_key[65];
    secp256k1_ec_pubkey_serialize(callback_data->secp256k1context, &serialized_public_key[0], &serialized_public_key_length, &public_key, serializationFlags);

    napi_value js_result;
    THROW_ON_FAILURE(
        napi_create_buffer_copy(env, serialized_public_key_length, (void *)serialized_public_key, NULL, &js_result),
        env, "Could not set the result buffer"
    );

    return js_result;
}

static int wrapped_js_nonce_fn(unsigned char *nonce, const unsigned char *message, const unsigned char *key, const unsigned char *algorithm, void *data, unsigned int attempt)
{
    custom_nonce_closure_t *nonce_closure_ptr = (custom_nonce_closure_t *) data;
    napi_env env = nonce_closure_ptr->env;

    napi_value message_buffer;
    RETURN_VALUE_ON_FAILURE(
        napi_create_buffer_copy(env, MESSAGE_LENGTH, message, NULL, &message_buffer), NONCE_FAILED
    );

    napi_value key_buffer;
    RETURN_VALUE_ON_FAILURE(
        napi_create_buffer_copy(env, KEY_LENGTH, key, NULL, &key_buffer), NONCE_FAILED
    );

    napi_status status;

    napi_value data_buffer;
    if (nonce_closure_ptr->original_data)
    {
        status = napi_create_buffer_copy(env, DATA_LENGTH, nonce_closure_ptr->original_data, NULL, &data_buffer);
    }
    else
    {
        status = napi_get_null(env, &data_buffer);
    }

    if (napi_ok != status)
    {
        return NONCE_FAILED;
    }

    napi_value algorithm_buffer;
    if (nonce_closure_ptr->original_data)
    {
        status = napi_create_buffer_copy(env, ALGORITHM_LENGTH, algorithm, NULL, &algorithm_buffer);
    }
    else
    {
        status = napi_get_null(env, &algorithm_buffer);
    }

    if (napi_ok != status)
    {
        return NONCE_FAILED;
    }

    napi_value js_attempt;
    RETURN_VALUE_ON_FAILURE(napi_create_uint32(env, attempt, &js_attempt), NONCE_FAILED);

    napi_value global;
    RETURN_VALUE_ON_FAILURE(napi_get_global(env, &global), NONCE_FAILED);

    size_t argc = 5;
    const napi_value argv[] = {
        message_buffer,
        key_buffer,
        algorithm_buffer,
        data_buffer,
        js_attempt
    };

    napi_value nonce_buffer;
    RETURN_VALUE_ON_FAILURE(
        napi_call_function(env, global, nonce_closure_ptr->js_noncefn, argc, argv, &nonce_buffer), NONCE_FAILED
    );

    bool is_nonce_buffer;
    RETURN_VALUE_ON_FAILURE(napi_is_buffer(env, nonce_buffer, &is_nonce_buffer), NONCE_FAILED);
    if (!is_nonce_buffer)
    {
        return NONCE_FAILED;
    }

    size_t nonce_length;
    const unsigned char *nonce_buffer_ptr;
    RETURN_VALUE_ON_FAILURE(
        napi_get_buffer_info(env, nonce_buffer, (void **) &nonce_buffer_ptr, &nonce_length), NONCE_FAILED
    );
    if (nonce_length != NONCE_LENGTH)
    {
        return NONCE_FAILED;
    }

    memcpy(nonce, nonce_buffer_ptr, NONCE_LENGTH);

    return NONCE_SUCCESS;
}

napi_value secp256k1_addon_sign_sync(napi_env env, napi_callback_info info)
{
    size_t argc = 4;
    napi_value argv[4];
    secp256k1_addon_callback_data_t *callback_data;
    THROW_ON_FAILURE(
        napi_get_cb_info(env, info, &argc, argv, NULL, (void **) &callback_data),
        env, "Could not read function arguments."
    );

    size_t message_length;
    const unsigned char *message;
    THROW_ON_FAILURE(
        napi_get_buffer_info(env, argv[0], (void **) &message, &message_length),
        env, "Invalid buffer was passed as message."
    );

    size_t private_key_length;
    const unsigned char *private_key;
    THROW_ON_FAILURE(
        napi_get_buffer_info(env, argv[1], (void **) &private_key, &private_key_length),
        env, "Invalid buffer was passed as a private key."
    );

    size_t data_length;
    unsigned char *data = NULL;

    napi_value null_value;
    THROW_ON_FAILURE(
        napi_get_null(env, &null_value),
        env, "Could not get null object"
    );

    bool is_noncefn_null;
    THROW_ON_FAILURE(
        napi_strict_equals(env, argv[2], null_value, &is_noncefn_null),
        env, "Could not check if noncefn is null"
    );

    bool is_data_null;
    THROW_ON_FAILURE(
        napi_strict_equals(env, argv[3], null_value, &is_data_null),
        env, "Could not check if data is null"
    );

    if (is_data_null)
    {
        data = NULL;
    }
    else
    {
        THROW_ON_FAILURE(
            napi_get_buffer_info(env, argv[3], (void **) &data, &data_length),
            env, "Invalid buffer was passed as data."
        );
    }

    secp256k1_ecdsa_recoverable_signature signature;
    int sign_status;
    if (is_noncefn_null)
    {    
        sign_status = secp256k1_ecdsa_sign_recoverable(callback_data->secp256k1context, &signature, message, private_key, secp256k1_nonce_function_rfc6979, data);
    }
    else
    {
        custom_nonce_closure_t nonce_closure = { data, env, argv[2] };
        sign_status = secp256k1_ecdsa_sign_recoverable(callback_data->secp256k1context, &signature, message, private_key, wrapped_js_nonce_fn, &nonce_closure);
    }
    
    if (0 == sign_status)
    {
        napi_throw_error(env, NULL, "Could not sign the mesage.");
    }

    size_t compact_output_length = 64;
    unsigned char compact_output[64];
    int recovery_id;
    secp256k1_ecdsa_recoverable_signature_serialize_compact(callback_data->secp256k1context, &compact_output[0], &recovery_id, &signature);

    napi_value js_signature;
    THROW_ON_FAILURE(
        napi_create_buffer_copy(env, compact_output_length, (void *)compact_output, NULL, &js_signature),
        env, "Could not set the signature buffer"
    );

    napi_value js_recovery;
    THROW_ON_FAILURE(
        napi_create_int32(env, recovery_id, &js_recovery),
        env, "Could not set the recovery id."
    );

    napi_value js_result;
    THROW_ON_FAILURE(
        napi_create_object(env, &js_result),
        env, "Could not create the result object."
    );   

    THROW_ON_FAILURE(
        napi_set_named_property(env, js_result, "signature", js_signature),
        env, "Could not set named property: 'signature'."
    );

    THROW_ON_FAILURE(
        napi_set_named_property(env, js_result, "recovery", js_recovery),
        env, "Could not set named property: 'recovery'."
    );

    return js_result;
}

napi_value secp256k1_addon_verify_sync(napi_env env, napi_callback_info info)
{
    size_t argc = 3;
    napi_value argv[3];
    secp256k1_addon_callback_data_t *callback_data;
    THROW_ON_FAILURE(
        napi_get_cb_info(env, info, &argc, argv, NULL, (void **) &callback_data),
        env, "Could not read function arguments."
    );

    size_t message_length;
    const unsigned char *message;
    THROW_ON_FAILURE(
        napi_get_buffer_info(env, argv[0], (void **) &message, &message_length),
        env, "Invalid buffer was passed as message."
    );
    
    size_t raw_signature_length;
    const unsigned char *raw_signature;
    THROW_ON_FAILURE(
        napi_get_buffer_info(env, argv[1], (void **) &raw_signature, &raw_signature_length),
        env, "Invalid buffer was passed as signature."
    );

    size_t raw_public_key_length;
    const unsigned char *raw_public_key;
    THROW_ON_FAILURE(
        napi_get_buffer_info(env, argv[2], (void **) &raw_public_key, &raw_public_key_length),
        env, "Invalid buffer was passed as a public key."
    );

    secp256k1_ecdsa_signature signature;
    if (0 == secp256k1_ecdsa_signature_parse_compact(callback_data->secp256k1context, &signature, raw_signature))
    {
        napi_throw_error(env, NULL, "Could not parse the signature.");
    }

    secp256k1_pubkey public_key;
    if (0 == secp256k1_ec_pubkey_parse(callback_data->secp256k1context, &public_key, raw_public_key, raw_public_key_length))
    {
        napi_throw_error(env, NULL, "Could not parse the public key.");
    }

    napi_value js_result;
    const int verify_result = secp256k1_ecdsa_verify(callback_data->secp256k1context, &signature, message, &public_key);
    THROW_ON_FAILURE(
        napi_get_boolean(env, verify_result, &js_result),
        env, "Could not set the result."
    );

    return js_result;
}
