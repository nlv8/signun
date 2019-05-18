#include "secp256k1_addon/sign.h"

#include <stdlib.h>
#include <string.h>

#include "secp256k1.h"

#include "signun_util.h"
#include "secp256k1_addon/util.h"


typedef struct
{
    napi_deferred deferred;
    secp256k1_context *secp256k1context;
    signun_js_value_cache_t js_value_cache;
    napi_async_work async_work;

    unsigned char message[MESSAGE_LENGTH];
    unsigned char raw_signature[SIGNATURE_LENGTH];
    size_t raw_public_key_length;
    unsigned char raw_public_key[SERIALIZED_PUBLIC_KEY_LENGTH];

    bool success;
    bool result;
} verify_callback_data_t;

napi_value secp256k1_addon_verify_sync(napi_env env, napi_callback_info info)
{
    size_t argc = 3;
    napi_value argv[3];
    secp256k1_addon_callback_data_t *callback_data;
    THROW_AND_RETURN_NULL_ON_FAILURE(
        napi_get_cb_info(env, info, &argc, argv, NULL, (void **) &callback_data),
        env, "Could not read function arguments."
    );

    size_t message_length;
    const unsigned char *message;
    THROW_AND_RETURN_NULL_ON_FAILURE(
        napi_get_buffer_info(env, argv[0], (void **) &message, &message_length),
        env, "Invalid buffer was passed as message."
    );
    
    size_t raw_signature_length;
    const unsigned char *raw_signature;
    THROW_AND_RETURN_NULL_ON_FAILURE(
        napi_get_buffer_info(env, argv[1], (void **) &raw_signature, &raw_signature_length),
        env, "Invalid buffer was passed as signature."
    );

    size_t raw_public_key_length;
    const unsigned char *raw_public_key;
    THROW_AND_RETURN_NULL_ON_FAILURE(
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

    const int verify_result = secp256k1_ecdsa_verify(callback_data->secp256k1context, &signature, message, &public_key);

    return verify_result
        ? callback_data->js_value_cache.js_true
        : callback_data->js_value_cache.js_false;
}

static void verify_async_execute(napi_env env, void *data)
{
    verify_callback_data_t *callback_data = (verify_callback_data_t *) data;

    secp256k1_ecdsa_signature signature;
    if (0 == secp256k1_ecdsa_signature_parse_compact(callback_data->secp256k1context, &signature, callback_data->raw_signature))
    {
        callback_data->success = false;
        return;
    }

    secp256k1_pubkey public_key;
    if (0 == secp256k1_ec_pubkey_parse(callback_data->secp256k1context, &public_key, callback_data->raw_public_key, callback_data->raw_public_key_length))
    {
        callback_data->success = false;
        return;
    }

    callback_data->success = true;

    callback_data->result = secp256k1_ecdsa_verify(callback_data->secp256k1context, &signature, callback_data->message, &public_key);
}

static void verify_async_complete(napi_env env, napi_status status, void *data)
{
    verify_callback_data_t *callback_data = (verify_callback_data_t *) data;

    if (napi_ok != napi_delete_async_work(env, callback_data->async_work))
    {
        REJECT_WITH_ERROR(env, "Could not delete async work.", callback_data->deferred);

        free(callback_data);

        return;
    }

    if (napi_ok != status)
    {
        REJECT_WITH_ERROR(env, "The execution was cancelled.", callback_data->deferred);

        free(callback_data);

        return;
    }

    if (!callback_data->success)
    {
        REJECT_WITH_ERROR(env, "Could not verify the signature.", callback_data->deferred);

        free(callback_data);

        return;
    }

    napi_value js_result = callback_data->result
        ? callback_data->js_value_cache.js_true
        : callback_data->js_value_cache.js_false;

    napi_resolve_deferred(env, callback_data->deferred, js_result);

    free(callback_data);
}

napi_value secp256k1_addon_verify_async(napi_env env, napi_callback_info info)
{
    size_t argc = 3;
    napi_value argv[3];
    secp256k1_addon_callback_data_t *current_callback_data;
    THROW_AND_RETURN_NULL_ON_FAILURE(
        napi_get_cb_info(env, info, &argc, argv, NULL, (void **) &current_callback_data),
        env, "Could not read function arguments."
    );

    size_t message_length;
    const unsigned char *message;
    THROW_AND_RETURN_NULL_ON_FAILURE(
        napi_get_buffer_info(env, argv[0], (void **) &message, &message_length),
        env, "Invalid buffer was passed as message."
    );
    
    size_t raw_signature_length;
    const unsigned char *raw_signature;
    THROW_AND_RETURN_NULL_ON_FAILURE(
        napi_get_buffer_info(env, argv[1], (void **) &raw_signature, &raw_signature_length),
        env, "Invalid buffer was passed as signature."
    );

    size_t raw_public_key_length;
    const unsigned char *raw_public_key;
    THROW_AND_RETURN_NULL_ON_FAILURE(
        napi_get_buffer_info(env, argv[2], (void **) &raw_public_key, &raw_public_key_length),
        env, "Invalid buffer was passed as a public key."
    );

    const char *resource_identifier = "secp256k1::async::verify";
    napi_value verify_resource_name;
    THROW_AND_RETURN_NULL_ON_FAILURE(
        napi_create_string_utf8(env, resource_identifier, NAPI_AUTO_LENGTH, &verify_resource_name),
        env, "Could not create resource name."
    );

    verify_callback_data_t *verify_callback_data = (verify_callback_data_t *)malloc(sizeof (verify_callback_data_t));
    
    verify_callback_data->secp256k1context = current_callback_data->secp256k1context;
    verify_callback_data->js_value_cache = current_callback_data->js_value_cache;

    memcpy(&verify_callback_data->message[0], message, MESSAGE_LENGTH);
    memcpy(&verify_callback_data->raw_signature[0], raw_signature, raw_signature_length);
    verify_callback_data->raw_public_key_length = raw_public_key_length;
    memcpy(&verify_callback_data->raw_public_key[0], raw_public_key, raw_public_key_length);

    napi_value promise;
    if (napi_ok != napi_create_promise(env, &verify_callback_data->deferred, &promise))
    {
        free(verify_callback_data);
        napi_throw_error(env, NULL, "Could not create result promise.");
        return NULL;
    }

    napi_async_work verify_async_work;
    if (napi_ok != napi_create_async_work(env, NULL, verify_resource_name, verify_async_execute, verify_async_complete, verify_callback_data, &verify_async_work))
    {
        REJECT_WITH_ERROR(env, "Could not create async work.", verify_callback_data->deferred);
        free(verify_callback_data);
        return promise;
    }

    verify_callback_data->async_work = verify_async_work;

    napi_status queue_status = napi_queue_async_work(env, verify_async_work);
    if (napi_ok != queue_status)
    {
        REJECT_WITH_ERROR(env, "Could not queue async work.", verify_callback_data->deferred);
        free(verify_callback_data);
        napi_delete_async_work(env, verify_async_work);
        return promise;
    }
    
    return promise;
}
