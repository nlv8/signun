#include "secp256k1_addon/public_key_create.h"

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

    unsigned char private_key[KEY_LENGTH];
    bool is_compressed;

    bool success;
    size_t public_key_length;
    unsigned char public_key[SERIALIZED_PUBLIC_KEY_LENGTH];
} public_key_create_callback_data_t;

napi_value secp256k1_addon_public_key_create_sync(napi_env env, napi_callback_info info)
{
    size_t argc = 2;
    napi_value argv[2];
    secp256k1_addon_callback_data_t *callback_data;
    THROW_AND_RETURN_NULL_ON_FAILURE(
        napi_get_cb_info(env, info, &argc, argv, NULL, (void **) &callback_data),
        env, "Could not read function arguments."
    );

    size_t private_key_length;
    const unsigned char *private_key;
    THROW_AND_RETURN_NULL_ON_FAILURE(
        napi_get_buffer_info(env, argv[0], (void **) &private_key, &private_key_length),
        env, "Invalid buffer was passed as a private key."
    );

    bool is_compressed;
    THROW_AND_RETURN_NULL_ON_FAILURE(
        napi_get_value_bool(env, argv[1], &is_compressed),
        env, "Invalid bool was passed as compressed flag."
    );

    unsigned int serializationFlags = is_compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;

    secp256k1_pubkey public_key;
    if (0 == secp256k1_ec_pubkey_create(callback_data->secp256k1context, &public_key, private_key))
    {
        napi_throw_error(env, NULL, "Could not create the public key.");
        return NULL;
    }

    size_t serialized_public_key_length = 65;
    unsigned char serialized_public_key[65];
    secp256k1_ec_pubkey_serialize(callback_data->secp256k1context, &serialized_public_key[0], &serialized_public_key_length, &public_key, serializationFlags);

    napi_value js_result;
    THROW_AND_RETURN_NULL_ON_FAILURE(
        napi_create_buffer_copy(env, serialized_public_key_length, (void *)serialized_public_key, NULL, &js_result),
        env, "Could not set the result buffer"
    );

    return js_result;
}


static void public_key_create_async_execute(napi_env env, void *data)
{
    public_key_create_callback_data_t *callback_data = (public_key_create_callback_data_t *) data;

    unsigned int serializationFlags = callback_data->is_compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;

    secp256k1_pubkey public_key;
    if (0 == secp256k1_ec_pubkey_create(callback_data->secp256k1context, &public_key, callback_data->private_key))
    {
        callback_data->success = false;
        return;
    }

    secp256k1_ec_pubkey_serialize(callback_data->secp256k1context, &callback_data->public_key[0], &callback_data->public_key_length, &public_key, serializationFlags);

    callback_data->success = true;
}

static void public_key_create_async_complete(napi_env env, napi_status status, void *data)
{
    public_key_create_callback_data_t *callback_data = (public_key_create_callback_data_t *) data;

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
        REJECT_WITH_ERROR(env, "Could not create the public key.", callback_data->deferred);

        free(callback_data);

        return;
    }

    napi_value js_result;
    if (napi_ok != napi_create_buffer_copy(env, callback_data->public_key_length, (void *)callback_data->public_key, NULL, &js_result))
    {
        REJECT_WITH_ERROR(env, "Could not set the result buffer.", callback_data->deferred);

        free(callback_data);

        return;
    }

    napi_resolve_deferred(env, callback_data->deferred, js_result);

    free(callback_data);
}

napi_value secp256k1_addon_public_key_create_async(napi_env env, napi_callback_info info)
{
    size_t argc = 2;
    napi_value argv[2];
    secp256k1_addon_callback_data_t *current_callback_data;
    THROW_AND_RETURN_NULL_ON_FAILURE(
        napi_get_cb_info(env, info, &argc, argv, NULL, (void **) &current_callback_data),
        env, "Could not read function arguments."
    );

    size_t private_key_length;
    unsigned char *private_key;
    THROW_AND_RETURN_NULL_ON_FAILURE(
        napi_get_buffer_info(env, argv[0], (void **) &private_key, &private_key_length),
        env, "Invalid buffer was passed as a private key."
    );

    bool is_compressed;
    THROW_AND_RETURN_NULL_ON_FAILURE(
        napi_get_value_bool(env, argv[1], &is_compressed),
        env, "Invalid bool was passed as compressed flag."
    );

    const char *resource_identifier = "secp256k1::async::createPublicKey";
    napi_value create_resource_name;
    THROW_AND_RETURN_NULL_ON_FAILURE(
        napi_create_string_utf8(env, resource_identifier, NAPI_AUTO_LENGTH, &create_resource_name),
        env, "Could not create resource name."
    );

    public_key_create_callback_data_t *create_callback_data = (public_key_create_callback_data_t *)malloc(sizeof (public_key_create_callback_data_t));
    create_callback_data->is_compressed = is_compressed;
    create_callback_data->public_key_length = SERIALIZED_PUBLIC_KEY_LENGTH;
    create_callback_data->secp256k1context = current_callback_data->secp256k1context;
    create_callback_data->js_value_cache = current_callback_data->js_value_cache;

    memcpy(&create_callback_data->private_key[0], private_key, KEY_LENGTH);

    napi_value promise;
    if (napi_ok != napi_create_promise(env, &create_callback_data->deferred, &promise))
    {
        free(create_callback_data);
        napi_throw_error(env, NULL, "Could not create result promise.");
        return NULL;
    }

    napi_async_work create_async_work;
    if (napi_ok != napi_create_async_work(env, NULL, create_resource_name, public_key_create_async_execute, public_key_create_async_complete, create_callback_data, &create_async_work))
    {
        REJECT_WITH_ERROR(env, "Could not create async work.", create_callback_data->deferred);
        free(create_callback_data);
        return promise;
    }

    create_callback_data->async_work = create_async_work;

    napi_status queue_status = napi_queue_async_work(env, create_async_work);
    if (napi_ok != queue_status)
    {
        REJECT_WITH_ERROR(env, "Could not queue async work.", create_callback_data->deferred);
        free(create_callback_data);
        napi_delete_async_work(env, create_async_work);
        return promise;
    }
    
    return promise;
}
