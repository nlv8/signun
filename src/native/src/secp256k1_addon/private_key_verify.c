#include "secp256k1_addon/private_key_verify.h"

#include <stdlib.h>
#include <string.h>

#include "secp256k1.h"

#include "signun_util.h"
#include "secp256k1_addon/util.h"


typedef struct
{
    napi_deferred deferred;
    secp256k1_context *secp256k1context;

    unsigned char private_key[KEY_LENGTH];

    bool is_verified;
} private_key_verify_callback_data_t;

napi_value secp256k1_addon_private_key_verify_sync(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[1];
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

    napi_value js_result;
    const int verify_result = secp256k1_ec_seckey_verify(callback_data->secp256k1context, private_key);
    THROW_AND_RETURN_NULL_ON_FAILURE(
        napi_get_boolean(env, verify_result, &js_result),
        env, "Could not set the result."
    );

    return js_result;
}

static void private_key_verify_async_execute(napi_env env, void *data)
{
    private_key_verify_callback_data_t *callback_data = (private_key_verify_callback_data_t *) data;

    callback_data->is_verified = secp256k1_ec_seckey_verify(callback_data->secp256k1context, callback_data->private_key);
}

static void private_key_verify_async_complete(napi_env env, napi_status status, void *data)
{
    private_key_verify_callback_data_t *callback_data = (private_key_verify_callback_data_t *) data;

    if (napi_ok != status)
    {
        REJECT_WITH_ERROR(env, "The execution was cancelled.", callback_data->deferred);

        free(callback_data);

        return;
    }

    napi_value js_result;
    if (napi_ok != napi_get_boolean(env, callback_data->is_verified, &js_result))
    {
        REJECT_WITH_ERROR(env, "Could not get a boolean.", callback_data->deferred);

        free(callback_data);

        return;
    }

    napi_resolve_deferred(env, callback_data->deferred, js_result);

    free(callback_data);
}

napi_value secp256k1_addon_private_key_verify_async(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[1];
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

    napi_value null_value;
    THROW_AND_RETURN_NULL_ON_FAILURE(
        napi_get_null(env, &null_value),
        env, "Could not get null value."
    );

    const char *resource_identifier = "secp256k1::async::verify";
    napi_value verify_resource_name;
    THROW_AND_RETURN_NULL_ON_FAILURE(
        napi_create_string_utf8(env, resource_identifier, NAPI_AUTO_LENGTH, &verify_resource_name),
        env, "Could not create resource name."
    );

    private_key_verify_callback_data_t *verify_callback_data = (private_key_verify_callback_data_t *)malloc(sizeof (private_key_verify_callback_data_t));
    verify_callback_data->secp256k1context = current_callback_data->secp256k1context;

    memcpy(verify_callback_data->private_key, private_key, KEY_LENGTH);

    napi_value promise;
    if (napi_ok != napi_create_promise(env, &verify_callback_data->deferred, &promise))
    {
        free(verify_callback_data);
        napi_throw_error(env, NULL, "Could not create result promise.");
        return NULL;
    }

    napi_async_work verify_async_work;
    if (napi_ok != napi_create_async_work(env, NULL, verify_resource_name, private_key_verify_async_execute, private_key_verify_async_complete, verify_callback_data, &verify_async_work))
    {
        REJECT_WITH_ERROR(env, "Could not create async work.", verify_callback_data->deferred);
        free(verify_callback_data);
        return promise;
    }

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
