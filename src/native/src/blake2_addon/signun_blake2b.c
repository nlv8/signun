#include "blake2_addon/signun_blake2b.h"

#include <stdlib.h>

#include "blake2.h"

#include "signun_util.h"


#define BLAKE2B_MAX_HASH_LENGTH 64
#define BLAKE2B_MAX_KEY_LENGTH 64

typedef struct
{
    napi_deferred deferred;
    napi_async_work async_work;

    unsigned int data_length;
    unsigned char *data;

    unsigned int hash_length;
    unsigned char hash[BLAKE2B_MAX_HASH_LENGTH];

    int result;
} hash_callback_data_t;

typedef struct
{
    napi_deferred deferred;
    napi_async_work async_work;

    unsigned int data_length;
    unsigned char *data;

    unsigned int key_length;
    unsigned char key[BLAKE2B_MAX_KEY_LENGTH];

    unsigned int hash_length;
    unsigned char hash[BLAKE2B_MAX_HASH_LENGTH];

    int result;
} keyed_hash_callback_data_t;

static void hash_async_execute(napi_env env, void *data)
{
    hash_callback_data_t *callback_data = (hash_callback_data_t *) data;

    callback_data->result = blake2b((void *) callback_data->hash, callback_data->hash_length,
        callback_data->data, callback_data->data_length,
        NULL, 0);
}

static void hash_async_complete(napi_env env, napi_status status, void *data)
{
    hash_callback_data_t *callback_data = (hash_callback_data_t *) data;

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

    if (0 != callback_data->result)
    {
        REJECT_WITH_ERROR(env, "Could not compute hash.", callback_data->deferred);

        free(callback_data);

        return;
    }

    napi_value js_result;
    if (napi_ok != napi_create_buffer_copy(env, callback_data->hash_length, (void *)callback_data->hash, NULL, &js_result))
    {
        REJECT_WITH_ERROR(env, "Could not set the result buffer.", callback_data->deferred);

        free(callback_data);

        return;
    }

    napi_resolve_deferred(env, callback_data->deferred, js_result);

    free(callback_data);
}

napi_value blake2_addon_blake2b_hash_async(napi_env env, napi_callback_info info)
{
    size_t argc = 2;
    napi_value argv[2];
    THROW_AND_RETURN_NULL_ON_FAILURE(
        napi_get_cb_info(env, info, &argc, argv, NULL, NULL),
        env, "Could not read function arguments."
    );

    unsigned int data_length;
    unsigned char *data;
    THROW_AND_RETURN_NULL_ON_FAILURE(
        napi_get_buffer_info(env, argv[0], (void **) &data, &data_length),
        env, "Invalid buffer was passed as data."
    );

    unsigned int hash_length;
    THROW_AND_RETURN_NULL_ON_FAILURE(
        napi_get_value_uint32(env, argv[1], &hash_length),
        env, "Invalid hash length was passed."
    );

    napi_value null_value;
    THROW_AND_RETURN_NULL_ON_FAILURE(
        napi_get_null(env, &null_value),
        env, "Could not get null value."
    );

    const char *resource_identifier = "blake2::async::hash";
    napi_value hash_resource_name;
    THROW_AND_RETURN_NULL_ON_FAILURE(
        napi_create_string_utf8(env, resource_identifier, NAPI_AUTO_LENGTH, &hash_resource_name),
        env, "Could not create resource name."
    );

    hash_callback_data_t *hash_callback_data = (hash_callback_data_t *)malloc(sizeof (hash_callback_data_t));

    hash_callback_data->data_length = data_length;
    hash_callback_data->data = data;
    hash_callback_data->hash_length = hash_length;

    napi_value promise;
    if (napi_ok != napi_create_promise(env, &hash_callback_data->deferred, &promise))
    {
        free(hash_callback_data);
        napi_throw_error(env, NULL, "Could not create result promise.");
        return NULL;
    }

    napi_async_work hash_async_work;
    if (napi_ok != napi_create_async_work(env, NULL, hash_resource_name, hash_async_execute, hash_async_complete, hash_callback_data, &hash_async_work))
    {
        REJECT_WITH_ERROR(env, "Could not create async work.", hash_callback_data->deferred);
        free(hash_callback_data);
        return promise;
    }

    hash_callback_data->async_work = hash_async_work;

    napi_status queue_status = napi_queue_async_work(env, hash_async_work);
    if (napi_ok != queue_status)
    {
        REJECT_WITH_ERROR(env, "Could not queue async work.", hash_callback_data->deferred);
        free(hash_callback_data);
        napi_delete_async_work(env, hash_async_work);
        return promise;
    }

    return promise;
}

static void keyed_hash_async_execute(napi_env env, void *data)
{
    keyed_hash_callback_data_t *callback_data = (keyed_hash_callback_data_t *) data;

    callback_data->result = blake2b((void *) callback_data->hash, callback_data->hash_length,
        callback_data->data, callback_data->data_length,
        callback_data->key, callback_data->key_length);
}

static void keyed_hash_async_complete(napi_env env, napi_status status, void *data)
{
    keyed_hash_callback_data_t *callback_data = (keyed_hash_callback_data_t *) data;

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

    if (0 != callback_data->result)
    {
        REJECT_WITH_ERROR(env, "Could not compute hash.", callback_data->deferred);

        free(callback_data);

        return;
    }

    napi_value js_result;
    if (napi_ok != napi_create_buffer_copy(env, callback_data->hash_length, (void *)callback_data->hash, NULL, &js_result))
    {
        REJECT_WITH_ERROR(env, "Could not set the result buffer.", callback_data->deferred);

        free(callback_data);

        return;
    }

    napi_resolve_deferred(env, callback_data->deferred, js_result);

    free(callback_data);
}

napi_value blake2_addon_blake2b_keyed_hash_async(napi_env env, napi_callback_info info)
{
    size_t argc = 4;
    napi_value argv[4];
    THROW_AND_RETURN_NULL_ON_FAILURE(
        napi_get_cb_info(env, info, &argc, argv, NULL, NULL),
        env, "Could not read function arguments."
    );

    unsigned char *data;
    THROW_AND_RETURN_NULL_ON_FAILURE(
        napi_get_buffer_info(env, argv[0], (void **) &data, NULL),
        env, "Invalid buffer was passed as data."
    );

    unsigned int key_length;
    unsigned char *key;
    THROW_AND_RETURN_NULL_ON_FAILURE(
        napi_get_buffer_info(env, argv[1], (void **) &key, &key_length),
        env, "Invalid buffer was passed as key."
    );

    unsigned int hash_length;
    THROW_AND_RETURN_NULL_ON_FAILURE(
        napi_get_value_uint32(env, argv[2], &hash_length),
        env, "Invalid hash length was passed."
    );

    unsigned int data_length;
    THROW_AND_RETURN_NULL_ON_FAILURE(
        napi_get_value_uint32(env, argv[3], &data_length),
        env, "Invalid data length was passed."
    );

    const char *resource_identifier = "blake2::async::keyed_hash";
    napi_value keyed_hash_resource_name;
    THROW_AND_RETURN_NULL_ON_FAILURE(
        napi_create_string_utf8(env, resource_identifier, NAPI_AUTO_LENGTH, &keyed_hash_resource_name),
        env, "Could not create resource name."
    );

    keyed_hash_callback_data_t *keyed_hash_callback_data = (keyed_hash_callback_data_t *)malloc(sizeof (keyed_hash_callback_data_t));

    keyed_hash_callback_data->data_length = data_length;
    keyed_hash_callback_data->data = data;
    keyed_hash_callback_data->key_length = key_length;
    memcpy(keyed_hash_callback_data->key, key, key_length);
    keyed_hash_callback_data->hash_length = hash_length;

    napi_value promise;
    if (napi_ok != napi_create_promise(env, &keyed_hash_callback_data->deferred, &promise))
    {
        free(keyed_hash_callback_data);
        napi_throw_error(env, NULL, "Could not create result promise.");
        return NULL;
    }

    napi_async_work keyed_hash_async_work;
    if (napi_ok != napi_create_async_work(env, NULL, keyed_hash_resource_name, keyed_hash_async_execute, keyed_hash_async_complete, keyed_hash_callback_data, &keyed_hash_async_work))
    {
        REJECT_WITH_ERROR(env, "Could not create async work.", keyed_hash_callback_data->deferred);
        free(keyed_hash_callback_data);
        return promise;
    }

    keyed_hash_callback_data->async_work = keyed_hash_async_work;

    napi_status queue_status = napi_queue_async_work(env, keyed_hash_async_work);
    if (napi_ok != queue_status)
    {
        REJECT_WITH_ERROR(env, "Could not queue async work.", keyed_hash_callback_data->deferred);
        free(keyed_hash_callback_data);
        napi_delete_async_work(env, keyed_hash_async_work);
        return promise;
    }

    return promise;
}
