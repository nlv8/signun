#include "secp256k1_addon/secp256k1_addon_async.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "secp256k1.h"
#include "secp256k1_recovery.h"

#include "signun_util.h"
#include "secp256k1_addon/secp256k1_addon_util.h"


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
    void *original_data;
    napi_env env;
    napi_value js_noncefn;
} custom_nonce_closure_t;

typedef struct
{
    napi_deferred deferred;
    secp256k1_context *secp256k1context;

    unsigned char private_key[KEY_LENGTH];

    bool result;
} private_key_verify_callback_data_t;

static void private_key_verify_async_execute(napi_env env, void *data)
{
    private_key_verify_callback_data_t *callback_data = (private_key_verify_callback_data_t *) data;

    callback_data->result = secp256k1_ec_seckey_verify(callback_data->secp256k1context, callback_data->private_key);
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
    if (napi_ok != napi_get_boolean(env, callback_data->result, &js_result))
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

typedef struct
{
    napi_deferred deferred;
    secp256k1_context *secp256k1context;

    unsigned char private_key[KEY_LENGTH];
    bool is_compressed;

    bool success;
    size_t result_length;
    unsigned char result[SERIALIZED_PUBLIC_KEY_LENGTH];
} public_key_create_callback_data_t;

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

    secp256k1_ec_pubkey_serialize(callback_data->secp256k1context, &callback_data->result[0], &callback_data->result_length, &public_key, serializationFlags);

    callback_data->success = true;
}

static void public_key_create_async_complete(napi_env env, napi_status status, void *data)
{
    public_key_create_callback_data_t *callback_data = (public_key_create_callback_data_t *) data;

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
    if (napi_ok != napi_create_buffer_copy(env, callback_data->result_length, (void *)callback_data->result, NULL, &js_result))
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

    napi_value null_value;
    THROW_AND_RETURN_NULL_ON_FAILURE(
        napi_get_null(env, &null_value),
        env, "Could not get null value."
    );

    const char *resource_identifier = "secp256k1::async::createPublicKey";
    napi_value create_resource_name;
    THROW_AND_RETURN_NULL_ON_FAILURE(
        napi_create_string_utf8(env, resource_identifier, NAPI_AUTO_LENGTH, &create_resource_name),
        env, "Could not create resource name."
    );

    public_key_create_callback_data_t *create_callback_data = (public_key_create_callback_data_t *)malloc(sizeof (public_key_create_callback_data_t));
    create_callback_data->is_compressed = is_compressed;
    create_callback_data->result_length = SERIALIZED_PUBLIC_KEY_LENGTH;
    create_callback_data->secp256k1context = current_callback_data->secp256k1context;

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

typedef struct
{
    napi_deferred deferred;
    secp256k1_context *secp256k1context;

    unsigned char message[MESSAGE_LENGTH];
    unsigned char private_key[KEY_LENGTH];
    unsigned char data[DATA_LENGTH];
    bool is_data_null;

    bool success;
    unsigned char result[SIGNATURE_LENGTH];
    int recovery_id;
} sign_callback_data_t;

static void sign_async_execute(napi_env env, void *data)
{
    sign_callback_data_t *callback_data = (sign_callback_data_t *) data;

    secp256k1_ecdsa_recoverable_signature signature;

    // Custom noncefn is not supported yet.
    int sign_status = secp256k1_ecdsa_sign_recoverable(callback_data->secp256k1context, &signature, callback_data->message, callback_data->private_key, secp256k1_nonce_function_rfc6979, callback_data->data);
    
    if (0 == sign_status)
    {
        callback_data->success = false;

        return;
    }

    secp256k1_ecdsa_recoverable_signature_serialize_compact(callback_data->secp256k1context, &callback_data->result[0], &callback_data->recovery_id, &signature); 

    callback_data->success = true;
}

static void sign_async_complete(napi_env env, napi_status status, void *data)
{
    sign_callback_data_t *callback_data = (sign_callback_data_t *) data;

    if (napi_ok != status)
    {
        REJECT_WITH_ERROR(env, "The execution was cancelled.", callback_data->deferred);

        free(callback_data);

        return;
    }

    if (!callback_data->success)
    {
        REJECT_WITH_ERROR(env, "Could not sign the message.", callback_data->deferred);

        free(callback_data);

        return;
    }

    napi_value js_signature;
    if (napi_ok != napi_create_buffer_copy(env, SIGNATURE_LENGTH, (void *)callback_data->result, NULL, &js_signature))
    {
        REJECT_WITH_ERROR(env, "Could not set the signature buffer", callback_data->deferred);

        free(callback_data);

        return;
    };

    napi_value js_recovery;
    if (napi_ok != napi_create_int32(env, callback_data->recovery_id, &js_recovery))
    {
        REJECT_WITH_ERROR(env, "Could not set the recovery id.", callback_data->deferred);

        free(callback_data);

        return;
    }

    napi_value js_result;
    if (napi_ok != napi_create_object(env, &js_result))
    {
        REJECT_WITH_ERROR(env, "Could not create the result object.", callback_data->deferred);

        free(callback_data);

        return;
    }

    if (napi_ok != napi_set_named_property(env, js_result, "signature", js_signature))
    {
        REJECT_WITH_ERROR(env, "Could not set named property: 'signature'.", callback_data->deferred);

        free(callback_data);

        return;
    }

    if (napi_ok != napi_set_named_property(env, js_result, "recovery", js_recovery))
    {
        REJECT_WITH_ERROR(env, "Could not set named property: 'recovery'.", callback_data->deferred);

        free(callback_data);

        return;
    }

    napi_resolve_deferred(env, callback_data->deferred, js_result);

    free(callback_data);
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

napi_value secp256k1_addon_sign_async(napi_env env, napi_callback_info info)
{
    size_t argc = 4;
    napi_value argv[4];
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

    size_t private_key_length;
    const unsigned char *private_key;
    THROW_AND_RETURN_NULL_ON_FAILURE(
        napi_get_buffer_info(env, argv[1], (void **) &private_key, &private_key_length),
        env, "Invalid buffer was passed as a private key."
    );

    size_t data_length;
    unsigned char *data = NULL;

    napi_value null_value;
    THROW_AND_RETURN_NULL_ON_FAILURE(
        napi_get_null(env, &null_value),
        env, "Could not get null object"
    );

    bool is_noncefn_null;
    THROW_AND_RETURN_NULL_ON_FAILURE(
        napi_strict_equals(env, argv[2], null_value, &is_noncefn_null),
        env, "Could not check if noncefn is null"
    );

    bool is_data_null;
    THROW_AND_RETURN_NULL_ON_FAILURE(
        napi_strict_equals(env, argv[3], null_value, &is_data_null),
        env, "Could not check if data is null"
    );

    if (is_data_null)
    {
        data = NULL;
    }
    else
    {
        THROW_AND_RETURN_NULL_ON_FAILURE(
            napi_get_buffer_info(env, argv[3], (void **) &data, &data_length),
            env, "Invalid buffer was passed as data."
        );
    }

    const char *resource_identifier = "secp256k1::async::sign";
    napi_value sign_resource_name;
    THROW_AND_RETURN_NULL_ON_FAILURE(
        napi_create_string_utf8(env, resource_identifier, NAPI_AUTO_LENGTH, &sign_resource_name),
        env, "Could not create resource name."
    );

    sign_callback_data_t *sign_callback_data = (sign_callback_data_t *)malloc(sizeof (sign_callback_data_t));
    
    sign_callback_data->secp256k1context = current_callback_data->secp256k1context;

    memcpy(&sign_callback_data->message[0], message, MESSAGE_LENGTH);
    memcpy(&sign_callback_data->private_key[0], private_key, KEY_LENGTH);
    if (data)
    {
        memcpy(&sign_callback_data->data[0], data, DATA_LENGTH);
    }
    sign_callback_data->is_data_null = data;

    napi_value promise;
    if (napi_ok != napi_create_promise(env, &sign_callback_data->deferred, &promise))
    {
        free(sign_callback_data);
        napi_throw_error(env, NULL, "Could not create result promise.");
        return NULL;
    }

    napi_async_work sign_async_work;
    if (napi_ok != napi_create_async_work(env, NULL, sign_resource_name, sign_async_execute, sign_async_complete, sign_callback_data, &sign_async_work))
    {
        REJECT_WITH_ERROR(env, "Could not create async work.", sign_callback_data->deferred);
        free(sign_callback_data);
        return promise;
    }

    napi_status queue_status = napi_queue_async_work(env, sign_async_work);
    if (napi_ok != queue_status)
    {
        REJECT_WITH_ERROR(env, "Could not queue async work.", sign_callback_data->deferred);
        free(sign_callback_data);
        napi_delete_async_work(env, sign_async_work);
        return promise;
    }
    
    return promise;
}

typedef struct
{
    napi_deferred deferred;
    secp256k1_context *secp256k1context;

    unsigned char message[MESSAGE_LENGTH];
    unsigned char raw_signature[SIGNATURE_LENGTH];
    size_t raw_public_key_length;
    unsigned char raw_public_key[SERIALIZED_PUBLIC_KEY_LENGTH];

    bool success;
    bool result;
} verify_callback_data_t;

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

    napi_value js_result;
    if (napi_ok != napi_get_boolean(env, callback_data->result, &js_result))
    {
        REJECT_WITH_ERROR(env, "Could not get a boolean.", callback_data->deferred);

        free(callback_data);

        return;
    }

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

    verify_callback_data_t *verify_callback_data = (verify_callback_data_t *)malloc(sizeof (verify_callback_data_t));
    
    verify_callback_data->secp256k1context = current_callback_data->secp256k1context;

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
