#include "secp256k1_addon.h"

#include <stdbool.h>
#include <stdio.h>

#include "secp256k1_recovery.h"


static secp256k1_context *secp256k1context;

static napi_value secp256k1_addon_private_key_verify(napi_env env, napi_callback_info info)
{
    napi_status status;
    size_t argc = 1;
    napi_value argv[1];
    status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
    if (status != napi_ok)
    {
        napi_throw_error(env, NULL, "Could not read function arguments.");
    }

    size_t private_key_length;
    const unsigned char *private_key;
    status = napi_get_buffer_info(env, argv[0], (void **) &private_key, &private_key_length);
    if (status != napi_ok)
    {
        napi_throw_error(env, NULL, "Invalid buffer was passed as a private key.");
    }

    napi_value js_result;
    const int verify_result = secp256k1_ec_seckey_verify(secp256k1context, private_key);
    status = napi_get_boolean(env, verify_result, &js_result);
    if (status != napi_ok)
    {
        napi_throw_error(env, NULL, "Could not set the result.");
    }

    return js_result;
}

static napi_value secp256k1_addon_public_key_create(napi_env env, napi_callback_info info)
{
    napi_status status;
    size_t argc = 2;
    napi_value argv[2];
    status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
    if (status != napi_ok)
    {
        napi_throw_error(env, NULL, "Could not read function arguments.");
    }

    size_t private_key_length;
    const unsigned char *private_key;
    status = napi_get_buffer_info(env, argv[0], (void **) &private_key, &private_key_length);
    if (status != napi_ok)
    {
        napi_throw_error(env, NULL, "Invalid buffer was passed as a private key.");
    }

    bool is_compressed;
    status = napi_get_value_bool(env, argv[1], &is_compressed);
    if (status != napi_ok)
    {
        napi_throw_error(env, NULL, "Invalid bool was passed as compressed flag.");
    }
    unsigned int serializationFlags = is_compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;

    secp256k1_pubkey public_key;
    if (0 == secp256k1_ec_pubkey_create(secp256k1context, &public_key, private_key))
    {
        napi_throw_error(env, NULL, "Could not create the public key.");
    }

    size_t serialized_public_key_length = 65;
    unsigned char serialized_public_key[65];
    secp256k1_ec_pubkey_serialize(secp256k1context, &serialized_public_key[0], &serialized_public_key_length, &public_key, serializationFlags);

    napi_value js_result;
    status = napi_create_buffer_copy(env, serialized_public_key_length, (void *)serialized_public_key, NULL, &js_result);
    if (status != napi_ok)
    {
        napi_throw_error(env, NULL, "Could not set the result buffer");
    }

    return js_result;
}

static napi_value secp256k1_addon_sign(napi_env env, napi_callback_info info)
{
    napi_status status;
    size_t argc = 4;
    napi_value argv[4];
    status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
    if (status != napi_ok)
    {
        napi_throw_error(env, NULL, "Could not read function arguments.");
    }

    size_t message_length;
    const unsigned char *message;
    status = napi_get_buffer_info(env, argv[0], (void **) &message, &message_length);
    if (status != napi_ok)
    {
        napi_throw_error(env, NULL, "Invalid buffer was passed as message.");
    }

    size_t private_key_length;
    const unsigned char *private_key;
    status = napi_get_buffer_info(env, argv[1], (void **) &private_key, &private_key_length);
    if (status != napi_ok)
    {
        napi_throw_error(env, NULL, "Invalid buffer was passed as a private key.");
    }

    // Omit data and nonce_fn for now
    void *data = NULL;
    secp256k1_nonce_function noncefn = secp256k1_nonce_function_rfc6979;

    secp256k1_ecdsa_recoverable_signature signature;
    if (0 == secp256k1_ecdsa_sign_recoverable(secp256k1context, &signature, message, private_key, noncefn, data))
    {
        napi_throw_error(env, NULL, "Could not sign the mesage.");
    }

    size_t compact_output_length = 64;
    unsigned char compact_output[64];
    int recovery_id;
    secp256k1_ecdsa_recoverable_signature_serialize_compact(secp256k1context, &compact_output[0], &recovery_id, &signature);

    napi_value js_signature;
    status = napi_create_buffer_copy(env, compact_output_length, (void *)compact_output, NULL, &js_signature);
    if (status != napi_ok)
    {
        napi_throw_error(env, NULL, "Could not set the signature buffer");
    }

    napi_value js_recovery;
    status = napi_create_int32(env, recovery_id, &js_recovery);
    if (status != napi_ok)
    {
        napi_throw_error(env, NULL, "Could not set the recovery id.");
    }

    napi_value js_result;
    status = napi_create_object(env, &js_result);
    if (status != napi_ok)
    {
        napi_throw_error(env, NULL, "Could not create the result object.");
    }    

    status = napi_set_named_property(env, js_result, "signature", js_signature);
    if (status != napi_ok)
    {
        napi_throw_error(env, NULL, "Could not set named property: 'signature'.");
    }

    status = napi_set_named_property(env, js_result, "recovery", js_recovery);
    if (status != napi_ok)
    {
        napi_throw_error(env, NULL, "Could not set named property: 'recovery'.");
    }

    return js_result;
}

static napi_value secp256k1_addon_verify(napi_env env, napi_callback_info info)
{
    napi_status status;
    size_t argc = 3;
    napi_value argv[3];
    status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
    if (status != napi_ok)
    {
        napi_throw_error(env, NULL, "Could not read function arguments.");
    }

    size_t message_length;
    const unsigned char *message;
    status = napi_get_buffer_info(env, argv[0], (void **) &message, &message_length);
    if (status != napi_ok)
    {
        napi_throw_error(env, NULL, "Invalid buffer was passed as message.");
    }

    size_t raw_signature_length;
    const unsigned char *raw_signature;
    status = napi_get_buffer_info(env, argv[1], (void **) &raw_signature, &raw_signature_length);
    if (status != napi_ok)
    {
        napi_throw_error(env, NULL, "Invalid buffer was passed as signature.");
    }

    size_t raw_public_key_length;
    const unsigned char *raw_public_key;
    status = napi_get_buffer_info(env, argv[2], (void **) &raw_public_key, &raw_public_key_length);
    if (status != napi_ok)
    {
        napi_throw_error(env, NULL, "Invalid buffer was passed as a public key.");
    }

    secp256k1_ecdsa_signature signature;
    if (0 == secp256k1_ecdsa_signature_parse_compact(secp256k1context, &signature, raw_signature))
    {
        napi_throw_error(env, NULL, "Could not parse the signature.");
    }

    secp256k1_pubkey public_key;
    if (0 == secp256k1_ec_pubkey_parse(secp256k1context, &public_key, raw_public_key, raw_public_key_length))
    {
        napi_throw_error(env, NULL, "Could not parse the public key.");
    }

    napi_value js_result;
    const int verify_result = secp256k1_ecdsa_verify(secp256k1context, &signature, message, &public_key);
    status = napi_get_boolean(env, verify_result, &js_result);
    if (status != napi_ok)
    {
        napi_throw_error(env, NULL, "Could not set the result.");
    }

    return js_result;
}

napi_status create_secp256k1_addon(napi_env env, napi_value base)
{
    napi_value addon;
    napi_status status;

    status = napi_create_object(env, &addon);
    if (status != napi_ok)
    {
        return status;
    }

    napi_value private_key_verify_fn;
    status = napi_create_function(env, "privateKeyVerify", NAPI_AUTO_LENGTH, secp256k1_addon_private_key_verify, NULL, &private_key_verify_fn);
    if (status != napi_ok)
    {
        return status;
    }

    status = napi_set_named_property(env, addon, "privateKeyVerify", private_key_verify_fn);
    if (status != napi_ok)
    {
        return status;
    }

    napi_value public_key_create_fn;
    status = napi_create_function(env, "publicKeyCreate", NAPI_AUTO_LENGTH, secp256k1_addon_public_key_create, NULL, &public_key_create_fn);
    if (status != napi_ok)
    {
        return status;
    }

    status = napi_set_named_property(env, addon, "publicKeyCreate", public_key_create_fn);
    if (status != napi_ok)
    {
        return status;
    }

    napi_value sign_fn;
    status = napi_create_function(env, "sign", NAPI_AUTO_LENGTH, secp256k1_addon_sign, NULL, &sign_fn);
    if (status != napi_ok)
    {
        return status;
    }

    status = napi_set_named_property(env, addon, "sign", sign_fn);
    if (status != napi_ok)
    {
        return status;
    }

    napi_value verify_fn;
    status = napi_create_function(env, "verify", NAPI_AUTO_LENGTH, secp256k1_addon_verify, NULL, &verify_fn);
    if (status != napi_ok)
    {
        return status;
    }

    status = napi_set_named_property(env, addon, "verify", verify_fn);
    if (status != napi_ok)
    {
        return status;
    }

    status = napi_set_named_property(env, base, "secp256k1", addon);
    if (status != napi_ok)
    {
        return status;
    }

    secp256k1context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    return napi_ok;
}
