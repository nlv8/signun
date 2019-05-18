#include "secp256k1_addon/addon.h"

#include "secp256k1_addon/private_key_verify.h"
#include "secp256k1_addon/public_key_create.h"
#include "secp256k1_addon/sign.h"
#include "secp256k1_addon/verify.h"
#include "secp256k1_addon/util.h"


static secp256k1_addon_callback_data_t callback_data;

napi_status create_secp256k1_addon(napi_env env, napi_value base, signun_js_value_cache_t js_value_cache)
{
    napi_value addon;

    callback_data.js_value_cache = js_value_cache;
    callback_data.secp256k1context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    RETURN_ON_FAILURE(napi_create_object(env, &addon));

    const size_t property_count = 8;
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_METHOD("privateKeyVerifySync", secp256k1_addon_private_key_verify_sync, &callback_data),
        DECLARE_NAPI_METHOD("publicKeyCreateSync", secp256k1_addon_public_key_create_sync, &callback_data),
        DECLARE_NAPI_METHOD("signSync", secp256k1_addon_sign_sync, &callback_data),
        DECLARE_NAPI_METHOD("verifySync", secp256k1_addon_verify_sync, &callback_data),

        DECLARE_NAPI_METHOD("privateKeyVerify", secp256k1_addon_private_key_verify_async, &callback_data),
        DECLARE_NAPI_METHOD("publicKeyCreate", secp256k1_addon_public_key_create_async, &callback_data),
        DECLARE_NAPI_METHOD("sign", secp256k1_addon_sign_async, &callback_data),
        DECLARE_NAPI_METHOD("verify", secp256k1_addon_verify_async, &callback_data)
    };

    RETURN_ON_FAILURE(napi_define_properties(env, addon, property_count, properties));
    RETURN_ON_FAILURE(napi_set_named_property(env, base, "secp256k1", addon));

    return napi_ok;
}
