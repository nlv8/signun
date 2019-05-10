#include "secp256k1_addon.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "secp256k1_addon_sync.h"
#include "signun_util.h"


secp256k1_context* secp256k1context;

napi_status create_secp256k1_addon(napi_env env, napi_value base)
{
    napi_value addon;

    RETURN_ON_FAILURE(napi_create_object(env, &addon));

    const size_t property_count = 4;
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_METHOD("privateKeyVerifySync", secp256k1_addon_private_key_verify_sync),
        DECLARE_NAPI_METHOD("publicKeyCreateSync", secp256k1_addon_public_key_create_sync),
        DECLARE_NAPI_METHOD("signSync", secp256k1_addon_sign_sync),
        DECLARE_NAPI_METHOD("verifySync", secp256k1_addon_verify_sync)
    };

    RETURN_ON_FAILURE(napi_define_properties(env, addon, property_count, properties));
    RETURN_ON_FAILURE(napi_set_named_property(env, base, "secp256k1", addon));

    secp256k1context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    return napi_ok;
}
