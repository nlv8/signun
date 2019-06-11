#include "blake2_addon/addon.h"

#include "signun_util.h"
#include "blake2_addon/simple.h"


napi_status create_secp256k1_addon(napi_env env, napi_value base)
{
    napi_value addon;

    RETURN_ON_FAILURE(napi_create_object(env, &addon));

    const size_t property_count = 2;
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_METHOD("hash", blake2_addon_hash_async, NULL),
        DECLARE_NAPI_METHOD("keyedHash", blake2_addon_keyed_hash_async, NULL)
    };

    RETURN_ON_FAILURE(napi_define_properties(env, addon, property_count, properties));
    RETURN_ON_FAILURE(napi_set_named_property(env, base, "blake2", addon));

    return napi_ok;
}
