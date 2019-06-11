#include "blake2_addon/blake2_addon.h"

#include "signun_util.h"
#include "blake2_addon/signun_blake2b.h"


napi_status create_blake2_addon(napi_env env, napi_value base)
{
    napi_value blake2b_addon;

    RETURN_ON_FAILURE(napi_create_object(env, &blake2b_addon));

    const size_t property_count = 2;
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_METHOD("hash", blake2_addon_blake2b_hash_async, NULL),
        DECLARE_NAPI_METHOD("keyedHash", blake2_addon_blake2b_keyed_hash_async, NULL)
    };

    RETURN_ON_FAILURE(napi_define_properties(env, blake2b_addon, property_count, properties));
    RETURN_ON_FAILURE(napi_set_named_property(env, base, "blake2b", blake2b_addon));

    return napi_ok;
}
