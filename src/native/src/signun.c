#include <stdbool.h>

#include "secp256k1_addon/addon.h"
#include "signun.h"

#include "signun_util.h"


static const char *INITIALIZATION_ERROR_MESSAGE = "Could not initialize Signun.";

static signun_js_value_cache_t js_value_cache;

napi_value create_signun_addon(napi_env env)
{
    THROW_AND_RETURN_NULL_ON_FAILURE(
        napi_get_null(env, &js_value_cache.js_null),
        env, INITIALIZATION_ERROR_MESSAGE
    );

    THROW_AND_RETURN_NULL_ON_FAILURE(
        napi_get_boolean(env, true, &js_value_cache.js_true),
        env, INITIALIZATION_ERROR_MESSAGE
    );

    THROW_AND_RETURN_NULL_ON_FAILURE(
        napi_get_boolean(env, false, &js_value_cache.js_false),
        env, INITIALIZATION_ERROR_MESSAGE
    );

    napi_value addon;

    THROW_AND_RETURN_NULL_ON_FAILURE(
        napi_create_object(env, &addon),
        env, INITIALIZATION_ERROR_MESSAGE
    );

    THROW_AND_RETURN_NULL_ON_FAILURE(
        create_secp256k1_addon(env, addon, js_value_cache),
        env, INITIALIZATION_ERROR_MESSAGE
    );

    return addon;
}
