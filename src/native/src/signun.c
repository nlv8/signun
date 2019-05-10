#include "secp256k1_addon/secp256k1_addon.h"
#include "signun.h"


static const char *INITIALIZATION_ERROR_MESSAGE = "Could not initialize Signun.";

napi_value create_signun_addon(napi_env env)
{
    napi_value addon;
    napi_status status;

    status = napi_create_object(env, &addon);
    if (status != napi_ok)
    {
        napi_throw_error(env, NULL, INITIALIZATION_ERROR_MESSAGE);
    }

    status = create_secp256k1_addon(env, addon);
    if (status != napi_ok)
    {
        napi_throw_error(env, NULL, INITIALIZATION_ERROR_MESSAGE);
    }

    return addon;
}
