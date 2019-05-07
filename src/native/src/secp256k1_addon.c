#include "secp256k1_addon.h"


napi_status create_secp256k1_addon(napi_env env, napi_value base)
{
    napi_value addon;
    napi_status status;

    status = napi_create_object(env, &addon);
    if (status != napi_ok)
    {
        return status;
    }

    status = napi_set_named_property(env, base, "secp256k1", addon);
    if (status != napi_ok)
    {
        return status;
    }

    return napi_ok;
}
