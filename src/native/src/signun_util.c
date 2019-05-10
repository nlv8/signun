#include "signun_util.h"


napi_status signun_create_error(napi_env env, const char *message, napi_value *error)
{
    napi_value js_message;
    RETURN_ON_FAILURE(napi_create_string_utf8(env, message, NAPI_AUTO_LENGTH, &js_message));

    RETURN_ON_FAILURE(napi_create_error(env, NULL, js_message, error));

    return napi_ok;
}
