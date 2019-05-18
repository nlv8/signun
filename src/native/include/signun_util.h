#ifndef __SIGNUN_UTIL_H
#define __SIGNUN_UTIL_H

#include <node_api.h>


#define DECLARE_NAPI_METHOD(name, function, data)     \
{ name, NULL, function, NULL, NULL, NULL, napi_default | napi_enumerable, data }

#define RETURN_ON_FAILURE(call)             \
    do                                      \
    {                                       \
        napi_status __unique_status = call; \
        if (napi_ok != __unique_status)     \
        {                                   \
            return __unique_status;         \
        }                                   \
    } while (0)

#define RETURN_VALUE_ON_FAILURE(call, value)    \
    do                                          \
    {                                           \
        napi_status __unique_status = call;     \
        if (napi_ok != __unique_status)         \
        {                                       \
            return value;                       \
        }                                       \
    } while (0)

#define THROW_AND_RETURN_VOID_ON_FAILURE(call, env, message)    \
    do                                                          \
    {                                                           \
        napi_status __unique_status = call;                     \
        if (napi_ok != __unique_status)                         \
        {                                                       \
            napi_throw_error(env, NULL, message);               \
            return;                                             \
        }                                                       \
    } while (0)

#define THROW_AND_RETURN_NULL_ON_FAILURE(call, env, message)    \
    do                                                          \
    {                                                           \
        napi_status __unique_status = call;                     \
        if (napi_ok != __unique_status)                         \
        {                                                       \
            napi_throw_error(env, NULL, message);               \
            return NULL;                                        \
        }                                                       \
    } while (0)

#define REJECT_WITH_ERROR(env, message, deferred)               \
    do                                                          \
    {                                                           \
        napi_value __unique_error;                              \
        signun_create_error(env, message, &__unique_error);     \
        napi_reject_deferred(env, deferred, __unique_error);    \
    }                                                           \
    while (0)                                                   \
        

napi_status signun_create_error(napi_env env, const char *message, napi_value *error);

#endif
