#ifndef __SIGNUN_UTIL_H
#define __SIGNUN_UTIL_H

#define DECLARE_NAPI_METHOD(name, function)     \
{ name, NULL, function, NULL, NULL, NULL, napi_default | napi_enumerable, NULL }

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

#define THROW_ON_FAILURE(call, env, message)         \
    do                                               \
    {                                                \
        napi_status __unique_status = call;          \
        if (napi_ok != __unique_status)              \
        {                                            \
            napi_throw_error(env, NULL, message);    \
        }                                            \
    } while (0)

#endif
