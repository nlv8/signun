#ifndef __SIGNUN_BLAKE2_ADDON_H
#define __SIGNUN_BLAKE2_ADDON_H

#include <node_api.h>

#include "blake2.h"


napi_status create_blake2_addon(napi_env env, napi_value base);

#endif
