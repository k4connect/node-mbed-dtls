#ifndef __CONSTANTS_H__
#define __CONSTANTS_H__

#include <napi.h>
#include <cstring>

#define ERROR_BUF_LEN 160 // max len of an error string is 133
#define ERROR_IS_KNOWN(str) ( memcmp( (str), "UNKNOWN ERROR CODE", 18 ) != 0 )

#define EXPORT_CONST(exp,co) (exp).Set(#co, co)

class Constants {
public:
	static Napi::Object Initialize(Napi::Env env, Napi::Object exports);
	static Napi::Value MbedtlsError(const Napi::CallbackInfo& info);
};

#endif
