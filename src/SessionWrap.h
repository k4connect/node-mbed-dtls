#ifndef __SESSION_WRAP_H__
#define __SESSION_WRAP_H__

#include <napi.h>

#include "mbedtls/ssl.h"

#define ID_LENGTH 32
#define MASTER_LENGTH 48
#define RANDBYTES_LENGTH 64
#define OUT_CR_LENGTH 8

class SessionWrap : public Napi::ObjectWrap<SessionWrap> {
public:
	static Napi::Object Initialize(Napi::Env& env, Napi::Object& exports);
	static Napi::Object CreateFromContext(Napi::Env env, mbedtls_ssl_context *ssl, uint8_t *random);
	Napi::Value Restore(const Napi::CallbackInfo& info);
	Napi::Value GetCiphersuite(const Napi::CallbackInfo& info);
	Napi::Value GetRandomBytes(const Napi::CallbackInfo& info);
	Napi::Value GetId(const Napi::CallbackInfo& info);
	Napi::Value GetMaster(const Napi::CallbackInfo& info);
	Napi::Value GetInEpoch(const Napi::CallbackInfo& info);
	Napi::Value GetOutCounter(const Napi::CallbackInfo& info);

	void SetCiphersuite(const Napi::CallbackInfo& info, const Napi::Value& value);
	void SetRandomBytes(const Napi::CallbackInfo& info, const Napi::Value& value);
	void SetId(const Napi::CallbackInfo& info, const Napi::Value& value);
	void SetMaster(const Napi::CallbackInfo& info, const Napi::Value& value);
	void SetInEpoch(const Napi::CallbackInfo& info, const Napi::Value& value);
	void SetOutCounter(const Napi::CallbackInfo& info, const Napi::Value& value);
	SessionWrap(const Napi::CallbackInfo& info);
	~SessionWrap();

	int ciphersuite;
	unsigned char id[ID_LENGTH];
	size_t id_len;
	unsigned char master[MASTER_LENGTH];
	uint8_t randbytes[RANDBYTES_LENGTH];
	uint16_t in_epoch;
	unsigned char out_ctr[OUT_CR_LENGTH];

private:
	static Napi::FunctionReference constructor;
};

#endif
