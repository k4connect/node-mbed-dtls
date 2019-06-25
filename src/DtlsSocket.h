#ifndef __DTLS_SOCKET_H__
#define __DTLS_SOCKET_H__

#include <napi.h>

#include "mbedtls/ssl.h"
#include "mbedtls/timing.h"

#include "DtlsServer.h"
#include "SessionWrap.h"

#define KEYBUFF_LENGTH 1024

class DtlsSocket : public Napi::ObjectWrap<DtlsSocket> {
public:
	static Napi::Value Initialize(Napi::Env& env, Napi::Object& target);
	static Napi::Object New(const Napi::CallbackInfo& info);
	inline void NopSet(const Napi::CallbackInfo& info, const Napi::Value& value) {}
	Napi::Value ReceiveDataFromNode(const Napi::CallbackInfo& info);
	Napi::Value Close(const Napi::CallbackInfo& info);
	Napi::Value Send(const Napi::CallbackInfo& info);
	Napi::Value ResumeSession(const Napi::CallbackInfo& info);
	Napi::Value Renegotiate(const Napi::CallbackInfo& info);
	Napi::Value GetPublicKey(const Napi::CallbackInfo& info);
	Napi::Value GetPublicKeyPEM(const Napi::CallbackInfo& info);
	Napi::Value GetOutCounter(const Napi::CallbackInfo& info);
	Napi::Value GetSession(const Napi::CallbackInfo& info);
	DtlsSocket(const Napi::CallbackInfo& info);
	int send_encrypted(const unsigned char *buf, size_t len);
	int recv(unsigned char *buf, size_t len);
	int send(const unsigned char *buf, size_t len);
	int receive_data(unsigned char *buf, int len);
	int step();
	void store_data(const unsigned char *buf, size_t len);
	int close();
	void error(int ret);
	void reset();
	void get_session_cache(mbedtls_ssl_session *session);
	void renegotiate(SessionWrap *sess);
	bool resume(SessionWrap *sess);
	void proceed();

	~DtlsSocket();

private:
	Napi::Env env;
	static Napi::FunctionReference constructor;
	void throwError(int ret);
	Napi::Function send_cb;
	Napi::Function error_cb;
	Napi::Function handshake_cb;
	Napi::Function resume_sess_cb;
	mbedtls_ssl_context ssl_context;
	mbedtls_timing_delay_context timer;
	mbedtls_ssl_config* ssl_config;
	const unsigned char *recv_buf;
	size_t recv_len;
	unsigned char *ip;
	size_t ip_len;

	bool session_wait;
	uint8_t random[64];
};

#endif
