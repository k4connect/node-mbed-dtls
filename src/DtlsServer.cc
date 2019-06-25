
#include "DtlsServer.h"

#include <stdio.h>
#include <sys/time.h>
#define mbedtls_printf     printf
#define mbedtls_fprintf    fprintf

void throwMbedTlsError(Napi::Env& env, int error) {
	char buf[256] = {};
	mbedtls_strerror(error, buf, sizeof(buf));
	throw Napi::Error::New(env, buf);
}

static void my_debug( void *ctx, int level,
											const char *file, int line,
											const char *str )
{
	((void) level);

	struct timeval tp;
	gettimeofday(&tp, NULL);
	long int ms = tp.tv_sec * 1000 + tp.tv_usec / 1000;

	mbedtls_fprintf((FILE *) ctx, "%013ld:%s:%04d: %s", ms, file, line, str);
	fflush((FILE *) ctx);
}

Napi::FunctionReference DtlsServer::constructor;

Napi::Object DtlsServer::Initialize(Napi::Env env, Napi::Object exports) {
	Napi::HandleScope scope(env);

	Napi::Function func = DefineClass(env, "DtlsServer", {
		InstanceAccessor("handshakeTimeoutMin", &DtlsServer::GetHandshakeTimeoutMin, &DtlsServer::SetHandshakeTimeoutMin),
	});

	constructor = Napi::Persistent(func);
	constructor.SuppressDestruct();

	exports.Set("DtlsServer", func);

	return exports;
}

DtlsServer::DtlsServer(const Napi::CallbackInfo& info) : Napi::ObjectWrap<DtlsServer>(info) {
	Napi::Env env = info.Env();

	// Required 1st param: key
	if (info.Length() < 1 || !info[0].IsBuffer()) {
		Napi::TypeError::New(env, "Expecting first parameter (key) to be a buffer").ThrowAsJavaScriptException();
		return;
	}

	Napi::Buffer<unsigned char> key_buffer = info[0].As<Napi::Buffer<unsigned char>>();
	unsigned char * key = (unsigned char *) key_buffer.Data();
	size_t key_len = key_buffer.Length();

	int debug_level = 0;
	if (info.Length() > 1) {
		debug_level = info[1].ToNumber().Uint32Value();
	}

	const char *pers = "dtls_server";
	mbedtls_ssl_config_init(&conf);
	mbedtls_ssl_cookie_init(&cookie_ctx);
#if defined(MBEDTLS_SSL_CACHE_C)
	mbedtls_ssl_cache_init(&cache);
#endif
	mbedtls_x509_crt_init(&srvcert);
	mbedtls_pk_init(&pkey);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);

#if defined(MBEDTLS_DEBUG_C)
	mbedtls_debug_set_threshold(debug_level);
#endif

	CHECK_MBEDTLS(mbedtls_pk_parse_key(&pkey, key, key_len, NULL, 0));
	CHECK_MBEDTLS(mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen(pers)));
	CHECK_MBEDTLS(mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_DATAGRAM, MBEDTLS_SSL_PRESET_DEFAULT));

	mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);

	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

	CHECK_MBEDTLS(mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey));
	CHECK_MBEDTLS(mbedtls_ssl_cookie_setup(&cookie_ctx, mbedtls_ctr_drbg_random, &ctr_drbg));

	mbedtls_ssl_conf_dtls_cookies(&conf, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check, &cookie_ctx);
	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);

	static int ssl_cert_types[] = { MBEDTLS_TLS_CERT_TYPE_RAW_PUBLIC_KEY, MBEDTLS_TLS_CERT_TYPE_NONE };
	mbedtls_ssl_conf_client_certificate_types(&conf, ssl_cert_types);
	mbedtls_ssl_conf_server_certificate_types(&conf, ssl_cert_types);

	// turn off server sending Certificate
	mbedtls_ssl_conf_certificate_send(&conf, MBEDTLS_SSL_SEND_CERTIFICATE_DISABLED);
}

Napi::Value DtlsServer::GetHandshakeTimeoutMin(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	return Napi::Number::New(env, this->config()->hs_timeout_min);
}

void DtlsServer::SetHandshakeTimeoutMin(const Napi::CallbackInfo& info, const Napi::Value& value) {
	uint32_t hs_timeout_min = value.As<Napi::Number>().Uint32Value();
	mbedtls_ssl_conf_handshake_timeout(this->config(), hs_timeout_min, this->config()->hs_timeout_max);
}

DtlsServer::~DtlsServer() {
	mbedtls_x509_crt_free( &srvcert );
	mbedtls_pk_free( &pkey );
	mbedtls_ssl_config_free( &conf );
	mbedtls_ssl_cookie_free( &cookie_ctx );
#if defined(MBEDTLS_SSL_CACHE_C)
	mbedtls_ssl_cache_free( &cache );
#endif
	mbedtls_ctr_drbg_free( &ctr_drbg );
	mbedtls_entropy_free( &entropy );
}
