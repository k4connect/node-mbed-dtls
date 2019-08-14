
#include "DtlsSocket.h"
#include "SessionWrap.h"

#include <stdlib.h>

#include "mbedtls/ssl_internal.h"
#include "mbedtls/pk.h"

using namespace Napi;

Napi::FunctionReference DtlsSocket::constructor;

Napi::Value DtlsSocket::Initialize(Napi::Env& env, Napi::Object& exports) {
	Napi::HandleScope scope(env);

	// Constructor
	Napi::Function func = DefineClass(env, "DtlsSocket", {
		InstanceMethod("receiveData", &DtlsSocket::ReceiveDataFromNode),
		InstanceMethod("close", &DtlsSocket::Close),
		InstanceMethod("send", &DtlsSocket::Send),
		InstanceMethod("resumeSession", &DtlsSocket::ResumeSession),
		InstanceMethod("renegotiate", &DtlsSocket::Renegotiate),
		InstanceAccessor("publicKey", &DtlsSocket::GetPublicKey, &DtlsSocket::NopSet),
		InstanceAccessor("publicKeyPEM", &DtlsSocket::GetPublicKeyPEM, &DtlsSocket::NopSet),
		InstanceAccessor("outCounter", &DtlsSocket::GetOutCounter, &DtlsSocket::NopSet),
		InstanceAccessor("session", &DtlsSocket::GetSession, &DtlsSocket::NopSet),
	});

	constructor = Napi::Persistent(func);
	constructor.SuppressDestruct();

	exports.Set("DtlsSocket", func);

	return exports;
}


Napi::Object DtlsSocket::New(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	if (info.Length() < 6) {
		throw Napi::TypeError::New(env, "DtlsSocket requires six arguments");
	}

	// TODO check arguments types

	Napi::Object server = info[0].As<Napi::Object>();
	Napi::Value client_ip = info[1].As<Napi::String>();
	Napi::Function send_cb = info[2].As<Napi::Function>();
	Napi::Function hs_cb = info[3].As<Napi::Function>();
	Napi::Function error_cb = info[4].As<Napi::Function>();
	Napi::Function resume_cb = info[5].As<Napi::Function>();

	Napi::Object obj = constructor.New({ server, client_ip, send_cb, hs_cb, error_cb, resume_cb });

	return obj;
}

Napi::Value DtlsSocket::ReceiveDataFromNode(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	Napi::HandleScope scope(env);

	DtlsSocket *socket = Napi::ObjectWrap<DtlsSocket>::Unwrap(info.This().As<Napi::Object>());

	if (info.Length() >= 1 && info[0].IsBuffer()) {
		Napi::Buffer<unsigned char> recv_buffer = info[0].As<Napi::Buffer<unsigned char>>();
		const unsigned char *recv_data = (unsigned char *) recv_buffer.Data();
		size_t recv_len = recv_buffer.Length();
		fprintf(stdout, "-------\n%d\n%x\n-------\n", recv_len, recv_data);
		socket->store_data(recv_data, recv_len);
	}

	unsigned char buf[RECV_BUF_LENGTH];
	unsigned int len = socket->receive_data(buf, RECV_BUF_LENGTH);

	return len > 0 ? Napi::Buffer<unsigned char>::Copy(env, buf, len) : env.Undefined();
}

Napi::Value DtlsSocket::GetPublicKey(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	DtlsSocket *socket = Napi::ObjectWrap<DtlsSocket>::Unwrap(info.This().As<Napi::Object>());

	mbedtls_ssl_session *session = socket->ssl_context.session;
	if (session == NULL) {
		throw Napi::TypeError::New(env, "ssl_context.session was null");
	}

	unsigned char buf[KEY_BUF_LENGTH];
	mbedtls_pk_context pk = session->peer_cert->pk;
	int ret = mbedtls_pk_write_pubkey_der(&pk, buf, KEY_BUF_LENGTH);

	if (ret < 0) {
		throw Napi::TypeError::New(env, "error at mbedtls_pk_write_pubkey_der");
	}

	// key is written at the end
	return Napi::Buffer<char>::Copy(env, (char *)buf + (KEY_BUF_LENGTH - ret), ret);
}

Napi::Value DtlsSocket::GetPublicKeyPEM(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	DtlsSocket *socket = Napi::ObjectWrap<DtlsSocket>::Unwrap(info.This().As<Napi::Object>());

	mbedtls_ssl_session *session = socket->ssl_context.session;
	if (session == NULL ||
		session->peer_cert == NULL) {
		throw Napi::TypeError::New(env, "ssl_context.session was null");
	}

	unsigned char buf[KEY_BUF_LENGTH];
	mbedtls_pk_context pk = session->peer_cert->pk;
	int ret = mbedtls_pk_write_pubkey_pem(&pk, buf, KEY_BUF_LENGTH);

	if (ret < 0) {
		throw Napi::TypeError::New(env, "error at mbedtls_pk_write_pubkey_pem");
	}

	return Napi::Buffer<char>::Copy(env, (char *)buf, strlen((char *)buf));
}

Napi::Value DtlsSocket::GetOutCounter(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	DtlsSocket *socket = Napi::ObjectWrap<DtlsSocket>::Unwrap(info.This().As<Napi::Object>());
	return Napi::Buffer<char>::Copy(env, (char *)socket->ssl_context.out_ctr, 8);
}

Napi::Value DtlsSocket::GetSession(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	DtlsSocket *socket = Napi::ObjectWrap<DtlsSocket>::Unwrap(info.This().As<Napi::Object>());
	Napi::Object sess = SessionWrap::CreateFromContext(env, &socket->ssl_context, socket->random);
	return sess;
}

Napi::Value DtlsSocket::Close(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	DtlsSocket *socket = Napi::ObjectWrap<DtlsSocket>::Unwrap(info.This().As<Napi::Object>());
	int ret = socket->close();

	return Napi::Number::New(env, ret);
}

Napi::Value DtlsSocket::Send(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	DtlsSocket *socket = Napi::ObjectWrap<DtlsSocket>::Unwrap(info.This().As<Napi::Object>());

	Napi::Buffer<unsigned char> send_data_buffer = info[0].As<Napi::Buffer<unsigned char>>();
	const unsigned char *send_data = (const unsigned char *) send_data_buffer.Data();
	int ret = socket->send(send_data, send_data_buffer.Length());

	return Napi::Number::New(env, ret);
}

Napi::Value DtlsSocket::ResumeSession(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	DtlsSocket *socket = Napi::ObjectWrap<DtlsSocket>::Unwrap(info.This().As<Napi::Object>());

	Napi::Object sessWrap = info[0].As<Napi::Object>();
	if (sessWrap.IsEmpty()) {
		throw Napi::TypeError::New(env, "ResumeSession requires one argument, was null");
	}

	SessionWrap *sess = Napi::ObjectWrap<SessionWrap>::Unwrap(sessWrap);
	bool ret = socket->resume(sess);
	return Napi::Number::New(env, ret);
}

Napi::Value DtlsSocket::Renegotiate(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	DtlsSocket *socket = Napi::ObjectWrap<DtlsSocket>::Unwrap(info.This().As<Napi::Object>());

	if (info[0].IsUndefined()) {
		socket->proceed();
		return Napi::Boolean::New(env, false);
	}

	SessionWrap *sess =  Napi::ObjectWrap<SessionWrap>::Unwrap(info[0].As<Napi::Object>());
	socket->renegotiate(sess);

	return Napi::Boolean::New(env, true);
}

int net_send( void *ctx, const unsigned char *buf, size_t len ) {
	DtlsSocket* socket = (DtlsSocket*)ctx;
	return socket->send_encrypted(buf, len);
}

int net_recv( void *ctx, unsigned char *buf, size_t len ) {
	DtlsSocket* socket = (DtlsSocket*)ctx;
	return socket->recv(buf, len);
}

DtlsSocket::DtlsSocket(const Napi::CallbackInfo& info) :
		Napi::ObjectWrap<DtlsSocket>(info),
		env(info.Env()) {
	DtlsServer *server = Napi::ObjectWrap<DtlsServer>::Unwrap(info[0].As<Napi::Object>());
	std::string client_ip = (std::string) info[1].As<Napi::String>();

	send_cb = Napi::Persistent(info[2].As<Napi::Function>());
	error_cb = Napi::Persistent(info[3].As<Napi::Function>());
	handshake_cb = Napi::Persistent(info[4].As<Napi::Function>());
	resume_sess_cb = Napi::Persistent(info[5].As<Napi::Function>());
	session_wait = false;
	int ret;

	if((ip = (unsigned char *)calloc(1, client_ip.length())) == NULL) {
		throwError(MBEDTLS_ERR_SSL_ALLOC_FAILED);
		return;
	}

	memcpy(ip, client_ip.c_str(), client_ip.length());
	ip_len = client_ip.length();

	mbedtls_ssl_init(&ssl_context);
	ssl_config = server->config();

	if((ret = mbedtls_ssl_setup(&ssl_context, ssl_config)) != 0)
	{
		throwError(ret);
	}

	mbedtls_ssl_set_timer_cb(&ssl_context,
													 &timer,
													 mbedtls_timing_set_delay,
													 mbedtls_timing_get_delay);
	mbedtls_ssl_set_bio(&ssl_context, this, net_send, net_recv, NULL);
	mbedtls_ssl_session_reset(&ssl_context);

	/* For HelloVerifyRequest cookies */
	if((ret = mbedtls_ssl_set_client_transport_id(&ssl_context, ip, ip_len)) != 0)
	{
		throwError(ret);
		return;
	}
}

bool DtlsSocket::resume(SessionWrap *sess) {
	ssl_context.major_ver = MBEDTLS_SSL_MAJOR_VERSION_3;
	ssl_context.minor_ver = MBEDTLS_SSL_MINOR_VERSION_3;

	ssl_context.state = MBEDTLS_SSL_HANDSHAKE_WRAPUP;
	ssl_context.handshake->resume = 1;

	ssl_context.in_epoch = sess->in_epoch;

	memcpy(ssl_context.out_ctr, sess->out_ctr, 8);
	memcpy(ssl_context.handshake->randbytes, sess->randbytes, 64);
	memcpy(ssl_context.session_negotiate->master, sess->master, 48);

	ssl_context.session_negotiate->id_len = sess->id_len;
	memcpy(ssl_context.session_negotiate->id, sess->id, sess->id_len);

	ssl_context.session_negotiate->ciphersuite = sess->ciphersuite;
	ssl_context.transform_negotiate->ciphersuite_info = mbedtls_ssl_ciphersuite_from_id(sess->ciphersuite);

	if (!ssl_context.transform_negotiate->ciphersuite_info)
	{
		error(MBEDTLS_ERR_SSL_NO_USABLE_CIPHERSUITE);
		return false;
	}

	int err = mbedtls_ssl_derive_keys(&ssl_context);
	if (err)
	{
		error(err);
		return false;
	}

	ssl_context.in_msg = ssl_context.in_iv + ssl_context.transform_negotiate->ivlen -
										ssl_context.transform_negotiate->fixed_ivlen;
	ssl_context.out_msg = ssl_context.out_iv + ssl_context.transform_negotiate->ivlen -
										 ssl_context.transform_negotiate->fixed_ivlen;

	ssl_context.session_in = ssl_context.session_negotiate;
	ssl_context.session_out = ssl_context.session_negotiate;

	ssl_context.transform_in = ssl_context.transform_negotiate;
	ssl_context.transform_out = ssl_context.transform_negotiate;

	mbedtls_ssl_handshake_wrapup(&ssl_context);

	return true;
}

void DtlsSocket::reset() {
	int ret;
	mbedtls_ssl_session_reset(&ssl_context);

	/* For HelloVerifyRequest cookies */
	if((ret = mbedtls_ssl_set_client_transport_id(&ssl_context, ip, ip_len)) != 0)
	{
		return error(ret);
	}
}

int DtlsSocket::send_encrypted(const unsigned char *buf, size_t len) {
	send_cb.Call({
		Napi::Buffer<char>::Copy(env, (char *)buf, len)
	});

	return len;
}

int DtlsSocket::recv(unsigned char *buf, size_t len) {
	if (recv_len != 0) {
		len = recv_len;
		memcpy(buf, recv_buf, recv_len);
		recv_buf = NULL;
		recv_len = 0;
		return len;
	}

	return MBEDTLS_ERR_SSL_WANT_READ;
}

int DtlsSocket::send(const unsigned char *buf, size_t len) {
	int ret;
	ret = mbedtls_ssl_write(&ssl_context, buf, len);
	if (ret < 0)
	{
		error(ret);
		return ret;
	}
	len = ret;
	return ret;
}

int DtlsSocket::receive_data(unsigned char *buf, int len) {
	int ret;

	if (ssl_context.state == MBEDTLS_SSL_HANDSHAKE_OVER) {
		// normal reading of unencrypted data
		memset(buf, 0, len);
		ret = mbedtls_ssl_read(&ssl_context, buf, len);
		if (ret <= 0 && ret != MBEDTLS_ERR_SSL_WANT_READ) {
			error(ret);
			return 0;
		}
		return ret;
	}

	return step();
}

void DtlsSocket::get_session_cache(mbedtls_ssl_session *session) {
	session_wait = true;

	resume_sess_cb.Call({
		Napi::String::New(env, (const char*) session->id, session->id_len)
	});
}

void DtlsSocket::renegotiate(SessionWrap *sess) {
	mbedtls_ssl_session *session = ssl_context.session_negotiate;

  if( session->ciphersuite != sess->ciphersuite ||
      session->id_len != sess->id_len )
      return;

  if( memcmp( session->id, sess->id,
              sess->id_len ) != 0 )
      return;

  memcpy( session->master, sess->master, 48 );

  session->verify_result = 0;
  ssl_context.handshake->resume = 1;

	proceed();
}

void DtlsSocket::proceed() {
	session_wait = false;
	step();
}

int DtlsSocket::step() {
	int ret;
	// handshake
	while (ssl_context.state != MBEDTLS_SSL_HANDSHAKE_OVER) {
		ret = mbedtls_ssl_handshake_step(&ssl_context);
		if (ret == 0) {
			if (session_wait &&
				(ssl_context.state == MBEDTLS_SSL_SERVER_HELLO ||
				 ssl_context.state == MBEDTLS_SSL_HANDSHAKE_WRAPUP)) {
				return 0;
			}

			if (ssl_context.state == MBEDTLS_SSL_SERVER_HELLO &&
					ssl_context.handshake->resume == 0 &&
					ssl_context.session_negotiate->id_len != 0) {
				get_session_cache(ssl_context.session_negotiate);

				// copy client random (renegotiation)
				if (ssl_context.handshake->resume == 1) {
					memcpy(random, ssl_context.handshake->randbytes, 32);
				}
				return 0;
			}

			// nasty grabbing of server random in renegotiation case
			if (ssl_context.state == MBEDTLS_SSL_SERVER_CHANGE_CIPHER_SPEC &&
					ssl_context.handshake->resume == 1) {
				memcpy(random + 32, ssl_context.out_msg + 6, 32);
			}

			// normal handshake random grab
			if (ssl_context.state == MBEDTLS_SSL_SERVER_CERTIFICATE)
			{
				memcpy(random, ssl_context.handshake->randbytes, 64);
			}

			// keep looping to send everything
			continue;
		} else if (ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED) {
			// client will start a new session, so reset things
			reset();
			continue;
		} else if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
			// we just need more data, so return
			if (recv_len > 0)
				continue;

			return 0;
		} else if (ret != 0) {
			// bad things
			error(ret);
			return 0;
		}
	}

	// this should only be called once when we first finish the handshake
	handshake_cb.Call({});
	return 0;
}

void DtlsSocket::throwError(int ret) {
	char error_buf[100];
	mbedtls_strerror(ret, error_buf, 100);
	throw Napi::Error::New(env, error_buf);
}

void DtlsSocket::error(int ret) {
	char error_buf[255];
	mbedtls_strerror(ret, error_buf, 255);

	error_cb.Call({
		Napi::Number::New(env, ret),
		Napi::String::New(env, error_buf)
	});
}

void DtlsSocket::store_data(const unsigned char *buf, size_t len) {
	recv_buf = buf;
	recv_len = len;
}

int DtlsSocket::close() {
	if(ssl_context.state != MBEDTLS_SSL_HANDSHAKE_OVER) {
		return 1;
	}
	return mbedtls_ssl_close_notify(&ssl_context);
}

DtlsSocket::~DtlsSocket() {
	if (ip != nullptr) {
		free(ip);
		ip = nullptr;
	}

	recv_buf = nullptr;
	mbedtls_ssl_free(&ssl_context);
}
