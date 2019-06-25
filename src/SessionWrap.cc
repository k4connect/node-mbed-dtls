#include "SessionWrap.h"
#include <stdlib.h>

Napi::FunctionReference SessionWrap::constructor;

Napi::Object SessionWrap::Initialize(Napi::Env& env, Napi::Object& exports) {
	Napi::HandleScope scope(env);

	Napi::Function func = DefineClass(env, "SessionWrap", {
		InstanceMethod("restore", &SessionWrap::Restore),
		InstanceAccessor("ciphersuite", &SessionWrap::GetCiphersuite, &SessionWrap::SetCiphersuite),
		InstanceAccessor("randbytes", &SessionWrap::GetRandomBytes, &SessionWrap::SetRandomBytes),
		InstanceAccessor("id", &SessionWrap::GetId, &SessionWrap::SetId),
		InstanceAccessor("master", &SessionWrap::GetMaster, &SessionWrap::SetMaster),
		InstanceAccessor("in_epoch", &SessionWrap::GetInEpoch, &SessionWrap::SetInEpoch),
		InstanceAccessor("out_ctr", &SessionWrap::GetOutCounter, &SessionWrap::SetOutCounter),
	});

	constructor = Napi::Persistent(func);
	constructor.SuppressDestruct();

	exports.Set("SessionWrap", func);
	return exports;
}

Napi::Object SessionWrap::CreateFromContext(Napi::Env env, mbedtls_ssl_context *ssl, uint8_t *random) {
	Napi::EscapableHandleScope scope(env);
	Napi::Object instance = constructor.New({ });

	SessionWrap *news = Napi::ObjectWrap<SessionWrap>::Unwrap(instance);
	news->ciphersuite = ssl->session->ciphersuite;
	memcpy(news->randbytes, random, 64);
	memcpy(news->id, ssl->session->id, ssl->session->id_len);
	news->id_len = ssl->session->id_len;
	memcpy(news->master, ssl->session->master, 48);
	news->in_epoch = ssl->in_epoch;
	memcpy(news->out_ctr, ssl->out_ctr, 8);

	return scope.Escape(instance).As<Napi::Object>();
}

Napi::Value SessionWrap::Restore(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	SessionWrap *session = Napi::ObjectWrap<SessionWrap>::Unwrap(info.This().As<Napi::Object>());

	Napi::Object object = info[0].ToObject();
	session->ciphersuite = object.Get("ciphersuite").As<Napi::Number>().Uint32Value();

	Napi::Object rbv = object.Get("randbytes").ToObject();
	memcpy(session->randbytes,
		(rbv).As<Napi::Buffer<char>>().Data(),
		(rbv).As<Napi::Buffer<char>>().Length());

	Napi::Object idv = object.Get("id").ToObject();
	memcpy(session->id,
		idv.As<Napi::Buffer<char>>().Data(),
		idv.As<Napi::Buffer<char>>().Length());
	session->id_len = (idv).As<Napi::Buffer<char>>().Length();

	Napi::Object masterv = object.Get("master").ToObject();
	memcpy(session->master,
		masterv.As<Napi::Buffer<char>>().Data(),
		masterv.As<Napi::Buffer<char>>().Length());

	session->in_epoch = object.Get("in_epoch").As<Napi::Number>().Uint32Value();

	Napi::Object out_ctrv = object.Get("out_ctr").ToObject();
	memcpy(session->out_ctr,
		out_ctrv.As<Napi::Buffer<char>>().Data(),
		out_ctrv.As<Napi::Buffer<char>>().Length());

	return Napi::Boolean::New(env, true);
}

Napi::Value SessionWrap::GetCiphersuite(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	SessionWrap *session = Napi::ObjectWrap<SessionWrap>::Unwrap(info.This().As<Napi::Object>());
	return Napi::Number::New(env, session->ciphersuite);
}

void SessionWrap::SetCiphersuite(const Napi::CallbackInfo& info, const Napi::Value& value) {
	SessionWrap *session = Napi::ObjectWrap<SessionWrap>::Unwrap(info.This().As<Napi::Object>());
	session->ciphersuite = value.As<Napi::Number>().Uint32Value();
}


Napi::Value SessionWrap::GetRandomBytes(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	SessionWrap *session = Napi::ObjectWrap<SessionWrap>::Unwrap(info.This().As<Napi::Object>());
	return Napi::Buffer<char>::Copy(env, (char *)session->randbytes, 64);
}

void SessionWrap::SetRandomBytes(const Napi::CallbackInfo& info, const Napi::Value& value) {
	SessionWrap *session = Napi::ObjectWrap<SessionWrap>::Unwrap(info.This().As<Napi::Object>());
	memcpy(session->randbytes,
		value.As<Napi::Buffer<unsigned char>>().Data(),
		value.As<Napi::Buffer<unsigned char>>().Length());
}


Napi::Value SessionWrap::GetId(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	SessionWrap *session = Napi::ObjectWrap<SessionWrap>::Unwrap(info.This().As<Napi::Object>());
	return Napi::Buffer<char>::Copy(env, (char *)session->id, session->id_len);
}

void SessionWrap::SetId(const Napi::CallbackInfo& info, const Napi::Value& value) {
	SessionWrap *session = Napi::ObjectWrap<SessionWrap>::Unwrap(info.This().As<Napi::Object>());
	memcpy(session->id,
		value.As<Napi::Buffer<unsigned char>>().Data(),
		value.As<Napi::Buffer<unsigned char>>().Length());
	session->id_len = value.As<Napi::Buffer<unsigned char>>().Length();
}


Napi::Value SessionWrap::GetMaster(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	SessionWrap *session = Napi::ObjectWrap<SessionWrap>::Unwrap(info.This().As<Napi::Object>());
	return Napi::Buffer<char>::Copy(env, (char *)session->master, 48);
}

void SessionWrap::SetMaster(const Napi::CallbackInfo& info, const Napi::Value& value) {
	SessionWrap *session = Napi::ObjectWrap<SessionWrap>::Unwrap(info.This().As<Napi::Object>());
	memcpy(session->master,
		value.As<Napi::Buffer<unsigned char>>().Data(),
		value.As<Napi::Buffer<unsigned char>>().Length());
}


Napi::Value SessionWrap::GetInEpoch(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	SessionWrap *session = Napi::ObjectWrap<SessionWrap>::Unwrap(info.This().As<Napi::Object>());
	return Napi::Number::New(env, session->in_epoch);
}

void SessionWrap::SetInEpoch(const Napi::CallbackInfo& info, const Napi::Value& value) {
	SessionWrap *session = Napi::ObjectWrap<SessionWrap>::Unwrap(info.This().As<Napi::Object>());
	session->in_epoch = value.As<Napi::Number>().Uint32Value();
}


Napi::Value SessionWrap::GetOutCounter(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	SessionWrap *session = Napi::ObjectWrap<SessionWrap>::Unwrap(info.This().As<Napi::Object>());
	return Napi::Buffer<char>::Copy(env, (char *)session->out_ctr, 8);
}

void SessionWrap::SetOutCounter(const Napi::CallbackInfo& info, const Napi::Value& value) {
	SessionWrap *session = Napi::ObjectWrap<SessionWrap>::Unwrap(info.This().As<Napi::Object>());
	memcpy(session->out_ctr,
		value.As<Napi::Buffer<unsigned char>>().Data(),
		value.As<Napi::Buffer<unsigned char>>().Length());
}

SessionWrap::SessionWrap(const Napi::CallbackInfo& info) : Napi::ObjectWrap<SessionWrap>(info) {
}

SessionWrap::~SessionWrap() {
}
