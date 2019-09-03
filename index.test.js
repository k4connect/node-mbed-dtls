'use strict';

const path = require('path');
const should = require('should');
const sinon = require('sinon');
const assert = require('assert');

const dtls = require('./index');

const opts = {
	cert: path.join(__dirname, 'test/public.der'),
	key: path.join(__dirname, 'test/private.der')
};

describe('createServer', function() {
	it('throws an exception when no cert or key provided', function() {
		(() => dtls.createServer()).should.throw();
	});

	it('emits an error trying to bind to same port', function (done) {
		const s1 = dtls.createServer(opts);
		s1.listen(5683);
		const s2 = dtls.createServer(opts);
		s2.once('error', (err) => {
			checkFinally(() => {
				assert(err);
			}, () => {
				s1.close();
			}, done);
		});
		s2.listen(5683);
	});

	it('emits close after error', function (done) {
		const errorSpy = sinon.spy();
		const closeSpy = sinon.spy();
		const s1 = dtls.createServer(opts);
		s1.listen(5683);
		const s2 = dtls.createServer(opts);
		s2.once('error', errorSpy);
		s2.once('close', () => {
			closeSpy();
			checkFinally(() => {
				assert(closeSpy.calledAfter(errorSpy));
			}, () => {
				s1.close();
			}, done);
		});
		s2.listen(5683);
	});
});

function checkFinally(f, g, done) {
	try {
		f();
	} catch (e) {
		return done(e);
	} finally {
		g();
	}
	done();
}
