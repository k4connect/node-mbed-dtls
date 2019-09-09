'use strict';

const chai = require('chai')
const path = require('path');
const fs = require('fs');
const should = require('should');
const sinon = require('sinon');
const assert = require('assert');

const expect = chai.expect;

const { DtlsServer } = require('bindings')('node_mbed_dtls.node');

const keyFilename = path.join(__dirname, '..', 'private.der');
const certFilename = path.join(__dirname, '..', 'public.der');
const key = fs.readFileSync(keyFilename);
const cert = fs.readFileSync(certFilename);
const opts = { cert: certFilename, key: keyFilename };

describe('DtlsServer', function() {
	describe('exports', function () {
		it('should exist', function () {
			expect(DtlsServer).to.be.a('function');
		});

		it('should be named correctly', function () {
			expect(DtlsServer.name).to.equal('DtlsServer');
		});
	});

	describe('constructor', function () {
		it('should throw if constructed with no arguments', function () {
			expect(() => { new DtlsServer() }).to.throw();
		});

		it('should throw if called as a function', function () {
			expect(() => { DtlsServer(key) }).to.throw();
		});

		it('should construct correctly given key buffer', function () {
			expect(new DtlsServer(key)).to.be.instanceOf(DtlsServer);
		});

		for (let level = 0; level < 5; level++) {
			it(`should construct correctly given key and an debug level of ${level}`, function () {
				expect(new DtlsServer(key, level)).to.be.instanceOf(DtlsServer);
			});
		}
	});

	describe('accessors', function () {
		let server;
		describe('handshake timeout min', function () {
			beforeEach(function () {
				server = new DtlsServer(key);
			});

			it('should have a default value of 1000ms', function () {
				expect(server.handshakeTimeoutMin).to.equal(1000);
			});

			it('should be settable', function () {
				server.handshakeTimeoutMin = 1337;
				expect(server.handshakeTimeoutMin).to.equal(1337);
			});
		});

		describe('handshake timeout max', function () {
			beforeEach(function () {
				server = new DtlsServer(key);
			});

			it('should have a default value of 1000ms', function () {
				expect(server.handshakeTimeoutMax).to.equal(60000);
			});

			it('should be settable', function () {
				server.handshakeTimeoutMax = 120000;
				expect(server.handshakeTimeoutMax).to.equal(120000);
			});
		});
	})
});
