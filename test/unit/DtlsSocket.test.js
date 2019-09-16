'use strict';

const chai = require('chai')
const fs = require('fs');
const path = require('path');
const should = require('should');
const sinon = require('sinon');
const assert = require('assert');

const expect = chai.expect;

const serverKey = fs.readFileSync(path.join(__dirname, '..', 'private.der'));
const { DtlsSocket, DtlsServer } = require('bindings')('node_mbed_dtls.node');


describe('DtlsSocket', function() {
	describe('exports', function () {
		it('should exist', function () {
			expect(DtlsSocket).to.be.a('function');
		});

		it('should be named correctly', function () {
			expect(DtlsSocket.name).to.equal('DtlsSocket');
		});
	});

	describe('constructor', function () {
		const ip = '123.45.67.89';
		let server;
		let sendCb;
		let handshakeCb;
		let errorCb;
		let sessResumeCb;

		beforeEach(function () {
			server = new DtlsServer(serverKey);
			sendCb = sinon.stub();
			handshakeCb = sinon.stub();
			errorCb = sinon.stub();
			sessResumeCb = sinon.stub();
		});

		it('should throw if constructed with no arguments', function () {
			expect(() => { new DtlsSocket() }).to.throw();
		});

		it('should throw if called as a function', function () {
			expect(() => { DtlsSocket(key) }).to.throw();
		});

		it('should construct correctly given all arguments', function () {
			expect(new DtlsSocket(server, '123.45.67.89', sendCb, handshakeCb, errorCb, sessResumeCb)).to.be.instanceOf(DtlsSocket);
		});
	});
});
