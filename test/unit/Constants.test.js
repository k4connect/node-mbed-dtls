'use strict';

const chai = require('chai');
const path = require('path');
const should = require('should');
const sinon = require('sinon');
const assert = require('assert');

const { expect } = chai;
const errors = [];
const mbed = require('bindings')('node_mbed_dtls.node');
const { MbedtlsError } = mbed;

for(let key in mbed) {
	if (key.match(/^MBEDTLS_ERR/)) errors.push(key);
}

const opts = {
	cert: path.join(__dirname, 'test/public.der'),
	key: path.join(__dirname, 'test/private.der')
};

describe('Constants', function() {
	describe('mbedtls error', function () {
		it('should be a function', function () {
			expect(MbedtlsError).to.be.a('function');
		});

		it('should translate an error code to a string', function () {
			// #define MBEDTLS_ERR_SSL_BAD_INPUT_DATA -0x7100
			expect( MbedtlsError(-0x7100) ).to.be.equal('SSL - Bad input parameters to function');
		});

		it('should return undefined for an unknown error code', function () {
			// Unused code -0xFFFF
			expect( MbedtlsError(-0xFFFF) ).to.be.undefined;
		});
	});

	describe('error constants', function () {
		describe('values existing', function () {
			for (let code of errors) {
				it(`${code} (-0x${(-mbed[code]).toString(16)}) should have a valid error string`, function () {
					expect(MbedtlsError(mbed[code])).to.be.a('string');
				});
			}
		});

		// Test below is not structured well, but we want this to fail if new values are added
		describe('values absent', function () {
			it (`should not have absent values`, function () {
				for (let i = -0xFFFF; i < 0; i++) {

					if (errors.indexOf(i) == -1) continue;
					expect(MbedtlsError(i)).to.be.undefined;
				}
			});
		});
	});
});
