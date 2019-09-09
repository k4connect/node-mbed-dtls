'use strict';

const path = require('path');
const should = require('should');
const sinon = require('sinon');
const assert = require('assert');

const mbed = require('bindings')('node_mbed_dtls.node');

const opts = {
	cert: path.join(__dirname, 'test/public.der'),
	key: path.join(__dirname, 'test/private.der')
};

describe('DtlsSocket', function() {

});
