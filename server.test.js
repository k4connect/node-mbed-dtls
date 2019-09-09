'use strict';

const chai = require('chai')
const path = require('path');
const fs = require('fs');
const should = require('should');
const sinon = require('sinon');
const assert = require('assert');

const expect = chai.expect;

const keyFilename = path.join(__dirname, 'test/private.der');
const certFilename = path.join(__dirname, 'test/public.der');
const key = fs.readFileSync(keyFilename);
const cert = fs.readFileSync(certFilename);
const opts = { cert: certFilename, key: keyFilename };

const dtls = require('./server');


describe('server', function() {

});
