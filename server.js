'use strict';

var dgram = require('dgram');
var fs = require('fs');
var EventEmitter = require('events').EventEmitter;

var DtlsSocket = require('./socket');
var mbed = require('bindings')('node_mbed_dtls.node');

const APPLICATION_DATA_CONTENT_TYPE = 23;
const IP_CHANGE_CONTENT_TYPE = 254;

class DtlsServer extends EventEmitter {
	constructor(options) {
		super();
		this.options = options = Object.assign({
			sendClose: true
		}, options);
		this.sockets = {};
		this._moveSessionMessages = new Map();
		this.dgramSocket = options.socket || dgram.createSocket('udp4');
		this._onMessage = this._onMessage.bind(this);
		this.listening = false;

		this.dgramSocket.on('message', this._onMessage);
		this.dgramSocket.once('listening', () => {
			this.listening = true;
			this.emit('listening');
		});
		this.dgramSocket.once('error', err => {
			this.emit('error', err);
			this._closeSocket();
		});
		this.dgramSocket.once('close', () => {
			this._socketClosed();
		});

		let key = Buffer.isBuffer(options.key) ? options.key : fs.readFileSync(options.key);
		// likely a PEM encoded key, add null terminating byte
		// 0x2d = '-'
		if (key[0] === 0x2d && key[key.length - 1] !== 0) {
			key = Buffer.concat([key, Buffer.from([0])]);
		}

		this.mbedServer = new mbed.DtlsServer(key, options.debug);
		if (options.handshakeTimeoutMin) {
			this.mbedServer.handshakeTimeoutMin = options.handshakeTimeoutMin;
		}
	}

	listen(port, hostname, callback) {
		this.dgramSocket.bind(port, hostname, callback);
	}

	close(callback) {
		if (callback) {
			this.once('close', callback);
		}
		this._closing = true;
		this._closeSocket();
	}

	address() {
		return this.dgramSocket.address();
	}

	getConnections(callback) {
		var numConnections = Object.keys(this.sockets).filter(skey => {
			return this.sockets[skey] && this.sockets[skey].connected;
		}).length;
		process.nextTick(() => callback(numConnections));
	}

	resumeSocket(rinfo, session) {
		const key = `${rinfo.address}:${rinfo.port}`;
		let client = this.sockets[key];
		if (client) {
			return false;
		}

		this.sockets[key] = client = this._createSocket(rinfo, key, true);
		if (client.resumeSession(session)) {
			this.emit('secureConnection', client, session);
			return true;
		}
		return false;
	}

	_debug() {
		if (this.options.debug) {
			console.log(...arguments);
		}
	}

	_handleIpChange(msg, key, rinfo, deviceId) {
		// Check if another MoveSession packet from the same device is being processed already
		const messages = this._moveSessionMessages.get(key);
		if (messages) {
			this._debug(`Enqueuing MoveSession message, ip=${key}`);
			messages.push({ msg, rinfo });
			return true;
		}
		this._moveSessionMessages.set(key, []);
		const lookedUp = this.emit('lookupKey', deviceId, (err, oldRinfo) => {
			if (!err && oldRinfo) {
				if (rinfo.address === oldRinfo.address && rinfo.port === oldRinfo.port) {
					// The IP and port have not changed.
					// The device just thought they might have.
					// the extra DTLS option has been stripped already, handle the message as normal
					// like normal using the client we already had.
					this._debug(`handleIpChange: ignoring ip change because address did not change ip=${key}, deviceID=${deviceId}`);
					this._onMessage(msg, rinfo, (client, received) => {
						// 'received' is true or false based on whether the message is pushed into the stream
						if (received) {
							this._processMoveSessionMessages(key);
						} else {
							this._clearMoveSessionMessages(key);
							this.emit('forceDeviceRehandshake', rinfo, deviceId);
						}
					});

					return;
				}
				// The IP and/or port have changed
				// Attempt to send to oldRinfo which will
				// a) attempt session resumption (if the client with old address and port doesnt exist yet)
				// b) attempt to send the message to the old old address and port
				this._onMessage(msg, oldRinfo, (client, received) => {
					const oldKey = `${oldRinfo.address}:${oldRinfo.port}`;
					// if the message went through OK
					if (received) {
						this._debug(`handleIpChange: message successfully received, changing ip address fromip=${oldKey}, toip=${key}, deviceID=${deviceId}`);
						// change IP
						client.remoteAddress = rinfo.address;
						client.remotePort = rinfo.port;
						// move in lookup table
						this.sockets[key] = client;
						delete this.sockets[oldKey];
						// update cached session
						let updatePending = false;
						client.emit('ipChanged', oldRinfo, () => {
							updatePending = true;
						}, err => {
							// Keep queueing messages until the cached session data is updated
							if (!err) {
								this._processMoveSessionMessages(key);
							} else {
								this._clearMoveSessionMessages(key);
							}
						});
						if (!updatePending) {
							// FIXME: The client socket may not have a handler registered for its 'ipChanged' events, see this thread
							// for details:
							// https://s.slack.com/archives/CKRRAGTSB/p1576283554014400?thread_ts=1575905941.123800&cid=CKRRAGTSB
							//
							// Technically, the session has been moved successfully though, so we can now process queued messages
							// which were received from the new device address
							this._debug(`ipChanged not handled, ip=${key}`);
							this._processMoveSessionMessages(key);
						}
					} else {
						this._debug(`handleIpChange: message not successfully received, NOT changing ip address fromip=${oldKey}, toip=${key}, deviceID=${deviceId}`);
						this._clearMoveSessionMessages(key);
						this.emit('forceDeviceRehandshake', rinfo, deviceId);
					}
				});
			} else {
				// In May 2019 some devices were stuck with bad sessions, never handshaking.
				// https://app.clubhouse.io/particle/milestone/32301/manage-next-steps-associated-with-device-connectivity-issues-starting-may-2nd-2019
				// This cloud-side solution was discovered by Eli Thomas which caused
				// mbedTLS to fail a socket read and initiate a handshake.
				this._debug(`Device in 'move session' lock state attempting to force it to re-handshake deviceID=${deviceId}`);
				this._clearMoveSessionMessages(key);
				//Always EMIT this event instead of calling _forceDeviceRehandshake internally this allows the DS to device wether to send the packet or not to the device
				this.emit('forceDeviceRehandshake', rinfo, deviceId);
			}
		});
		if (!lookedUp) {
			this._clearMoveSessionMessages(key);
		}
		return lookedUp;
	}

	_processMoveSessionMessages(key) {
		const messages = this._moveSessionMessages.get(key);
		if (messages) {
			this._moveSessionMessages.delete(key);
			this._processNextMoveSessionMessage(key, messages);
		}
	}

	_processNextMoveSessionMessage(key, messages) {
		if (messages.length) {
			const m = messages.shift();
			// Process queued messages one by one asynchronously so that each client gets a fair share of
			// the server time
			setImmediate(() => {
				this._debug(`Processing queued MoveSession message, ip=${key}`);
				this._onMessage(m.msg, m.rinfo, (client, received) => {
					if (received) {
						this._processNextMoveSessionMessage(key, messages);
					} else {
						this._debug(`Discarding queued MoveSession messages, ip=${key}`);
					}
				});
			});
		}
	}

	_clearMoveSessionMessages(key) {
		// Print a warning if the queue is not empty
		if (this.options.debug) {
			const messages = this._moveSessionMessages.get(key);
			if (messages && messages.length) {
				this._debug(`Discarding queued MoveSession messages, ip=${key}`);
			}
		}
		this._moveSessionMessages.delete(key);
	}

	_forceDeviceRehandshake(rinfo, deviceId){
		this._debug(`Attempting force re-handshake by sending malformed hello request packet to deviceID=${deviceId}`);

		// Construct the 'session killing' Avada Kedavra packet
		const malformedHelloRequest = Buffer.from([
			0x16,                                 // Handshake message type 22
			0xfe, 0xfd,                           // DTLS 1.2
			0x00, 0x01,                           // Epoch
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // Sequence number, works when set to anything, therefore chose 0x00
			0x00, 0x10,                           // Data length, this has to be >= 16 (minumum) (deliberatly set to 0x10 (16) which is > the data length (2) that follows to force an mbed error on the device
			0x00,                                 // HandshakeType hello_request
			0x00                                  // Handshake body, intentionally too short at a single byte
		]);

		// Sending the malformed hello request back over the raw UDP socket
		this.dgramSocket.send(malformedHelloRequest, rinfo.port, rinfo.address);
	}

	_attemptResume(client, msg, key, cb) {
		const lcb = cb || (() => {});
		const called = this.emit('resumeSession', key, client, (err, session) => {
			if (!err && session) {
				const resumed = client.resumeSession(session);
				if (resumed) {
					client.cork();

					const received = client.receive(msg);
					// callback before secureConnection so
					// IP can be changed
					lcb(client, received);
					if (received) {
						this.emit('secureConnection', client, session);
					}

					client.uncork();
					return;
				}
			}
			client.receive(msg);
			lcb(null, false);
		});

		// if somebody was listening, session will attempt to be resumed
		// do not process with receive until resume finishes
		return called;
	}

	_onMessage(msg, rinfo, cb) {
		const key = `${rinfo.address}:${rinfo.port}`;

		// special IP changed content type
		if (msg.length > 0 && msg[0] === IP_CHANGE_CONTENT_TYPE) {
			const idLen = msg[msg.length - 1];
			const idStartIndex = msg.length - idLen - 1;
			const deviceId = msg.slice(idStartIndex, idStartIndex + idLen).toString('hex').toLowerCase();

			// slice off id and length, return content type to ApplicationData
			msg = msg.slice(0, idStartIndex);
			msg[0] = APPLICATION_DATA_CONTENT_TYPE;

			this._debug(`received ip change ip=${key}, deviceID=${deviceId}`);
			if (this._handleIpChange(msg, key, rinfo, deviceId)) {
				return;
			}
		}

		let client = this.sockets[key];
		if (!client) {
			this.sockets[key] = client = this._createSocket(rinfo, key);

			if (msg.length > 0 && msg[0] === APPLICATION_DATA_CONTENT_TYPE) {
				if (this._attemptResume(client, msg, key, cb)) {
					return;
				}
			}
		}

		if (cb) {
			// we cork because we want the callback to happen
			// before the implications of the message do
			client.cork();
			const received = client.receive(msg);
			cb(client, received);
			client.uncork();
		} else {
			client.receive(msg);
		}
	}

	_createSocket(rinfo, key, selfRestored) {
		var client = new DtlsSocket(this, rinfo.address, rinfo.port);
		client.sendClose = this.options.sendClose;
		client.selfRestored = selfRestored;
		this._attachToSocket(client, key);
		return client;
	}

	_attachToSocket(client, key) {
		client.once('error', (code, err) => {
			delete this.sockets[key];
			if (!client.connected) {
				this.emit('clientError', err, client);
			}
		});
		client.once('close', () => {
			delete this.sockets[key];
			client = null;
			if (this._closing && Object.keys(this.sockets).length === 0) {
				this._closeSocket();
			}
		});
		client.once('reconnect', socket => {
			// treat like a brand new connection
			socket.reset();
			this._attachToSocket(socket, key);
			this.sockets[key] = socket;
		});

		client.once('secureConnect', () => {
			this.emit('secureConnection', client);
		});

		this.emit('connection', client);
	}

	_endSockets() {
		if (this.dgramSocket) {
			this.dgramSocket.removeListener('message', this._onMessage);
		}
		const sockets = Object.keys(this.sockets);
		sockets.forEach(skey => {
			const s = this.sockets[skey];
			if (s) {
				s.end();
			}
		});
	}

	_socketClosed() {
		this.listening = false;
		if (this.dgramSocket) {
			this.dgramSocket.removeListener('message', this._onMessage);
		}
		this.dgramSocket = null;
		this._endSockets();
		this.sockets = {};

		this.emit('close');
		this.removeAllListeners();
	}

	_closeSocket() {
		if (!this.listening) {
			process.nextTick(() => {
				this._socketClosed();
			});
			return;
		}

		if (this.dgramSocket) {
			this.dgramSocket.close();
		}
	}
}

module.exports = DtlsServer;
