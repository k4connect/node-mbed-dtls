# node-mbed-dtls
node DTLS server wrapping [mbedtls](https://github.com/ARMmbed/mbedtls)


## Setup

Run

```
git submodule update --init mbedtls
```

If you don't run this, the mbedtls directory will be empty, causing `no rule for target aes.o` errors when building.

## Building

```
npm run build
```

or

```
npm install
```
