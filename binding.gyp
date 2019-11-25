{
  "targets": [
    {
      "target_name": "mbedtls",
      "type": "static_library",
      "sources": [
        "mbedtls/library/debug.c",
        "mbedtls/library/ssl_cache.c",
        "mbedtls/library/ssl_ciphersuites.c",
        "mbedtls/library/ssl_cli.c",
        "mbedtls/library/ssl_cookie.c",
        "mbedtls/library/ssl_srv.c",
        "mbedtls/library/ssl_ticket.c",
        "mbedtls/library/ssl_tls.c"
      ],
      "include_dirs": [
        "mbedtls/include",
        "mbedtls/crypto/include",
        "config"
      ],
      "defines": [
        "MBEDTLS_CONFIG_FILE=\"node_dtls_conf.h\""
      ]
    },
    {
      "target_name": "mbedcrypto",
      "type": "static_library",
      "sources": [
        "mbedtls/crypto/library/aes.c",
        "mbedtls/crypto/library/aesni.c",
        "mbedtls/crypto/library/arc4.c",
        "mbedtls/crypto/library/aria.c",
        "mbedtls/crypto/library/asn1parse.c",
        "mbedtls/crypto/library/asn1write.c",
        "mbedtls/crypto/library/base64.c",
        "mbedtls/crypto/library/bignum.c",
        "mbedtls/crypto/library/blowfish.c",
        "mbedtls/crypto/library/camellia.c",
        "mbedtls/crypto/library/ccm.c",
        "mbedtls/crypto/library/chacha20.c",
        "mbedtls/crypto/library/chachapoly.c",
        "mbedtls/crypto/library/cipher.c",
        "mbedtls/crypto/library/cipher_wrap.c",
        "mbedtls/crypto/library/cmac.c",
        "mbedtls/crypto/library/ctr_drbg.c",
        "mbedtls/crypto/library/des.c",
        "mbedtls/crypto/library/dhm.c",
        "mbedtls/crypto/library/ecdh.c",
        "mbedtls/crypto/library/ecdsa.c",
        "mbedtls/crypto/library/ecjpake.c",
        "mbedtls/crypto/library/ecp.c",
        "mbedtls/crypto/library/ecp_curves.c",
        "mbedtls/crypto/library/entropy.c",
        "mbedtls/crypto/library/entropy_poll.c",
        "mbedtls/crypto/library/error.c",
        "mbedtls/crypto/library/gcm.c",
        "mbedtls/crypto/library/havege.c",
        "mbedtls/crypto/library/hkdf.c",
        "mbedtls/crypto/library/hmac_drbg.c",
        "mbedtls/crypto/library/md.c",
        "mbedtls/crypto/library/md2.c",
        "mbedtls/crypto/library/md4.c",
        "mbedtls/crypto/library/md5.c",
        "mbedtls/crypto/library/memory_buffer_alloc.c",
        "mbedtls/crypto/library/nist_kw.c",
        "mbedtls/crypto/library/oid.c",
        "mbedtls/crypto/library/padlock.c",
        "mbedtls/crypto/library/pem.c",
        "mbedtls/crypto/library/pk.c",
        "mbedtls/crypto/library/pk_wrap.c",
        "mbedtls/crypto/library/pkcs12.c",
        "mbedtls/crypto/library/pkcs5.c",
        "mbedtls/crypto/library/pkparse.c",
        "mbedtls/crypto/library/pkwrite.c",
        "mbedtls/crypto/library/platform.c",
        "mbedtls/crypto/library/platform_util.c",
        "mbedtls/crypto/library/poly1305.c",
        "mbedtls/crypto/library/psa_crypto.c",
        "mbedtls/crypto/library/psa_crypto_se.c",
        "mbedtls/crypto/library/psa_crypto_slot_management.c",
        "mbedtls/crypto/library/psa_crypto_storage.c",
        "mbedtls/crypto/library/psa_its_file.c",
        "mbedtls/crypto/library/ripemd160.c",
        "mbedtls/crypto/library/rsa.c",
        "mbedtls/crypto/library/rsa_internal.c",
        "mbedtls/crypto/library/sha1.c",
        "mbedtls/crypto/library/sha256.c",
        "mbedtls/crypto/library/sha512.c",
        "mbedtls/crypto/library/threading.c",
        "mbedtls/crypto/library/timing.c",
        "mbedtls/crypto/library/version.c",
        "mbedtls/crypto/library/version_features.c",
        "mbedtls/crypto/library/xtea.c"
      ],
      "include_dirs": [
        "mbedtls/include",
        "mbedtls/crypto/include",
        "config"
      ],
      "defines": [
        "MBEDTLS_CONFIG_FILE=\"node_dtls_conf.h\""
      ]
    },
    {
      "target_name": "mbedx509",
      "type": "static_library",
      "sources": [
        "mbedtls/library/certs.c",
        "mbedtls/library/pkcs11.c",
        "mbedtls/library/x509.c",
        "mbedtls/library/x509_create.c",
        "mbedtls/library/x509_crl.c",
        "mbedtls/library/x509_crt.c",
        "mbedtls/library/x509_csr.c",
        "mbedtls/library/x509write_crt.c",
        "mbedtls/library/x509write_csr.c"
      ],
      "include_dirs": [
        "mbedtls/include",
        "mbedtls/crypto/include",
        "config"
      ],
      "defines": [
        "MBEDTLS_CONFIG_FILE=\"node_dtls_conf.h\""
      ]
    },
    {
      "target_name": "node_mbed_dtls",
      "sources": [
        "src/init.cc",
        "src/DtlsServer.cc",
        "src/DtlsSocket.cc",
        "src/DtlsClientSocket.cc",
        "src/SessionWrap.cc"
      ],
      "include_dirs": [
        "<!(node -e \"require('nan')\")",
        "mbedtls/include",
        "mbedtls/crypto/include",
        "config"
      ],
      "dependencies": [
        "mbedtls",
        "mbedx509",
        "mbedcrypto"
      ],
      "defines": [
        "MBEDTLS_CONFIG_FILE=\"node_dtls_conf.h\""
      ]
    }
  ]
}
