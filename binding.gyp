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
        "mbedx509"
      ],
      "defines": [
        "MBEDTLS_CONFIG_FILE=\"node_dtls_conf.h\""
      ]
    }
  ]
}
