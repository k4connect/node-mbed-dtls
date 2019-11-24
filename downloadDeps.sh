#!/bin/bash
rm mbedtls -rf
git clone -b development https://github.com/ARMmbed/mbedtls.git mbedtls

# ARMmbed requires a submodule for the crypto sources.
pushd mbedtls
git submodule update --init crypto
popd
# git clone -b 5d74241b54632db5d0f71b05bf81a970be32af06 https://github.com/ARMmbed/mbedtls.git mbedtls
