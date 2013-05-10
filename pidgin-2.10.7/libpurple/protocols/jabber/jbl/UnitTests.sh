#!/bin/sh

CC=gcc -g
GLIB_FLAGS=`pkg-config --cflags --libs glib-2.0`
export PKG_CONFIG_PATH=/usr/local/ssl/lib/pkgconfig
OPENSSL_FLAGS=`pkg-config --cflags --libs libcrypto libssl`
OPENSSL_FLAGS="$OPENSSL_FLAGS -ldl"

CRYPTRON="cryptron/ecies.c cryptron/secure.c cryptron/keys.c"

# echo "Building SymCipher..."
# $CC SymCipherTest.c SymCipher.c -o SymCipherTest -lcrypto $GLIB_FLAGS $OPENSSL_FLAGS
echo "Building AsymCipher..."
$CC AsymCipherTest.c AsymCipher.c $CRYPTRON -o AsymCipherTest -lcrypto $GLIB_FLAGS $OPENSSL_FLAGS

# echo "Testing SymCipher..."
# ./SymCipherTest
echo "Testing SymCipher..."
./AsymCipherTest
