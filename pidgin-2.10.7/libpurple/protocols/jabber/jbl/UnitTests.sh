#!/bin/sh

CC=clang
GLIB_FLAGS=`pkg-config --cflags --libs glib-2.0`

echo "Building..."
$CC SymCipherTest.c SymCipher.c -o SymCipherTest -lcrypto $GLIB_FLAGS

echo "Testing..."
./SymCipherTest
