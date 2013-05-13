#!/bin/sh

function stopOnErr()
{
	if [ $? != 0 ]
	  then
		echo "*** an error occured, script aborted";
		exit 1;
	fi
}

CC='clang -g'
GLIB_FLAGS=`pkg-config --cflags --libs glib-2.0`
export PKG_CONFIG_PATH=/usr/local/ssl/lib/pkgconfig
OPENSSL_FLAGS=`pkg-config --cflags --libs libcrypto libssl`
OPENSSL_FLAGS="$OPENSSL_FLAGS -ldl"
PURPLE_FLAGS="-lpurple"

CRYPTRON="cryptron/ecies.c cryptron/secure.c cryptron/keys.c"

echo "Building tests..."
$CC SymCipherTest.c SymCipher.c -o SymCipherTest $GLIB_FLAGS $OPENSSL_FLAGS $PURPLE_FLAGS
stopOnErr
#$CC AsymCipherTest.c AsymCipher.c -o AsymCipherTest $CRYPTRON $GLIB_FLAGS $OPENSSL_FLAGS
stopOnErr

echo "Testing..."
./SymCipherTest
stopOnErr
./AsymCipherTest
stopOnErr
