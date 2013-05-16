#!/bin/sh

function check()
{
	echo "$@"
	$@
	
	if [ $? != 0 ]
	  then
		echo "*** an error occured, script aborted";
		exit 1;
	fi
}

CC='gcc -g -Wall'
GLIB_FLAGS=`pkg-config --cflags --libs glib-2.0`
export PKG_CONFIG_PATH=/usr/local/ssl/lib/pkgconfig
OPENSSL_FLAGS=`pkg-config --cflags --libs libcrypto libssl`
OPENSSL_FLAGS="$OPENSSL_FLAGS -ldl"
PURPLE_FLAGS="-lpurple"

CRYPTRON="cryptron/ecies.c cryptron/secure.c cryptron/keys.c"

echo "Building tests..."
check $CC SymCipherTest.c SymCipher.c -o SymCipherTest $GLIB_FLAGS $OPENSSL_FLAGS $PURPLE_FLAGS
check $CC AsymCipherTest.c AsymCipher.c -o AsymCipherTest $CRYPTRON $GLIB_FLAGS $OPENSSL_FLAGS


echo "Testing..."
check ./SymCipherTest
check ./AsymCipherTest

echo "End of script"