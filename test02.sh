#!/bin/sh
# Test basic encryption/decryption functionality of test_cryptocopy

/bin/rm -rf input.txt output.txt

echo "Hello CSE-506" > input.txt

./test_cryptocopy -e -p "HelloWorld" input.txt output.txt
retval=$?
if test $retval != 0 ; then
	echo Encryption failed with error: $retval
	exit $retval
else
	echo Encryption succeeded
fi


./test_cryptocopy -d -p "HelloWorld" output.txt intest.txt
retval=$?
if test $retval != 0 ; then
	echo Decryption failed with error: $retval
	exit $retval
else
	echo Decryption succeeded
fi

if cmp intest.txt input.txt ; then
	echo "test_cryptocopy: input and output files contents are the same"
	/bin/rm intest.txt
	exit 0
else
	echo "test_cryptocopy: input and output files contents DIFFER"
	/bin/rm intest.txt
	exit 1
fi
