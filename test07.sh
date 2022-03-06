#!/bin/sh
# NEGATIVE Test, decryption should fail when different password provided for encryption and decryption
# While decrypting, a new output file is provided, but if decryption fails, then that file shouldn't 
# exist on the filesytem

/bin/rm -rf input.txt output.txt

#/bin/cp in_test.txt input.txt
echo "Hello CSE-506" > input.txt

./test_cryptocopy -e -p "HelloWorld" input.txt output.txt
retval=$?
if test $retval != 0 ; then
	echo Encryption failed with error: $retval
	exit $retval
else
	echo Encryption succeeded
fi

#new output file intest.txt provided
# intest.txt shouldn't exist on the fs if decryption fails
./test_cryptocopy -d -p "HelloWorldxxxx" output.txt intest.txt
retval=$?
if test $retval != 0 ; then
	echo Decryption failed with error: $retval
	exit $retval
else
	echo Decryption succeeded
fi

if cmp intest.txt input.txt ; then
	echo "test_cryptocopy: input and output files contents are the same"
	exit 0
else
	echo "test_cryptocopy: input and output files contents DIFFER"
	exit 1
fi
