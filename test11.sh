#!/bin/sh
# Test basic encryption/decryption functionality with a 30 MB file

/bin/rm -rf input.txt output.txt

seq 4000000 > input.txt

size=$(du -sh input.txt | awk '{ print $1 }')

echo "The size of the input file is $size"

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
	exit 0
else
	echo "test_cryptocopy: input and output files contents DIFFER"
	exit 1
fi