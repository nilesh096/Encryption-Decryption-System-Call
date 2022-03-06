#!/bin/sh
# NEGATIVE Test: test_cryptocopy should fail when input file is not provided

/bin/rm -rf input.txt output.txt

#/bin/cp in_test.txt input.txt
echo "Hello CSE-506" > input.txt

./test_cryptocopy -e -p "HelloWorld"
retval=$?
if test $retval != 0 ; then
	echo "test_cryptocopy failed with error: $retval, input file not provided"
else
	echo test_cryptocopy success
fi
