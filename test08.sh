#!/bin/sh
# NEGATIVE Test: test_cryptocopy should fail when output file is not provided

/bin/rm -rf input.txt output.txt

#/bin/cp in_test.txt input.txt
echo "Hello CSE-506" > input.txt

./test_cryptocopy -e -p input.txt output.txt
retval=$?
if test $retval != 0 ; then
	echo test_cryptocopy failed with error: $retval, output file not provided
else
	echo test_cryptocopy success
fi
