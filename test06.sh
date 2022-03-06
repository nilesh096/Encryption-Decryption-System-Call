#!/bin/sh
# NEGATIVE Test: test_cryptocopy should fail when password length is less than equal to 6 characters

/bin/rm -rf input.txt output.txt

#/bin/cp in_test.txt input.txt
echo "Hello CSE-506" > input.txt

./test_cryptocopy -e -p "Hello" input.txt output.txt
retval=$?
if test $retval != 0 ; then
	echo "test_cryptocopy failed with error: $retval, password should be greater than 6 characters"
	exit $retval
else
	echo test_cryptocopy success
fi
