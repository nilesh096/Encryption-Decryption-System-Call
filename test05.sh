#!/bin/sh
# NEGATIVE Test: test_cryptocopy should fail when password is provided with copy option

/bin/rm -rf input.txt output.txt

#/bin/cp in_test.txt input.txt
echo "Hello CSE-506" > input.txt

./test_cryptocopy -c -p "HelloWorld" input.txt output.txt
retval=$?
if test $retval != 0 ; then
	echo "test_cryptocopy failed with error: $retval, password can't be provided with copy option"
	exit $retval
else
	echo test_cryptocopy success
fi