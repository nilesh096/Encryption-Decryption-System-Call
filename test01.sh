#!/bin/sh
# test basic copy functionality

/bin/rm -rf input.txt output.txt

#/bin/cp in_test.txt input.txt
echo "Hello CSE-506" > input.txt

./test_cryptocopy -c input.txt output.txt
retval=$?
if test $retval != 0 ; then
	echo test_cryptocopy failed with error: $retval
	exit $retval
else
	echo test_cryptocopy program succeeded
fi

if cmp input.txt output.txt ; then
	echo "test_cryptocopy: input and output files contents are the same"
	exit 0
else
	echo "test_cryptocopy: input and output files contents DIFFER"
	exit 1
fi






