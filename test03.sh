#!/bin/sh
# NEGATIVE Test: test_cryptocopy should fail when output file is a hardlink of the inputfile 
# or vise-versa

/bin/rm -rf input.txt output.txt

echo "Hello CSE-506" > input.txt

#Creating hardlink file of the input.txt file
ln input.txt output.txt

./test_cryptocopy -e -p "HelloWorld" input.txt output.txt
retval=$?
if test $retval != 0 ; then
	echo Encryption failed with error: $retval, hardlink provided
	exit $retval
else
	echo Encryption succeeded
fi
