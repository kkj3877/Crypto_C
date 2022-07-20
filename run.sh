#!/bin/bash

cd ./build/

cmake ..
if [ "$?" -ne "0" ]
then
    exit 1
fi

make
if [ "$?" -ne "0" ]
then
    exit 1
fi

./test/test_lea
