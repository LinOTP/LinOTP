#!/bin/bash
if [[ $OSTYPE == darwin* ]]; then
    #Mac OSX
    glibtoolize;
else
    libtoolize;
fi;
aclocal
automake --add-missing
autoconf
./configure
make
sudo make install
