#!/bin/sh

libtoolize || glibtoolize
aclocal
automake --add-missing
autoconf
