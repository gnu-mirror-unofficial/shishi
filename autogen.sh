#!/bin/sh -x
autoreconf --install --force --verbose
: 'You can now run CFLAGS=-g ./configure --enable-maintainer-mode --disable-shared and then make.'
