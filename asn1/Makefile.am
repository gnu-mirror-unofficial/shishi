## Process this file with automake to produce Makefile.in.

INCLUDES = -I../

EXTRA_DIST = libtasn1.h der.h mem.h gstr.h errors.h \
             int.h parser_aux.h structure.h errors_int.h \
             element.h README

noinst_LIBRARIES = libminitasn1.a

libminitasn1_a_SOURCES = decoding.c gstr.c errors.c parser_aux.c \
           structure.c element.c coding.c
