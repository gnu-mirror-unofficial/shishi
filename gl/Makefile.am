## Process this file with automake to produce Makefile.in.

# GNULIB modules:
# strnlen strndup mempcpy alloca argp error gethostname getopt memmove memset realloc setenv strcase strchrnul strdup strerror sysexits vasprintf vasnprintf xalloc xstrndup getdate timegm linebuffer xgethostname xgetdomainname getline xreadlink

# Local not-yet-in-gnulib modules:
# + base64 (x)memdup

# After using gnulib-tool, do:
# s/libfoo_a/libfoo_la/g
# s/libfoo.a/libfoo.la/
# s/libfoo_a_LIBADD = @LIBOBJS@//g
# s/#libfoo_la_LIBADD/libfoo_la_LIBADD/g
# s/@LIBOBJS@/@LTLIBOBJS@/g
# s/noinst_LIBRARIES/noinst_LTLIBRARIES/g

AUTOMAKE_OPTIONS = 1.5 gnits no-dependencies

noinst_LTLIBRARIES = libfoo.la

libfoo_la_SOURCES =
libfoo_la_LIBADD = @LTLIBOBJS@
EXTRA_DIST =
BUILT_SOURCES =
SUFFIXES =
MOSTLYCLEANFILES =
CLEANFILES =
DISTCLEANFILES =
MAINTAINERCLEANFILES =
BUILT_SOURCES += $(ALLOCA_H)
EXTRA_DIST += alloca_.h

# We need the following in order to create an <alloca.h> when the system
# doesn't have one that works with the given compiler.
all-local $(libfoo_la_OBJECTS): $(ALLOCA_H)
alloca.h: alloca_.h
	cp $(srcdir)/alloca_.h $@-t
	mv $@-t $@
MOSTLYCLEANFILES += alloca.h alloca.h-t

libfoo_la_LIBADD += @ALLOCA@
#libfoo_la_LIBADD += @LTALLOCA@
libfoo_la_SOURCES += argp.h argp-ba.c argp-eexst.c \
           argp-fmtstream.c argp-fmtstream.h argp-fs-xinl.c argp-help.c \
           argp-namefrob.h argp-parse.c argp-pv.c argp-pvh.c argp-xinl.c


libfoo_la_SOURCES += exit.h

libfoo_la_SOURCES += exitfail.h exitfail.c


libfoo_la_SOURCES += getdate.h getdate.y
BUILT_SOURCES += getdate.c
MAINTAINERCLEANFILES += getdate.c

libfoo_la_SOURCES += getdomainname.h


libfoo_la_SOURCES += getline.h
EXTRA_DIST += getndelim2.h getndelim2.c

libfoo_la_SOURCES += getopt.h getopt.c getopt1.c

libfoo_la_SOURCES += gettext.h

libfoo_la_SOURCES += linebuffer.h linebuffer.c



libfoo_la_SOURCES += mempcpy.h



libfoo_la_SOURCES += progname.h progname.c




libfoo_la_SOURCES += setenv.h

BUILT_SOURCES += $(STDBOOL_H)
EXTRA_DIST += stdbool_.h

# We need the following in order to create an <stdbool.h> when the system
# doesn't have one that works.
all-local $(libfoo_la_OBJECTS): $(STDBOOL_H)
stdbool.h: stdbool_.h
	sed -e 's/@''HAVE__BOOL''@/$(HAVE__BOOL)/g' < $(srcdir)/stdbool_.h > $@-t
	mv $@-t $@
MOSTLYCLEANFILES += stdbool.h stdbool.h-t

libfoo_la_SOURCES += strcase.h

libfoo_la_SOURCES += strchrnul.h



libfoo_la_SOURCES += strndup.h


EXTRA_DIST += sysexit_.h

# We need the following in order to create a <sysexits.h> when the system
# doesn't have one that works with the given compiler.
all-local $(libfoo_la_OBJECTS): $(SYSEXITS_H)
sysexits.h: sysexit_.h
	cp $(srcdir)/sysexit_.h sysexits.h-t
	mv sysexits.h-t sysexits.h
MOSTLYCLEANFILES += sysexits.h sysexits.h-t

libfoo_la_SOURCES += time_r.h

libfoo_la_SOURCES += timegm.h

libfoo_la_SOURCES += unlocked-io.h

libfoo_la_SOURCES += printf-args.h printf-parse.h vasnprintf.h

libfoo_la_SOURCES += vasprintf.h

libfoo_la_SOURCES += xalloc.h xmalloc.c xstrdup.c

libfoo_la_SOURCES += xgetdomainname.h xgetdomainname.c

libfoo_la_SOURCES += xgethostname.h xgethostname.c

libfoo_la_SOURCES += xreadlink.h xreadlink.c

libfoo_la_SOURCES += xsize.h

libfoo_la_SOURCES += xstrndup.h xstrndup.c


# Local changes

libfoo_la_SOURCES += base64.c base64.h
libfoo_la_SOURCES += memdup.h memdup.c
libfoo_la_SOURCES += xmemdup.h xmemdup.c
EXTRA_DIST += README
