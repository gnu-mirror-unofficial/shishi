## Process this file with automake to produce Makefile.in.

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
libfoo_la_SOURCES += allocsa.h allocsa.c


libfoo_la_SOURCES += exit.h

libfoo_la_SOURCES += exitfail.h exitfail.c


libfoo_la_SOURCES += getdate.h getdate.y
BUILT_SOURCES += getdate.c
MAINTAINERCLEANFILES += getdate.c

libfoo_la_SOURCES += getdomainname.h


libfoo_la_SOURCES += getline.h
EXTRA_DIST += getndelim2.h getndelim2.c

BUILT_SOURCES += $(GETOPT_H)
EXTRA_DIST += getopt_.h getopt_int.h

# We need the following in order to create an <getopt.h> when the system
# doesn't have one that works with the given compiler.
all-local $(libfoo_la_OBJECTS): $(GETOPT_H)
getopt.h: getopt_.h
	cp $(srcdir)/getopt_.h $@-t
	mv $@-t $@
MOSTLYCLEANFILES += getopt.h getopt.h-t

libfoo_la_SOURCES += getsubopt.h

libfoo_la_SOURCES += gettext.h

libfoo_la_SOURCES += gettime.c



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

libfoo_la_SOURCES += strdup.h

libfoo_la_SOURCES += strndup.h


libfoo_la_SOURCES += timegm.h

libfoo_la_SOURCES += time_r.h

libfoo_la_SOURCES += timespec.h

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

libfoo_la_LIBADD += @LIB_CLOCK_GETTIME@
libfoo_la_SOURCES += base64.c base64.h
EXTRA_DIST += README
