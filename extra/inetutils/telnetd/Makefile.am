inetdaemon_PROGRAMS = shishi-telnetd

shishi_telnetd_SOURCES = telnetd.c pty.c term.c utility.c \
 state.c termstat.c slc.c
noinst_HEADERS = telnetd.h

man_MANS = shishi-telnetd.8

LIBTERMCAP = @LIBTERMCAP@
LIBCRYPT = @LIBCRYPT@
LIBUTIL = @LIBUTIL@

LDADD = -L../libinetutils -L../libtelnet -linetutils -ltelnet \
	$(LIBTERMCAP) $(LIBUTIL) $(LIBCRYPT) @LIBAUTH@

EXTRA_DIST = $(man_MANS)
