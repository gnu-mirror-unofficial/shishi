/* shishid.c --- Shishi Key Distribution Center daemon.
 * Copyright (C) 2002, 2003  Simon Josefsson
 *
 * This file is part of Shishi.
 *
 * Shishi is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Shishi is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Shishi; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>

/* Get setuid, read, etc. */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

/* Get gethostbyname, getservbyname. */
#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif

/* Get getpwnam. */
#ifdef HAVE_PWD_H
# include <pwd.h>
#endif

/* For select, etc. */
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

/* For select, etc. */
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

/* Get select, etc. */
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif

/* Get accept, sendto, etc. */
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif

/* Used for the backlog argument to listen. */
#ifndef SOMAXCONN
# define SOMAXCONN INT_MAX
#endif

#ifdef HAVE_SYS_IOCTL_H
# include <sys/ioctl.h>
#endif

/* Get errno. */
#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif
#ifndef errno
extern int errno;
#endif

#if HAVE_INTTYPES_H
# include <inttypes.h>
#else
# if HAVE_STDINT_H
#  include <stdint.h>
# endif
#endif

/* Get signal, etc. */
#ifdef HAVE_SIGNAL_H
# include <signal.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IN6_H
# include <netinet/in6.h>
#endif

#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif

#ifdef HAVE_SYSLOG_H
# include <syslog.h>
#endif

#ifdef USE_STARTTLS
# include <gnutls/gnutls.h>
#endif

/* Setup i18n. */
#ifdef HAVE_LOCALE_H
# include <locale.h>
#else
# define setlocale(Category, Locale) /* empty */
#endif
#include <gettext.h>
#define _(String) gettext (String)
#define gettext_noop(String) String
#define N_(String) gettext_noop (String)

/* Get xmalloc. */
#include "xalloc.h"

/* Get error. */
#include "error.h"

/* Get asprintf. */
#include "vasprintf.h"

/* Get program_name, etc. */
#include "progname.h"

/* Shishi and Shisa library. */
#include <shishi.h>
#include <shisa.h>

/* Command line parameter parser via gengetopt. */
#include "shishid_cmd.h"

#define FAMILY_IPV4 "IPv4"
#define FAMILY_IPV6 "IPv6"

#ifdef WITH_IPV6
# define LISTEN_DEFAULT FAMILY_IPV4 ":*:kerberos/udp, " \
			FAMILY_IPV4 ":*:kerberos/tcp, " \
			FAMILY_IPV6 ":*:kerberos/udp, " \
			FAMILY_IPV6 ":*:kerberos/tcp"
#else
# define LISTEN_DEFAULT "*:kerberos/udp, *:kerberos/tcp"
#endif

struct listenspec
{
  char *str;
  int family;
  int listening;
  struct sockaddr listenaddr;
  struct sockaddr addr;
  socklen_t addrlen;
  struct sockaddr_in *sin;
  int port;
  int type;
  int sockfd;
  char buf[BUFSIZ]; /* XXX */
  size_t bufpos;
#ifdef USE_STARTTLS
  gnutls_session session;
  int usetls;
#endif
  struct listenspec *next;
};

Shishi * handle;
Shisa * dbh;
struct gengetopt_args_info arg;
struct listenspec *listenspec;
char *fatal_krberror;
size_t fatal_krberror_len;

#ifdef USE_STARTTLS
#define DH_BITS 1024
gnutls_dh_params dh_params;
gnutls_anon_server_credentials anoncred;
#endif

extern void kdc_loop (void);

static void
kdc_listen ()
{
  struct listenspec *ls;
  int maxfd = 0;
  int i;
  int yes;

  for (ls = listenspec; ls; ls = ls->next)
    {
      if (!arg.quiet_flag)
	printf ("Listening on %s...", ls->str);

      ls->sockfd = socket (ls->family, ls->type, 0);
      if (ls->sockfd < 0)
	{
	  if (!arg.quiet_flag)
	    printf ("failed\n");
	  error (0, errno, "Cannot listen on %s because socket failed",
		 ls->str);
	  ls->sockfd = 0;
	  continue;
	}

      yes = 1;
      if (setsockopt (ls->sockfd, SOL_SOCKET, SO_REUSEADDR,
		      (char *) &yes, sizeof (yes)) < 0)
	{
	  if (!arg.quiet_flag)
	    printf ("failed\n");
	  error (0, errno, "Cannot listen on %s because setsockopt failed",
		 ls->str);
	  close (ls->sockfd);
	  ls->sockfd = 0;
	  continue;
	}

      if (bind (ls->sockfd, &ls->listenaddr, sizeof (ls->listenaddr)) != 0)
	{
	  if (!arg.quiet_flag)
	    printf ("failed\n");
	  error (0, errno, "Cannot listen on %s because bind failed",
		 ls->str);
	  close (ls->sockfd);
	  ls->sockfd = 0;
	  continue;
	}

      if (ls->type == SOCK_STREAM && listen (ls->sockfd, SOMAXCONN) != 0)
	{
	  if (!arg.quiet_flag)
	    printf ("failed\n");
	  error (0, errno, "Cannot listen on %s because listen failed",
		 ls->str);
	  close (ls->sockfd);
	  ls->sockfd = 0;
	  continue;
	}

      maxfd++;
      if (!arg.quiet_flag)
	printf ("done\n");
    }

  if (maxfd == 0)
    error (EXIT_FAILURE, 0, "Failed to bind any ports.");

  if (!arg.quiet_flag)
    printf ("Listening on %d ports...\n", maxfd);
}

static void
kdc_unlisten (void)
{
  struct listenspec *ls;
  int rc;

  for (ls = listenspec; ls; ls = ls->next)
    {
      if (!ls->listening)
	error (0, 0, "Unclosed outstanding connection to %s on socket %d?!",
	       ls->str, ls->sockfd);

      if (ls->sockfd)
	{
	  if (!arg.quiet_flag)
	    printf ("Closing %s...\n", ls->str);
	  rc = close (ls->sockfd);
	  if (rc != 0)
	    error (0, errno, "Could not close %s on socket %d",
		   ls->str, ls->sockfd);
	}

      if (ls->str)
	free (ls->str);
    }
}

static void
kdc_setuid (void)
{
  struct passwd *passwd;
  int rc;

  if (!arg.setuid_given)
    return;

  passwd = getpwnam (arg.setuid_arg);
  if (passwd == NULL)
    if (errno)
      error (EXIT_FAILURE, errno, "Cannot setuid because getpwnam failed");
    else
      error (EXIT_FAILURE, 0, "No such user `%s'.", arg.setuid_arg);

  rc = setuid (passwd->pw_uid);
  if (rc == -1)
    error (EXIT_FAILURE, errno, "Cannot setuid");

  if (!arg.quiet_flag)
    printf ("User identity set to `%s' (%d)...\n",
	    passwd->pw_name, passwd->pw_uid);
}

static int
setup_fatal_krberror (Shishi * handle)
{
  Shishi_asn1 krberr;
  int rc;

  krberr = shishi_krberror (handle);
  if (!krberr)
    return SHISHI_MALLOC_ERROR;

  rc = shishi_krberror_set_etext (handle, krberr,
				  "Internal KDC error, contact administrator");
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_krberror_der (handle, krberr, &fatal_krberror,
			    &fatal_krberror_len);
  if (rc != SHISHI_OK)
    return rc;

  return SHISHI_OK;
}

static void
doit (void)
{
  int err;

  err = shishi_init_server_with_paths (&handle, arg.configuration_file_arg);
  if (err)
    error (EXIT_FAILURE, 0, "Cannot initialize Shishi: %s (%d)",
	   shishi_strerror (err), err);

  if (arg.verbose_flag > 1)
    shishi_cfg (handle, "verbose");

  if (arg.verbose_flag > 2)
    shishi_cfg (handle, "verbose-noice");

  if (arg.verbose_flag > 3)
    shishi_cfg (handle, "verbose-asn1");

  if (arg.verbose_flag > 4)
    shishi_cfg (handle, "verbose-crypto");

  err = shisa_init (&dbh);
  if (err)
    error (EXIT_FAILURE, 0, "Cannot initialize Shisa: %s (%d)",
	   shisa_strerror (err), err);

  err = setup_fatal_krberror (handle);
  if (err)
    error (EXIT_FAILURE, 0, "Cannot allocate fatal error packet: %s (%d)",
	   shisa_strerror (err), err);

#ifdef USE_STARTTLS
  if (!arg.quiet_flag)
    printf ("Initializing GNUTLS...\n");
  err = gnutls_global_init ();
  if (err)
    error (EXIT_FAILURE, 0, "Cannot initialize GNUTLS: %s (%d)",
	   gnutls_strerror (err), err);
  err = gnutls_dh_params_init (&dh_params);
  if (err)
    error (EXIT_FAILURE, 0, "Cannot initialize GNUTLS DH parameters: %s (%d)",
	   gnutls_strerror (err), err);
  err = gnutls_dh_params_generate2 (dh_params, DH_BITS);
  if (err)
    error (EXIT_FAILURE, 0, "Cannot generate GNUTLS DH parameters: %s (%d)",
	   gnutls_strerror (err), err);
  err = gnutls_anon_allocate_server_credentials (&anoncred);
  if (err)
    error (EXIT_FAILURE, 0, "Cannot allocate GNUTLS credential: %s (%d)",
	   gnutls_strerror (err), err);
  gnutls_anon_set_server_dh_params (anoncred, dh_params);
  if (!arg.quiet_flag)
    printf ("Initializing GNUTLS...done\n");
#endif

  kdc_listen ();

#ifdef LOG_PERROR
  openlog (PACKAGE, LOG_CONS | LOG_PERROR, LOG_DAEMON);
#else
  openlog (PACKAGE, LOG_CONS, LOG_DAEMON);
#endif

  kdc_setuid ();

  kdc_loop ();

  kdc_unlisten ();

#ifdef USE_STARTTLS
  if (!arg.quiet_flag)
    printf ("Deinitializing GNUTLS...\n");
  gnutls_global_deinit ();
  if (!arg.quiet_flag)
    printf ("Deinitializing GNUTLS...done\n");
#endif

  shisa_done (dbh);
  shishi_done (handle);
}

static void
parse_listen (char *listen)
{
  char *ptrptr;
  char *val;
  int i;

  for (i = 0; (val = strtok_r (i == 0 ? listen : NULL, ", \t", &ptrptr)); i++)
    {
      char *service, *proto;
      struct servent *se;
      struct hostent *he;
      struct listenspec *ls;
      struct sockaddr_in *sin;
#ifdef WITH_IPV6
      struct sockaddr_in6 *sin6;
#endif

      ls = xzalloc (sizeof (*ls));
      ls->next = listenspec;
      listenspec = ls;

      ls->str = strdup (val);
      ls->bufpos = 0;
      ls->listening = 1;
      sin = (struct sockaddr_in *) &ls->listenaddr;
#ifdef WITH_IPV6
      sin6 = (struct sockaddr_in6 *) &ls->listenaddr;
#endif

      proto = strrchr (val, '/');
      if (proto == NULL)
	error (1, 0, "Could not find type in listen spec: `%s'", ls->str);
      *proto = '\0';
      proto++;

      if (strcmp (proto, "tcp") == 0)
	ls->type = SOCK_STREAM;
      else
	ls->type = SOCK_DGRAM;

      service = strrchr (val, ':');
      if (service == NULL)
	error (1, 0, "Could not find service in listen spec: `%s'", ls->str);
      *service = '\0';
      service++;

      se = getservbyname (service, proto);
      if (se)
	ls->port = ntohs (se->s_port);
      else if (strcmp (service, "kerberos") == 0)
	ls->port = 88;
      else if (atoi (service) != 0)
	ls->port = atoi (service);
      else
	error (1, 0, "Unknown service `%s' in listen spec: `%s'",
	       service, ls->str);

#ifdef WITH_IPV6
      if (ls->family == AF_INET6)
	sin6->sin6_port = htons (ls->port);
      else
#endif
	sin->sin_port = htons (ls->port);

      if (strncmp (val, FAMILY_IPV4 ":", strlen (FAMILY_IPV4 ":")) == 0)
	{
	  ls->family = AF_INET;
	  val += strlen (FAMILY_IPV4 ":");
	}
#ifdef WITH_IPV6
      else if (strncmp (val, FAMILY_IPV6 ":", strlen (FAMILY_IPV6 ":")) ==
	       0)
	{
	  ls->family = AF_INET6;
	  val += strlen (FAMILY_IPV6 ":");
	}
#endif
      else
	ls->family = AF_INET;

      if (strcmp (val, "*") == 0)
	{
#ifdef WITH_IPV6
	  if (ls->family == AF_INET6)
	    sin6->sin6_addr = in6addr_any;
	  else
#endif
	    sin->sin_addr.s_addr = htonl (INADDR_ANY);
	}
      else if ((he = gethostbyname (val)))
	{
	  if (he->h_addrtype == AF_INET)
	    {
	      sin->sin_family = AF_INET;
	      memcpy (&sin->sin_addr, he->h_addr_list[0], he->h_length);
	    }
#ifdef WITH_IPV6
	  else if (he->h_addrtype == AF_INET6)
	    {
	      sin6->sin6_family = AF_INET6;
	      memcpy (&sin6->sin6_addr, he->h_addr_list[0], he->h_length);
	    }
#endif
	  else
	    error (1, 0, "Unknown protocol family (%d) returned "
		   "by gethostbyname(\"%s\"): `%s'", he->h_addrtype,
		   val, ls->str);
	}
      else
	error (1, 0, "Unknown host `%s' in listen spec: `%s'", val, ls->str);
    }
}

int
main (int argc, char *argv[])
{
  int rc;

  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);
  set_program_name (argv[0]);

  if (cmdline_parser (argc, argv, &arg) != 0)
    error (EXIT_FAILURE, 0, "Try `%s --help' for more information.",
	   program_name);

  if (arg.help_given)
    {
      cmdline_parser_print_help ();
      printf ("\nMandatory arguments to long options are "
	      "mandatory for short options too.\n\n");
      printf ("Report bugs to <%s>.\n", PACKAGE_BUGREPORT);
      return EXIT_SUCCESS;
    }

  if (!arg.configuration_file_arg)
    arg.configuration_file_arg = strdup (SYSTEMCFGFILE);
  if (!arg.listen_given)
    arg.listen_arg = strdup (LISTEN_DEFAULT);
  parse_listen (arg.listen_arg);

  doit ();

  free (arg.listen_arg);
  free (arg.configuration_file_arg);
  if (arg.setuid_arg)
    free (arg.setuid_arg);

  return EXIT_SUCCESS;
}
