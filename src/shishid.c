/* shishid.c	Shishi Key Distribution Center daemon.
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
#include "config.h"
#endif

#ifdef STDC_HEADERS
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#endif

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#if defined HAVE_DECL_H_ERRNO && !HAVE_DECL_H_ERRNO
extern int h_errno;
#endif

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#if HAVE_INTTYPES_H
# include <inttypes.h>
#else
# if HAVE_STDINT_H
#  include <stdint.h>
# endif
#endif

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

#if HAVE_STRING_H
# if !STDC_HEADERS && HAVE_MEMORY_H
#  include <memory.h>
# endif
# include <string.h>
#endif
#if HAVE_STRINGS_H
# include <strings.h>
#endif

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif

#ifdef ENABLE_NLS
extern char *_shishi_gettext (const char *str);
#define _(String) _shishi_gettext (String)
#define gettext_noop(String) String
#define N_(String) gettext_noop (String)
#endif

#include <shishi.h>
#include <argp.h>

#define FAMILY_IPV4 "IPv4"
#define FAMILY_IPV6 "IPv6"

#ifdef WITH_IPV6
#define LISTEN_DEFAULT FAMILY_IPV4 ":*:kerberos/udp, " \
			FAMILY_IPV4 ":*:kerberos/tcp, " \
			FAMILY_IPV6 ":*:kerberos/udp, " \
			FAMILY_IPV6 ":*:kerberos/tcp"
#else
#define LISTEN_DEFAULT "*:kerberos/udp, *:kerberos/tcp"
#endif

struct listenspec
{
  char *str;
  int family;
  struct sockaddr addr;
  int port;
  int type;
  int sockfd;
  char buf[BUFSIZ];
  size_t bufpos;
};

struct arguments
{
  int silent, verbose;
  char *cfgfile;
  struct listenspec *listenspec;
  int nlistenspec;
};

const char *argp_program_version = PACKAGE_STRING;
const char *argp_program_bug_address = PACKAGE_BUGREPORT;

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  struct arguments *arguments = state->input;
  char *ptrptr;
  char *val;
  int i;

  switch (key)
    {
    case 'q':
    case 's':
      arguments->silent = 1;
      break;

    case 'v':
      arguments->verbose = 1;
      break;

    case 'c':
      arguments->cfgfile = strdup (arg);
      break;

    case ARGP_KEY_END:
      if (arguments->nlistenspec > 0)
	break;
      arg = strdup (LISTEN_DEFAULT);
      /* fall through */

    case 'l':
      for (i = 0; (val = strtok_r (i == 0 ? arg : NULL, ", \t", &ptrptr));
	   i++)
	{
	  char *service, *proto;
	  struct servent *se;
	  struct hostent *he;
	  struct listenspec *ls;
	  struct sockaddr_in *sin;
#ifdef WITH_IPV6
	  struct sockaddr_in6 *sin6;
#endif

	  arguments->nlistenspec++;
	  arguments->listenspec = realloc (arguments->listenspec,
					   sizeof (*arguments->listenspec) *
					   arguments->nlistenspec);
	  if (arguments->listenspec == NULL)
	    argp_error (state, "Fatal memory allocation error");
	  ls = &arguments->listenspec[arguments->nlistenspec - 1];
	  ls->str = strdup (val);
	  ls->bufpos = 0;
	  sin = (struct sockaddr_in *) &ls->addr;
#ifdef WITH_IPV6
	  sin6 = (struct sockaddr_in6 *) &ls->addr;
#endif

	  proto = strrchr (val, '/');
	  if (proto == NULL)
	    argp_error (state, "Could not find type in listen spec: `%s'",
			ls->str);
	  *proto = '\0';
	  proto++;

	  if (strcmp (proto, "tcp") == 0)
	    ls->type = SOCK_STREAM;
	  else
	    ls->type = SOCK_DGRAM;

	  service = strrchr (val, ':');
	  if (service == NULL)
	    argp_error (state, "Could not find service in listen spec: `%s'",
			ls->str);
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
	    argp_error (state, "Unknown service `%s' in listen spec: `%s'",
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
	  else if (he = gethostbyname (val))
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
		argp_error (state, "Unknown protocol family (%d) returned "
			    "by gethostbyname(\"%s\"): `%s'", he->h_addrtype,
			    val, ls->str);
	    }
	  else
	    argp_error (state, "Unknown host `%s' in listen spec: `%s'",
			val, ls->str);

	}
      break;

    case ARGP_KEY_ARG:
      argp_error (state, "Too many arguments: `%s'", arg);
      break;

    default:
      return ARGP_ERR_UNKNOWN;
    }

  return 0;
}

static struct argp_option options[] = {

  {"verbose", 'v', 0, 0,
   "Produce verbose output."},

  {"quiet", 'q', 0, 0,
   "Don't produce any output."},

  {"silent", 's', 0, OPTION_ALIAS},

  {"configuration-file", 'c', "FILE", 0,
   "Read configuration from file.  Default is " SYSTEMCFGFILE "."},

  {"listen", 'l', "[FAMILY:]ADDRESS:SERVICE/TYPE,...", 0,
   "What to listen on. Family is \"IPv4\" or \"IPv6\", if absent the "
   "family is decided by gethostbyname(ADDRESS). An address of \"*\" "
   "indicates all addresses on the local host. "
   "The default is \"" LISTEN_DEFAULT "\"."},

  {0}
};

static struct argp argp = {
  options,
  parse_opt,
  NULL,
  "Shishid -- Key Distribution Center network daemon"
};

void
process (Shishi * handle,
	 struct arguments arg, char *data, int datalen, int sockfd)
{
  ASN1_TYPE kdcreq;
  ASN1_TYPE kdcrep, ticket, encticketpart;

  printf ("Processing %d bytes: %s\n", datalen, data);

  kdcreq = shishi_d2a_kdcreq (handle, data, datalen);
  if (kdcreq == ASN1_TYPE_EMPTY)
    puts ("oops");

  shishi_kdcreq_print (handle, stdout, kdcreq);

  puts ("o");
  kdcrep = shishi_as_rep (handle);

  //shishi_kdcrep_print(handle, stdout, kdcrep);
  puts ("o");

  ticket = shishi_asn1_ticket (handle);
  puts ("o");

  //shishi_ticket_print (handle, stdout, ticket);

  encticketpart = shishi_asn1_encticketpart (handle);
  puts ("o");

  shishi_encticketpart_print (handle, stdout, encticketpart);

  puts ("o");

}

int quit = 0;

void
ctrlc (int signum)
{
  quit = 1;
}

int
doit (Shishi * handle, struct arguments arg)
{
  struct listenspec *ls;
  fd_set readfds;
  struct timeval timeout;
  struct sockaddr addr;
  socklen_t length = sizeof (addr);
  int maxfd = 0;
  int rc;
  int i;
  int read_bytes;
  int yes;

  for (i = 0; i < arg.nlistenspec; i++)
    {
      ls = &arg.listenspec[i];

      if (!arg.silent)
	printf ("Listening on %s...", ls->str);

      ls->sockfd = socket (ls->family, ls->type, 0);
      if (ls->sockfd < 0)
	{
	  if (!arg.silent)
	    printf ("failed\n");
	  perror ("socket");
	  ls->sockfd = 0;
	  continue;
	}

      yes = 1;
      if (setsockopt (ls->sockfd, SOL_SOCKET, SO_REUSEADDR,
		      (char *) &yes, sizeof (yes)) < 0)
	{
	  if (!arg.silent)
	    printf ("failed\n");
	  perror ("setsockopt");
	  close (ls->sockfd);
	  ls->sockfd = 0;
	  continue;
	}

      if (bind (ls->sockfd, &ls->addr, sizeof (ls->addr)) != 0)
	{
	  if (!arg.silent)
	    printf ("failed\n");
	  perror ("bind");
	  close (ls->sockfd);
	  ls->sockfd = 0;
	  continue;
	}

      if (ls->type == SOCK_STREAM && listen (ls->sockfd, 512) != 0)
	{
	  if (!arg.silent)
	    printf ("failed\n");
	  perror ("listen");
	  close (ls->sockfd);
	  ls->sockfd = 0;
	  continue;
	}

      maxfd++;
      if (!arg.silent)
	printf ("done\n");
    }

  if (maxfd == 0)
    {
      fprintf (stderr, "Failed to bind any ports.\n");
      return 1;
    }

  if (!arg.silent)
    printf ("Listening on %d ports...\n", maxfd);

  signal (SIGINT, ctrlc);
  signal (SIGTERM, ctrlc);

  while (!quit)
    {
      sleep (1);
      do
	{
	  FD_ZERO (&readfds);
	  maxfd = 0;
	  for (i = 0; i < arg.nlistenspec; i++)
	    {
	      if (arg.listenspec[i].sockfd >= maxfd)
		maxfd = arg.listenspec[i].sockfd + 1;
	      FD_SET (arg.listenspec[i].sockfd, &readfds);
	    }
	}
      while ((rc = select (maxfd, &readfds, NULL, NULL, NULL)) == 0);

      if (rc < 0)
	{
	  if (errno != EINTR)
	    perror ("select");
	  continue;
	}

      for (i = 0; i < arg.nlistenspec; i++)
	if (FD_ISSET (arg.listenspec[i].sockfd, &readfds))
	  {
	    if (arg.listenspec[i].type == SOCK_STREAM &&
		arg.listenspec[i].family != -1)
	      {
		fprintf (stderr, "New connection on %s...",
			 arg.listenspec[i].str);

		/* XXX search for closed fd's before allocating new entry */
		arg.listenspec = realloc (arg.listenspec,
					  sizeof (*arg.listenspec) *
					  (arg.nlistenspec + 1));
		if (arg.listenspec != NULL)
		  {
		    struct sockaddr_in *sin;
		    char *str;

		    arg.nlistenspec++;
		    ls = &arg.listenspec[arg.nlistenspec - 1];
		    ls->bufpos = 0;
		    ls->type = arg.listenspec[i].type;
		    ls->family = -1;
		    length = sizeof (ls->addr);
		    ls->sockfd = accept (arg.listenspec[i].sockfd,
					 &ls->addr, &length);
		    sin = (struct sockaddr_in *) &ls->addr;
		    str = inet_ntoa (sin->sin_addr);
		    ls->str = malloc (strlen (arg.listenspec[i].str) +
				      strlen (" peer ") + strlen (str) + 1);
		    sprintf (ls->str, "%s peer %s", arg.listenspec[i].str,
			     str);
		    puts (ls->str);
		  }
	      }
	    else
	      {
		ls = &arg.listenspec[i];

		read_bytes = recvfrom (ls->sockfd, ls->buf + ls->bufpos,
				       BUFSIZ - ls->bufpos, 0, &addr,
				       &length);

		if (arg.listenspec[i].type == SOCK_STREAM &&
		    arg.listenspec[i].family == -1 && read_bytes == 0)
		  {
		    printf ("Peer %s disconnected\n", ls->str);
		    close (ls->sockfd);
		    ls->sockfd = 0;
		  }
		else
		  {
		    ls->bufpos += read_bytes;
		    ls->buf[ls->bufpos] = '\0';
		  }

		printf ("Has %d bytes from %s\n", ls->bufpos, ls->str);

		if (arg.listenspec[i].type == SOCK_DGRAM ||
		    (ls->bufpos > 4
		     && ntohl (*(int *) ls->buf) == ls->bufpos))
		  {
		    process (handle, arg, ls->buf, ls->bufpos, ls->sockfd);
		    ls->bufpos = 0;
		  }
	      }
	  }
    }

  for (i = 0; i < arg.nlistenspec; i++)
    if (arg.listenspec[i].sockfd)
      {
	if (!arg.silent)
	  printf ("Closing %s...", arg.listenspec[i].str);
	rc = close (arg.listenspec[i].sockfd);
	if (rc != 0)
	  {
	    if (!arg.silent)
	      printf ("failed\n");
	    perror ("close");
	  }
	else if (!arg.silent)
	  printf ("done\n");
      }

  return 0;
}

int
main (int argc, char *argv[])
{
  struct arguments arg;
  Shishi *handle;
  int rc;

  memset ((void *) &arg, 0, sizeof (arg));
  argp_parse (&argp, argc, argv, ARGP_IN_ORDER, 0, &arg);

  rc = shishi_init_with_paths (&handle, NULL, arg.cfgfile, "");
  if (rc != SHISHI_OK)
    {
      fprintf (stderr, "Could not initialize library\n");
      return 1;
    }

  rc = doit (handle, arg);

  shishi_done (handle);

  return rc;
}
