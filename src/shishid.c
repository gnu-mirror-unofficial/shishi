/* shishid.c	kerberos 5 daemon using shishi library
 * Copyright (C) 2002  Simon Josefsson
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

#ifdef STDC_HEADERS
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#endif

#include <unistd.h>
#include <ctype.h>
#include <netdb.h>
#include <pwd.h>
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <argp.h>
#include <locale.h>


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

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif

#include <errno.h>
extern int errno;

#include "shishi.h"

#include "gettext.h"
#define _(String) gettext (String)
#define _N(S1, S2, N) ngettext (S1, S2, N)
#define gettext_noop(String) String
#define N_(String) gettext_noop (String)

#define FAMILY_IPV4 "IPv4"
#define FAMILY_IPV6 "IPv6"

#ifdef WITH_IPV6
#define LISTEN_DEFAULT "*:kerberos/udp, *:kerberos/tcp" ", " FAMILY_IPV6 ":*:kerberos/udp, " FAMILY_IPV6 ":*:kerberos/tcp"
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
  int res;
  char *ptrptr;
  char *val;
  int i;

  switch (key)
    {
    case 'q':
      arguments->silent = 1;
      break;

    case 'v':
      arguments->verbose = 1;
      break;

    case 'c':
      arguments->cfgfile = strdup(arg);
      break;

    case ARGP_KEY_END:
      if (arguments->nlistenspec > 0)
	break;
      arg = strdup(LISTEN_DEFAULT);
      /* fall through */

    case 'l':
      for (i = 0; val = strtok_r(i == 0 ? arg : NULL, ", \t", &ptrptr); i++)
	{
	  char *service, *proto;
	  struct servent *se;
	  struct hostent *he;
	  struct listenspec *ls;

	  arguments->nlistenspec++;
	  arguments->listenspec = realloc(arguments->listenspec,
					  sizeof(*arguments->listenspec) * 
					  arguments->nlistenspec);
	  if (arguments->listenspec == NULL)
	    argp_error (state, "Fatal memory allocation error");
	  ls = &arguments->listenspec[arguments->nlistenspec-1];
	  ls->str = strdup(val);

	  proto = strrchr(val, '/');
	  if (proto == NULL)
	    argp_error (state, "Could not find type in listen spec: `%s'", 
			ls->str);
	  *proto = '\0';
	  proto++;

	  service = strrchr(val, ':');
	  if (service == NULL)
	    argp_error (state, "Could not find service in listen spec: `%s'", 
			ls->str);
	  *service = '\0';
	  service++;

	  if (strcmp(proto, "tcp") == 0)
	    ls->type = SOCK_STREAM;
	  else
	    ls->type = SOCK_DGRAM;

	  se = getservbyname(service, proto);
	  if (se)
	      ls->port = ntohs(se->s_port);
	  else if (strcmp(service, "kerberos") == 0)
	    ls->port = 88;
	  else if (atoi(service) != 0)
	    ls->port = atoi(service);
	  else
	    argp_error (state, "Unknown service `%s' in listen spec: `%s'",
			service, ls->str);

#ifdef WITH_IPV6
	  if (ls->family == AF_INET6)
	    ((struct sockaddr_in6*)&ls->addr)->sin6_port = htons(ls->port);
	  else
#endif
	    ((struct sockaddr_in*)&ls->addr)->sin_port = htons(ls->port);

	  if (strncmp(val, FAMILY_IPV4 ":", strlen(FAMILY_IPV4 ":")) == 0)
	    {
	      ls->family = AF_INET;
	      val += strlen(FAMILY_IPV4 ":");
	    }
#ifdef WITH_IPV6
	  else if (strncmp(val, FAMILY_IPV6":", strlen(FAMILY_IPV6 ":")) == 0)
	    {
	      ls->family = AF_INET6;
	      val += strlen(FAMILY_IPV6 ":");
	    }
#endif
	  else
	    ls->family = AF_INET;

	  if (strcmp (val, "*") == 0)
	    {
#ifdef WITH_IPV6
	      if (ls->family == AF_INET6)
		((struct sockaddr_in6*)&ls->addr)->sin6_addr = in6addr_any;
	      else
#endif
		((struct sockaddr_in*)&ls->addr)->sin_addr.s_addr = 
		  htonl(INADDR_ANY);
	    }
	  else if (he = gethostbyname(val))
	    {
	      if (he->h_addrtype == AF_INET)
		{
		  ((struct sockaddr_in*)&ls->addr)->sin_family = AF_INET;
		  memcpy(&((struct sockaddr_in*)&ls->addr)->sin_addr, 
			 he->h_addr_list[0], he->h_length);
		}
#ifdef WITH_IPV6
	      else if (he->h_addrtype == AF_INET6)
		{
		  ((struct sockaddr_in6*)&ls->addr)->sin6_family = AF_INET6;
		  memcpy(&((struct sockaddr_in6*)&ls->addr)->sin6_addr, 
			 he->h_addr_list[0], he->h_length);
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
      argp_error (state, _("Too many arguments: `%s'"), arg);
      break;

    default:
      return ARGP_ERR_UNKNOWN;
    }

  return 0;
}

static struct argp_option options[] = {

  {"verbose", 'v', 0, 0,
   "Produce verbose output.",},

  {"quiet", 'q', 0, 0,
   "Don't produce any output."},

  {"silent", 0, 0, OPTION_ALIAS},

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
  "Shishid -- A Kerberos 5 Key Distribution Center Network Service"
};

void
die(char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  vfprintf (stderr, fmt, ap);
  va_end(ap);
  exit(1);
}

int
doit (struct arguments arg)
{
  int i;
  struct listenspec *ls;
  fd_set readfds;
  struct timeval timeout;
  int maxfd = 0;

  for (i = 0; i < arg.nlistenspec; i++)
    {
      struct listenspec *ls = &arg.listenspec[i];

      printf("%d: %s\n", i, ls->str);

      ls->sockfd = socket(ls->family, ls->type, 0);
      if (ls->sockfd < 0)
	{
	  printf("Cannot create socket\n");
	  ls->sockfd = 0;
	  continue;
	}

      if (bind(ls->sockfd, &ls->addr, sizeof(ls->addr)) != 0)
	{
	  close(ls->sockfd);
	  ls->sockfd = 0;
	  printf("Cannot bind socket\n");
	  continue;
	}
      if (ls->type == SOCK_STREAM)
	{
	  if (listen(ls->sockfd, 512) != 0)
	    {
	      printf("Cannot listen on socket\n");
	    }
	  printf ("accepting connections on port %d\n", ls->port);

	}
      if (ls->sockfd > maxfd)
	maxfd = ls->sockfd + 1;
    }

  do {
    do {
      printf("loop\n");
      FD_ZERO (&readfds);
      for (i = 0; i < arg.nlistenspec; i++)
	FD_SET (arg.listenspec[i].sockfd, &readfds);
      timeout.tv_sec = 5;
      timeout.tv_usec = 0;
    } while(select(maxfd, &readfds, NULL, NULL, &timeout) == 0);

    printf("foo\n");
  } while (1);

  printf("closing\n");
  
  for (i = 0; i < arg.nlistenspec; i++)
    if (arg.listenspec[i].sockfd)
      close(arg.listenspec[i].sockfd);

  printf("done\n");
}

int
main (int argc, char *argv[])
{
  struct arguments arg;
  Shishi *handle;
  int rc;

  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);

  memset ((void *) &arg, 0, sizeof (arg));
  argp_parse (&argp, argc, argv, ARGP_IN_ORDER, 0, &arg);

  handle = shishi_init ();
  if (handle == NULL)
    die("Internal error: could not initialize shishi\n");

  if (arg.cfgfile == NULL)
    arg.cfgfile = SYSTEMCFGFILE;

  rc = shishi_readcfg (handle, arg.cfgfile);
  if (rc != SHISHI_OK && rc != SHISHI_FOPEN_ERROR)
    die("Could not read system config: %s\n", shishi_strerror (rc));

  rc = doit(arg);

  shishi_done (handle);

  return rc;
}
