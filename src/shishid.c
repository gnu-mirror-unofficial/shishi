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
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#if defined HAVE_DECL_H_ERRNO && !HAVE_DECL_H_ERRNO
/* extern int h_errno; */
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

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#ifdef USE_STARTTLS
#include <gnutls/gnutls.h>
#endif

#ifdef HAVE_LOCALE_H
# include <locale.h>
#else
# define setlocale(Category, Locale) /* empty */
#endif

#include <gettext.h>
#define _(String) gettext (String)
#define gettext_noop(String) String
#define N_(String) gettext_noop (String)

#include "xalloc.h"
#include "progname.h"

#include <shishi.h>
#include <shisa.h>

#include "shishid_cmd.h"

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

#define DH_BITS 1024
#ifdef USE_STARTTLS
static gnutls_dh_params dh_params;
#endif

static char *fatal_krberror;
static size_t fatal_krberror_len;

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

Shishi * handle;
Shisa * dbh;
struct gengetopt_args_info arg;
struct listenspec *listenspec;
int nlistenspec;

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

      nlistenspec++;
      listenspec = xrealloc (listenspec, sizeof (*listenspec) * nlistenspec);
      ls = &listenspec[nlistenspec - 1];
      memset (ls, 0, sizeof (*ls));
      ls->str = strdup (val);
      ls->bufpos = 0;
      sin = (struct sockaddr_in *) &ls->addr;
#ifdef WITH_IPV6
      sin6 = (struct sockaddr_in6 *) &ls->addr;
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

static int
asreq1 (Shishi_as * as)
{
  Shishi_tkt *tkt;
  Shishi_key *sessionkey, *userkey;
  int etype, i;
  int err;
  char *username, *servername, *realm;
  Shisa_principal krbtgt;
  Shisa_principal user;

  err = shishi_kdcreq_server (handle, shishi_as_req (as), &servername, NULL);
  if (err != SHISHI_OK)
    return err;
  printf ("servername %s\n", servername);

  err = shishi_kdcreq_realm (handle, shishi_as_req (as), &realm, NULL);
  if (err != SHISHI_OK)
    return err;
  printf ("client & server realm %s\n", realm);

  err = shisa_principal_find (dbh, realm, servername, &krbtgt);
  if (err != SHISA_OK)
    {
      printf ("server %s@%s not found\n", servername, realm);
      return SHISHI_INVALID_PRINCIPAL_NAME;
    }

  err = shishi_kdcreq_client (handle, shishi_as_req (as), &username, NULL);
  if (err != SHISHI_OK)
    return err;
  printf ("username %s\n", username);

  err = shisa_principal_find (dbh, realm, username, &user);
  if (err != SHISA_OK)
    {
      printf ("user %s@%s not found\n", username, realm);
      return SHISHI_INVALID_PRINCIPAL_NAME;
    }

  tkt = shishi_as_tkt (as);
  if (!tkt)
    return SHISHI_MALLOC_ERROR;

  i = 1;
  do
    {
      err = shishi_kdcreq_etype (handle, shishi_as_req (as), &etype, i);
      if (err == SHISHI_OK && shishi_cipher_supported_p (etype))
	break;
    }
  while (err == SHISHI_OK);
  if (err != SHISHI_OK)
    return err;

  /* XXX use a "preferred server kdc etype" from shishi instead? */

  err = shishi_key_random (handle, etype, &sessionkey);
  if (err)
    return err;

  err = shishi_tkt_key_set (tkt, sessionkey);
  if (err)
    return err;

  err = shishi_tkt_clientrealm_set (tkt, realm, username);
  if (err)
    return err;

  err = shishi_tkt_serverrealm_set (tkt, realm, servername);
  if (err)
    return err;

#if 0
  userkey = shishi_keys_for_serverrealm_in_file (handle,
						 arg.keyfile,
						 username, realm);
  if (!userkey)
    return !SHISHI_OK;

  err = shishi_tkt_build (tkt, arg.tgskey);
  if (err)
    return err;
#endif

  err = shishi_as_rep_build (as, userkey);
  if (err)
    return err;

  if (arg.verbose_flag)
    {
      shishi_kdcreq_print (handle, stderr, shishi_as_req (as));
      shishi_encticketpart_print (handle, stderr,
				  shishi_tkt_encticketpart (tkt));
      shishi_ticket_print (handle, stderr, shishi_tkt_ticket (tkt));
      shishi_enckdcreppart_print (handle, stderr,
				  shishi_tkt_enckdcreppart (tkt));
      shishi_kdcrep_print (handle, stderr, shishi_as_rep (as));
    }

  return SHISHI_OK;
}

static int
asreq (Shishi_asn1 kdcreq, char **out, size_t * outlen)
{
  Shishi_as *as;
  int rc;

  rc = shishi_as (handle, &as);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR, "Incoming request failed: Cannot create AS: %s\n",
	      shishi_strerror (rc));
      /* XXX hard coded KRB-ERROR? */
      *out = strdup ("foo");
      *outlen = strlen (*out);
      return rc;
    }

  shishi_as_req_set (as, kdcreq);

  rc = asreq1 (as);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_NOTICE, "Could not answer request: %s: %s\n",
	      shishi_strerror (rc),
	      shishi_krberror_message (handle, shishi_as_krberror (as)));
      rc = shishi_as_krberror_der (as, out, outlen);
    }
  else
    rc = shishi_as_rep_der (as, out, outlen);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR,
	      "Incoming request failed: Cannot DER encode reply: %s\n",
	      shishi_strerror (rc));
      /* XXX hard coded KRB-ERROR? */
      *out = strdup ("aaaaaa");
      *outlen = strlen (*out);
      return rc;
    }

  return SHISHI_OK;
}

static int
tgsreq1 (Shishi_tgs * tgs)
{
  int rc;
  Shishi_tkt *tkt;
  Shishi_key *sessionkey, *sessiontktkey, *serverkey, *subkey, *keytouse;
  char buf[BUFSIZ];
  int buflen;
  int err;
  char *username, *servername, *realm;
  int32_t etype, keyusage;
  int i;

  buflen = sizeof (buf) - 1;
  err = shishi_encticketpart_cname_get
    (handle, shishi_tkt_encticketpart (shishi_ap_tkt (shishi_tgs_ap (tgs))),
     buf, &buflen);
  if (err != SHISHI_OK)
    return err;
  buf[buflen] = '\0';
  username = strdup (buf);
  printf ("username %s\n", username);

  buflen = sizeof (buf) - 1;
  err = shishi_kdcreq_sname_get (handle, shishi_tgs_req (tgs), buf, &buflen);
  if (err != SHISHI_OK)
    return err;
  buf[buflen] = '\0';
  servername = strdup (buf);
  printf ("servername %s\n", servername);

  buflen = sizeof (buf) - 1;
  err = shishi_kdcreq_realm_get (handle, shishi_tgs_req (tgs), buf, &buflen);
  if (err != SHISHI_OK)
    return err;
  buf[buflen] = '\0';
  realm = strdup (buf);
  printf ("server realm %s\n", realm);

  tkt = shishi_tgs_tkt (tgs);
  if (!tkt)
    return SHISHI_MALLOC_ERROR;

  i = 1;
  do
    {
      err = shishi_kdcreq_etype (handle, shishi_tgs_req (tgs), &etype, i);
      if (err == SHISHI_OK && shishi_cipher_supported_p (etype))
	break;
    }
  while (err == SHISHI_OK);
  if (err != SHISHI_OK)
    return err;

  /* XXX use a "preferred server kdc etype" from shishi instead? */

  err = shishi_key_random (handle, etype, &sessionkey);
  if (err)
    return err;

  err = shishi_tkt_key_set (tkt, sessionkey);
  if (err)
    return err;

  /* extract pa-data and populate tgs->ap */
  rc = shishi_tgs_req_process (tgs);
  if (rc != SHISHI_OK)
    return rc;

  /* XXX check if ticket is for our tgt key */

#if 0
  /* decrypt ticket with our key, and decrypt authenticator using key in tkt */
  rc = shishi_ap_req_process_keyusage
    (shishi_tgs_ap (tgs), arg.tgskey,
     SHISHI_KEYUSAGE_TGSREQ_APREQ_AUTHENTICATOR);
  if (rc != SHISHI_OK)
    return rc;
#endif

  /* XXX check that checksum in authenticator match tgsreq.req-body */

  err = shishi_tkt_clientrealm_set (tkt, realm, username);
  if (err)
    return err;

  err = shishi_tkt_serverrealm_set (tkt, realm, servername);
  if (err)
    return err;
#if 0
  serverkey = shishi_keys_for_serverrealm_in_file (handle,
						   arg.keyfile,
						   servername, realm);
  if (!serverkey)
    return !SHISHI_OK;
#endif
  err = shishi_tkt_build (tkt, serverkey);
  if (err)
    return err;

  err = shishi_encticketpart_get_key
    (handle,
     shishi_tkt_encticketpart (shishi_ap_tkt (shishi_tgs_ap (tgs))),
     &sessiontktkey);

  err = shishi_authenticator_get_subkey
    (handle, shishi_ap_authenticator (shishi_tgs_ap (tgs)), &subkey);
  if (err != SHISHI_OK && err != SHISHI_ASN1_NO_ELEMENT)
    return err;

  if (err == SHISHI_OK)
    {
      keyusage = SHISHI_KEYUSAGE_ENCTGSREPPART_AUTHENTICATOR_KEY;
      keytouse = subkey;
    }
  else
    {
      keyusage = SHISHI_KEYUSAGE_ENCTGSREPPART_SESSION_KEY;
      keytouse = sessiontktkey;
    }

  err = shishi_tgs_rep_build (tgs, keyusage, keytouse);
  if (err)
    return err;

  if (arg.verbose_flag)
    {
      puts ("KDC-REQ in:");
      shishi_kdcreq_print (handle, stderr, shishi_tgs_req (tgs));
      puts ("AP-REQ in KDC-REQ:");
      shishi_apreq_print (handle, stderr,
			  shishi_ap_req (shishi_tgs_ap (tgs)));
      puts ("Authenticator in AP-REQ in KDC-REQ:");
      shishi_authenticator_print (handle, stderr, shishi_ap_authenticator
				  (shishi_tgs_ap (tgs)));
      puts ("Ticket in AP-REQ:");
      shishi_ticket_print (handle, stdout,
			   shishi_tkt_ticket
			   (shishi_ap_tkt (shishi_tgs_ap (tgs))));
      puts ("EncTicketPart in AP-REQ:");
      shishi_encticketpart_print (handle, stdout,
				  shishi_tkt_encticketpart
				  (shishi_ap_tkt (shishi_tgs_ap (tgs))));
      puts ("Ticket in TGS-REP:");
      shishi_ticket_print (handle, stdout, shishi_tkt_ticket (tkt));
      puts ("EncTicketPart in TGS-REP:");
      shishi_encticketpart_print (handle, stderr,
				  shishi_tkt_encticketpart (tkt));
      puts ("EncKDCRepPart in TGS-REP:");
      shishi_enckdcreppart_print (handle, stderr,
				  shishi_tkt_enckdcreppart (tkt));
      puts ("KDC-REP:");
      shishi_kdcrep_print (handle, stderr, shishi_tgs_rep (tgs));
    }

  return SHISHI_OK;
}

static int
tgsreq (Shishi_asn1 kdcreq, char **out, size_t * outlen)
{
  Shishi_tgs *tgs;
  int rc;

  rc = shishi_tgs (handle, &tgs);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR, "Incoming request failed: Cannot create TGS: %s\n",
	      shishi_strerror (rc));
      /* XXX hard coded KRB-ERROR? */
      *out = strdup ("foo");
      *outlen = strlen (*out);
      return rc;
    }

  shishi_tgs_req_set (tgs, kdcreq);

  rc = tgsreq1 (tgs);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_NOTICE, "Could not answer request: %s: %s\n",
	      shishi_strerror (rc),
	      shishi_krberror_message (handle, shishi_tgs_krberror (tgs)));
      rc = shishi_tgs_krberror_der (tgs, out, outlen);
    }
  else
    rc = shishi_tgs_rep_der (tgs, out, outlen);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR,
	      "Incoming request failed: Cannot DER encode reply: %s\n",
	      shishi_strerror (rc));
      /* XXX hard coded KRB-ERROR? */
      *out = strdup ("aaaaaa");
      *outlen = strlen (*out);
      return rc;
    }

  return SHISHI_OK;
}

static int
process_1 (char *in, size_t inlen, char **out, size_t * outlen)
{
  Shishi_asn1 node;
  Shishi_asn1 krberr;
  int rc;

  krberr = shishi_krberror (handle);
  if (!krberr)
    return SHISHI_MALLOC_ERROR;

  node = shishi_der2asn1 (handle, in, inlen);

  fprintf (stderr, "ASN.1 msg-type %d (0x%x)...\n",
	   shishi_asn1_msgtype (handle, node),
	   shishi_asn1_msgtype (handle, node));

  switch (shishi_asn1_msgtype (handle, node))
    {
    case SHISHI_MSGTYPE_AS_REQ:
      rc = asreq (node, out, outlen);
      break;

    case SHISHI_MSGTYPE_TGS_REQ:
      rc = tgsreq (node, out, outlen);
      break;

    default:
      rc = !SHISHI_OK;
      break;
    }

  if (rc != SHISHI_OK)
    {
      rc = shishi_krberror_set_etext (handle, krberr, "General error");
      if (rc != SHISHI_OK)
	return rc;

      rc = shishi_krberror_der (handle, krberr, out, outlen);
      if (rc != SHISHI_OK)
	return rc;
    }

  return SHISHI_OK;
}

static void
process (char *in, int inlen, char **out, size_t * outlen)
{
  int rc;

  *out = NULL;
  *outlen = 0;

  rc = process_1 (in, inlen, out, outlen);

  if (rc != SHISHI_OK || *out == NULL || *outlen == 0)
    {
      *out = fatal_krberror;
      *outlen = fatal_krberror_len;
    }
}

int quit = 0;

static void
ctrlc (int signum)
{
  quit = 1;
}

static int
kdc_listen ()
{
  struct listenspec *ls;
  int maxfd = 0;
  int i;
  int yes;

  for (i = 0; i < nlistenspec; i++)
    {
      ls = &listenspec[i];

      if (!arg.quiet_flag)
	printf ("Listening on %s...", ls->str);

      ls->sockfd = socket (ls->family, ls->type, 0);
      if (ls->sockfd < 0)
	{
	  if (!arg.quiet_flag)
	    printf ("failed\n");
	  perror ("socket");
	  ls->sockfd = 0;
	  continue;
	}

      yes = 1;
      if (setsockopt (ls->sockfd, SOL_SOCKET, SO_REUSEADDR,
		      (char *) &yes, sizeof (yes)) < 0)
	{
	  if (!arg.quiet_flag)
	    printf ("failed\n");
	  perror ("setsockopt");
	  close (ls->sockfd);
	  ls->sockfd = 0;
	  continue;
	}

      if (bind (ls->sockfd, &ls->addr, sizeof (ls->addr)) != 0)
	{
	  if (!arg.quiet_flag)
	    printf ("failed\n");
	  perror ("bind");
	  close (ls->sockfd);
	  ls->sockfd = 0;
	  continue;
	}

      if (ls->type == SOCK_STREAM && listen (ls->sockfd, 512) != 0)
	{
	  if (!arg.quiet_flag)
	    printf ("failed\n");
	  perror ("listen");
	  close (ls->sockfd);
	  ls->sockfd = 0;
	  continue;
	}

      maxfd++;
      if (!arg.quiet_flag)
	printf ("done\n");
    }

  if (maxfd == 0)
    {
      fprintf (stderr, "Failed to bind any ports.\n");
      return 1;
    }

  if (!arg.quiet_flag)
    printf ("Listening on %d ports...\n", maxfd);

  return 0;
}

static int
kdc_loop (void)
{
  struct listenspec *ls;
  fd_set readfds;
  struct sockaddr addr;
  socklen_t length = sizeof (addr);
  int maxfd = 0;
  int rc;
  int i;
  ssize_t sent_bytes, read_bytes;

  while (!quit)
    {
      do
	{
	  FD_ZERO (&readfds);
	  maxfd = 0;
	  for (i = 0; i < nlistenspec; i++)
	    {
	      if (listenspec[i].sockfd >= maxfd)
		maxfd = listenspec[i].sockfd + 1;
	      FD_SET (listenspec[i].sockfd, &readfds);
	    }
	}
      while ((rc = select (maxfd, &readfds, NULL, NULL, NULL)) == 0);

      if (rc < 0)
	{
	  if (errno != EINTR)
	    perror ("select");
	  continue;
	}

      for (i = 0; i < nlistenspec; i++)
	if (FD_ISSET (listenspec[i].sockfd, &readfds))
	  {
	    if (listenspec[i].type == SOCK_STREAM &&
		listenspec[i].family != -1)
	      {
		struct sockaddr_in *sin;
		char *str;

		fprintf (stderr, "New connection on %s...",
			 listenspec[i].str);

		/* XXX search for closed fd's before allocating new entry */
		listenspec = xrealloc (listenspec, sizeof (*listenspec) *
				       (nlistenspec + 1));

		nlistenspec++;
		ls = &listenspec[nlistenspec - 1];
		ls->bufpos = 0;
		ls->type = listenspec[i].type;
		ls->family = -1;
		length = sizeof (ls->addr);
		ls->sockfd = accept (listenspec[i].sockfd, &ls->addr, &length);
		sin = (struct sockaddr_in *) &ls->addr;
		str = inet_ntoa (sin->sin_addr);
		ls->str = xmalloc (strlen (listenspec[i].str) +
				   strlen (" peer ") + strlen (str) + 1);
		sprintf (ls->str, "%s peer %s", listenspec[i].str,
			 str);
		puts (ls->str);
	      }
	    else
	      {
		ls = &listenspec[i];

		read_bytes = recvfrom (ls->sockfd, ls->buf + ls->bufpos,
				       BUFSIZ - ls->bufpos, 0, &addr,
				       &length);

		if (listenspec[i].type == SOCK_STREAM &&
		    listenspec[i].family == -1 && read_bytes == 0)
		  {
		    printf ("Peer %s disconnected\n", ls->str);
		    close (ls->sockfd);
		    ls->sockfd = 0;
		  }
		else if (read_bytes > 0)
		  {
		    ls->bufpos += read_bytes;
		    ls->buf[ls->bufpos] = '\0';
		  }

		printf ("Has %d bytes from %s\n", ls->bufpos, ls->str);

#ifdef USE_STARTTLS
		if (listenspec[i].type == SOCK_STREAM &&
		    ls->bufpos == 4 &&
		    memcmp (ls->buf, "\x70\x00\x00\x01", 4) == 0)
		  {
		    int err, i;
		    int ret;
		    struct sockaddr_in sa_serv;
		    struct sockaddr_in sa_cli;
		    int client_len;
		    char topbuf[512];
		    gnutls_session session;
		    char buffer[BUFSIZ + 1];
		    int optval = 1;
		    const int kx_prio[] = { GNUTLS_KX_ANON_DH, 0 };
		    gnutls_anon_server_credentials anoncred;

		    if (!arg.quiet_flag)
		      printf ("Trying to upgrade to TLS...\n");

		    sent_bytes = sendto (ls->sockfd, "\x70\x00\x00\x02", 4,
					 0, &addr, length);

		    gnutls_anon_allocate_server_credentials (&anoncred);
		    gnutls_anon_set_server_dh_params (anoncred, dh_params);
		    gnutls_init (&session, GNUTLS_SERVER);
		    gnutls_set_default_priority (session);
		    gnutls_kx_set_priority (session, kx_prio);
		    gnutls_credentials_set (session, GNUTLS_CRD_ANON,
					    anoncred);
		    gnutls_certificate_server_set_request (session,
							   GNUTLS_CERT_REQUEST);
		    gnutls_dh_set_prime_bits (session, DH_BITS);
		    gnutls_transport_set_ptr (session,
					      (gnutls_transport_ptr) ls->
					      sockfd);

		    ret = gnutls_handshake (session);
		    if (ret < 0)
		      {
			gnutls_deinit (session);
			if (!arg.quiet_flag)
			  printf ("Handshake has failed %d: %s\n",
				  ret, gnutls_strerror (ret));
		      }

		    if (!arg.quiet_flag)
		      printf ("TLS successful\n");

		    bzero (buffer, BUFSIZ + 1);
		    ret = gnutls_record_recv (session, buffer, BUFSIZ);

		    if (ret == 0)
		      {
			printf ("- Peer has closed the GNUTLS connection\n");
		      }
		    else if (ret < 0)
		      {
			printf ("*** Corrupted data(%d). Closing.\n\n", ret);
		      }
		    else if (ret > 0)
		      {
			char *p;
			size_t plen;

			process (buffer, ret, &p, &plen);

			printf ("TLS process %d sending %d\n", ret, plen);

			gnutls_record_send (session, p, plen);

			if (p != fatal_krberror)
			  free (p);
		      }
		    ls->bufpos = 0;
		    gnutls_bye (session, GNUTLS_SHUT_WR);
		    gnutls_deinit (session);
		    gnutls_global_deinit ();
		  }
		else
#endif
		if (listenspec[i].type == SOCK_DGRAM ||
		      (ls->bufpos > 4 &&
			 ntohl (*(int *) ls->buf) + 4 == ls->bufpos))
		  {
		    char *p;
		    size_t plen;

		    if (listenspec[i].type == SOCK_STREAM)
		      process (ls->buf + 4, ls->bufpos - 4, &p, &plen);
		    else
		      process (ls->buf, ls->bufpos, &p, &plen);

		    if (p && plen > 0)
		      {
			do
			  sent_bytes = sendto (ls->sockfd, p, plen,
					       0, &addr, length);
			while (sent_bytes == -1 && errno == EAGAIN);

			if (sent_bytes < 0)
			  perror ("write");
			else if ((size_t) sent_bytes > plen)
			  fprintf (stderr, "wrote %db but buffer only %db",
				   sent_bytes, plen);
			else if ((size_t) sent_bytes < plen)
			  fprintf (stderr,
				   "short write (%db) writing %d bytes\n",
				   sent_bytes, plen);

			if (p != fatal_krberror)
			  free (p);
		      }

		    ls->bufpos = 0;
		  }
	      }
	  }
    }

  return 0;
}

static int
kdc_setuid (void)
{
  struct passwd *passwd;
  int rc;

  if (!arg.setuid_given)
    return 0;

  passwd = getpwnam (arg.setuid_arg);
  if (passwd == NULL)
    {
      perror ("setuid: getpwnam");
      return 1;
    }

  rc = setuid (passwd->pw_uid);
  if (rc == -1)
    {
      perror ("setuid");
      return 1;
    }

  if (!arg.quiet_flag)
    printf ("User identity set to `%s' (%d)...\n",
	    passwd->pw_name, passwd->pw_uid);

  return 0;
}

static void
kdc_unlisten (void)
{
  int i;
  int rc;

  for (i = 0; i < nlistenspec; i++)
    if (listenspec[i].sockfd)
      {
	if (!arg.quiet_flag)
	  printf ("Closing %s...", listenspec[i].str);
	rc = close (listenspec[i].sockfd);
	if (rc != 0)
	  {
	    if (!arg.quiet_flag)
	      printf ("failed\n");
	    perror ("close");
	  }
	else if (!arg.quiet_flag)
	  printf ("done\n");
      }
}

static int
launch (void)
{
  int rc;

  rc = kdc_listen ();
  if (rc != 0)
    return rc;

  rc = kdc_setuid ();
  if (rc != 0)
    return rc;

  signal (SIGINT, ctrlc);
  signal (SIGTERM, ctrlc);

  rc = kdc_loop ();
  if (rc != 0)
    return rc;

  kdc_unlisten ();

  return 0;
}

static int
setup (void)
{
  int rc;

  rc = setup_fatal_krberror (handle);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR, "Cannot allocate fatal error message\n");
      return 1;
    }

  rc = launch ();

  return rc;
}

static int
init (void)
{
  int rc;

#ifdef USE_STARTTLS
  if (!arg.quiet_flag)
    printf ("Initializing GNUTLS...\n");
  fflush (stdout);
  gnutls_global_init ();
  gnutls_dh_params_init (&dh_params);
  if (!arg.quiet_flag)
    printf ("Initializing GNUTLS...done\n");
  fflush (stdout);
#endif

  rc = shishi_init_server_with_paths (&handle, arg.configuration_file_arg);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR, "Aborting due to library initialization failure\n");
      return 1;
    }

  if (arg.verbose_flag > 1)
    shishi_cfg (handle, "verbose");

  if (arg.verbose_flag > 2)
    shishi_cfg (handle, "verbose-noice");

  if (arg.verbose_flag > 3)
    shishi_cfg (handle, "verbose-asn1");

  if (arg.verbose_flag > 4)
    shishi_cfg (handle, "verbose-crypto");

  rc = shisa_init (&dbh);
  if (rc != SHISA_OK)
    {
      syslog (LOG_ERR, "Aborting due to Shisa initialization failure\n");
      return 1;
    }

  rc = setup ();

  shisa_done (dbh);
  shishi_done (handle);

  return rc;
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
    {
      error (1, 0, "Try `%s --help' for more information.", argv[0]);
      return 1;
    }

  if (arg.help_given)
    {
      cmdline_parser_print_help ();
      printf ("\nMandatory arguments to long options are "
	      "mandatory for short options too.\n\n");
      printf ("Report bugs to <%s>.\n", PACKAGE_BUGREPORT);
      return 1;
    }

#ifdef LOG_PERROR
  openlog (PACKAGE, LOG_CONS | LOG_PERROR, LOG_DAEMON);
#else
  openlog (PACKAGE, LOG_CONS, LOG_DAEMON);
#endif

  if (!arg.configuration_file_arg)
    arg.configuration_file_arg = strdup (SYSTEMCFGFILE);
  if (!arg.listen_given)
    arg.listen_arg = strdup (LISTEN_DEFAULT);
  parse_listen (arg.listen_arg);

  rc = init ();

  free (arg.listen_arg);
  free (arg.configuration_file_arg);
  if (arg.setuid_arg)
    free (arg.setuid_arg);

  closelog ();

  return rc;
}
