/* shishid.c --- Shishi Key Distribution Center daemon.
 * Copyright (C) 2002, 2003, 2004, 2005, 2007, 2008  Simon Josefsson
 *
 * This file is part of Shishi.
 *
 * Shishi is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * Shishi is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Shishi; if not, see http://www.gnu.org/licenses or write
 * to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
 * Floor, Boston, MA 02110-1301, USA
 *
 */

/* Get Shishid stuff. */
#include "kdc.h"

/* Gnulib helpers. */
#include "progname.h"
#include "version-etc.h"
#include "error.h"

/* Global variables. */
Shishi *handle;
Shisa *dbh;
struct gengetopt_args_info arg;
struct listenspec *listenspec;
char *fatal_krberror;
size_t fatal_krberror_len;
#ifdef USE_STARTTLS
gnutls_dh_params dh_params;
gnutls_anon_server_credentials anoncred;
gnutls_certificate_credentials x509cred;
#endif

/* Listen to all listenspec's, removing entries that fail. */
static void
kdc_listen (void)
{
  struct listenspec *ls, *tmp;
  int maxfd = 0;
  int yes;

  for (ls = listenspec; ls; ls = ls->next)
    {
      if (!arg.quiet_flag)
	printf ("Listening on %s...\n", ls->str);

      ls->sockfd = socket (ls->family, ls->type, 0);
      if (ls->sockfd < 0)
	{
	  error (0, errno, "Cannot listen on %s because socket failed",
		 ls->str);
	  goto error;
	}

      yes = 1;
      if (setsockopt (ls->sockfd, SOL_SOCKET, SO_REUSEADDR,
		      (char *) &yes, sizeof (yes)) < 0)
	{
	  error (0, errno, "Cannot listen on %s because setsockopt failed",
		 ls->str);
	  goto errorclose;
	}

      if (bind (ls->sockfd, &ls->listenaddr, sizeof (ls->listenaddr)) != 0)
	{
	  error (0, errno, "Cannot listen on %s because bind failed",
		 ls->str);
	  goto errorclose;
	}

      if (ls->type == SOCK_STREAM && listen (ls->sockfd, SOMAXCONN) != 0)
	{
	  error (0, errno, "Cannot listen on %s because listen failed",
		 ls->str);
	  goto errorclose;
	}

      maxfd++;
      continue;

    errorclose:
      close (ls->sockfd);
    error:
      tmp = ls->next;
      if (listenspec == ls)
	listenspec = tmp;
      free (ls->str);
      free (ls);
      ls = tmp;
      if (!ls)
	break;
    }

  if (maxfd == 0)
    error (EXIT_FAILURE, 0, "Failed to bind any ports.");

  if (!arg.quiet_flag)
    printf ("Listening on %d ports...\n", maxfd);
}

/* Close open sockets, reporting any errors. */
static void
kdc_unlisten (void)
{
  struct listenspec *ls;
  int rc;

  for (ls = listenspec; ls; ls = ls->next)
    {
      if (!ls->listening)
	syslog (LOG_NOTICE,
		"Closing outstanding connection to %s on socket %d",
		ls->str, ls->sockfd);

      if (ls->sockfd)
	{
	  if (!arg.quiet_flag)
	    printf ("Closing %s...\n", ls->str);
	  rc = close (ls->sockfd);
	  if (rc != 0)
	    syslog (LOG_ERR, "Could not close %s on socket %d: %s (%d)",
		    ls->str, ls->sockfd, strerror (errno), errno);
	}

      if (ls->str)
	free (ls->str);
    }
}

/* If requested, abandon user privileges. */
static void
kdc_setuid (void)
{
  struct passwd *passwd;
  int rc;

  if (!arg.setuid_given)
    return;

  passwd = getpwnam (arg.setuid_arg);
  if (passwd == NULL)
    {
      if (errno)
	error (EXIT_FAILURE, errno, "Cannot setuid because getpwnam failed");
      else
	error (EXIT_FAILURE, 0, "No such user `%s'.", arg.setuid_arg);
    }

  rc = setuid (passwd->pw_uid);
  if (rc == -1)
    error (EXIT_FAILURE, errno, "Cannot setuid");

  if (!arg.quiet_flag)
    printf ("User identity set to `%s' (%d)...\n",
	    passwd->pw_name, passwd->pw_uid);
}

/* Create a hard coded error message that can be used in case kdc.c
   fail to produce */
static int
setup_fatal_krberror (void)
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

/* Core daemon part.  Initialize and set up various things, and then
   hand over control to kdc.c via kdc_loop, and cleaning up
   afterwards.  Note that kdc_loop only return when the process has
   received SIGINT or SIGTERM. */
static void
doit (void)
{
  int rc;

  rc = shishi_init_server_with_paths (&handle, arg.configuration_file_arg);
  if (rc)
    error (EXIT_FAILURE, 0, "Cannot initialize Shishi: %s (%d)",
	   shishi_strerror (rc), rc);

  if (arg.verbose_given > 1)
    shishi_cfg (handle, "verbose");
  if (arg.verbose_given > 2)
    shishi_cfg (handle, "verbose-noise");
  if (arg.verbose_given > 3)
    shishi_cfg (handle, "verbose-asn1");
  if (arg.verbose_given > 4)
    shishi_cfg (handle, "verbose-crypto");
  if (arg.verbose_given > 5)
    shishi_cfg (handle, "verbose-crypto-noise");

  rc = shisa_init (&dbh);
  if (rc)
    error (EXIT_FAILURE, 0, "Cannot initialize Shisa: %s (%d)",
	   shisa_strerror (rc), rc);

  rc = setup_fatal_krberror ();
  if (rc)
    error (EXIT_FAILURE, 0, "Cannot allocate fatal error packet: %s (%d)",
	   shisa_strerror (rc), rc);

#ifdef USE_STARTTLS
  if (!arg.quiet_flag)
    printf ("Initializing GNUTLS...\n");

  rc = gnutls_global_init ();
  if (rc)
    error (EXIT_FAILURE, 0, "Cannot initialize GNUTLS: %s (%d)",
	   gnutls_strerror (rc), rc);

  rc = gnutls_anon_allocate_server_credentials (&anoncred);
  if (rc)
    error (EXIT_FAILURE, 0, "Cannot allocate GNUTLS credential: %s (%d)",
	   gnutls_strerror (rc), rc);

  rc = gnutls_certificate_allocate_credentials (&x509cred);
  if (rc)
    error (EXIT_FAILURE, 0,
	   "Cannot allocate GNUTLS X.509 credential: %s (%d)",
	   gnutls_strerror (rc), rc);

  if (arg.x509cafile_given)
    {
      int num;
      num = gnutls_certificate_set_x509_trust_file (x509cred,
						    arg.x509cafile_arg,
						    GNUTLS_X509_FMT_PEM);
      if (num <= 0)
	error (EXIT_FAILURE, 0, "No X.509 CAs found in `%s' (%d): %s",
	       arg.x509cafile_arg, num, gnutls_strerror (num));
      if (!arg.quiet_flag)
	printf ("Parsed %d CAs...\n", num);
    }

  if (arg.x509crlfile_given)
    {
      int num;

      num = gnutls_certificate_set_x509_crl_file (x509cred,
						  arg.x509crlfile_arg,
						  GNUTLS_X509_FMT_PEM);
      if (num <= 0)
	error (EXIT_FAILURE, 0, "No X.509 CRLs found in `%s' (%d): %s",
	       arg.x509crlfile_arg, num, gnutls_strerror (num));
      if (!arg.quiet_flag)
	printf ("Parsed %d CRLs...\n", num);
    }

  if (arg.x509certfile_given && arg.x509keyfile_given)
    {
      rc = gnutls_certificate_set_x509_key_file (x509cred,
						 arg.x509certfile_arg,
						 arg.x509keyfile_arg,
						 GNUTLS_X509_FMT_PEM);
      if (rc != GNUTLS_E_SUCCESS)
	error (EXIT_FAILURE, 0,
	       "No X.509 server certificate/key found in `%s'/`%s' (%d): %s",
	       arg.x509certfile_arg, arg.x509keyfile_arg, rc,
	       gnutls_strerror (rc));
      if (!arg.quiet_flag)
	printf ("Loaded server certificate/key...\n");
    }
  else if (arg.x509certfile_given || arg.x509keyfile_given)
    error (EXIT_FAILURE, 0, "Need both --x509certfile and --x509keyfile");

  rc = gnutls_dh_params_init (&dh_params);
  if (rc)
    error (EXIT_FAILURE, 0, "Cannot initialize GNUTLS DH parameters: %s (%d)",
	   gnutls_strerror (rc), rc);

  if (!arg.quiet_flag)
    printf ("Generating Diffie-Hellman parameters...\n");

  rc = gnutls_dh_params_generate2 (dh_params, DH_BITS);
  if (rc)
    error (EXIT_FAILURE, 0, "Cannot generate GNUTLS DH parameters: %s (%d)",
	   gnutls_strerror (rc), rc);

  gnutls_anon_set_server_dh_params (anoncred, dh_params);

  gnutls_certificate_set_dh_params (x509cred, dh_params);

  resume_db_init (arg.resume_limit_arg);

  if (!arg.quiet_flag)
    printf ("Initializing GNUTLS...done\n");
#endif

  kdc_listen ();

  {
    const char *slash = strrchr (program_name, '/');
    const char *shortname = (slash != NULL ? slash + 1 : program_name);

#ifdef LOG_PERROR
    openlog (shortname, LOG_CONS | LOG_PERROR, LOG_DAEMON);
#else
    openlog (shortname, LOG_CONS, LOG_DAEMON);
#endif
  }

  kdc_setuid ();

  kdc_loop ();

  kdc_unlisten ();

#ifdef USE_STARTTLS
  if (!arg.quiet_flag)
    printf ("Deinitializing GNUTLS...\n");

  resume_db_done ();

  gnutls_global_deinit ();

  if (!arg.quiet_flag)
    printf ("Deinitializing GNUTLS...done\n");
#endif

  shisa_done (dbh);
  shishi_done (handle);
}

#define FAMILY_IPV4 "IPv4"
#define FAMILY_IPV6 "IPv6"

#ifdef WITH_IPV6
# define LISTEN_DEFAULT FAMILY_IPV4 ":*:kerberos/udp, " \
  FAMILY_IPV4 ":*:kerberos/tcp, "			\
  FAMILY_IPV6 ":*:kerberos/udp, "			\
  FAMILY_IPV6 ":*:kerberos/tcp"
#else
# define LISTEN_DEFAULT "*:kerberos/udp, *:kerberos/tcp"
#endif

/* Parse the --listen parameter, creating listenspec elements. */
static void
parse_listen (char *listenstr)
{
  char *ptrptr;
  char *val;
  int i;

  for (i = 0; (val = strtok_r (i == 0 ? listenstr : NULL,
			       ", \t", &ptrptr)); i++)
    {
      char *service, *proto;
      struct servent *se;
      struct hostent *he;
      struct listenspec *ls;
      struct sockaddr_in *sockin;
#ifdef WITH_IPV6
      struct sockaddr_in6 *sockin6;
#endif

      ls = xzalloc (sizeof (*ls));
      ls->next = listenspec;
      listenspec = ls;

      ls->str = strdup (val);
      ls->bufpos = 0;
      ls->listening = 1;
      sockin = (struct sockaddr_in *) &ls->listenaddr;
#ifdef WITH_IPV6
      sockin6 = (struct sockaddr_in6 *) &ls->listenaddr;
#endif

      proto = strrchr (val, '/');
      if (proto == NULL)
	error (EXIT_FAILURE, 0, "Could not find type in listen spec: `%s'",
	       ls->str);
      *proto = '\0';
      proto++;

      if (strcmp (proto, "tcp") == 0)
	ls->type = SOCK_STREAM;
      else
	ls->type = SOCK_DGRAM;

      service = strrchr (val, ':');
      if (service == NULL)
	error (EXIT_FAILURE, 0, "Could not find service in listen spec: `%s'",
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
	error (EXIT_FAILURE, 0, "Unknown service `%s' in listen spec: `%s'",
	       service, ls->str);

#ifdef WITH_IPV6
      if (ls->family == AF_INET6)
	sockin6->sin6_port = htons (ls->port);
      else
#endif
	sockin->sin_port = htons (ls->port);

      if (strncmp (val, FAMILY_IPV4 ":", strlen (FAMILY_IPV4 ":")) == 0)
	{
	  ls->family = AF_INET;
	  val += strlen (FAMILY_IPV4 ":");
	}
#ifdef WITH_IPV6
      else if (strncmp (val, FAMILY_IPV6 ":", strlen (FAMILY_IPV6 ":")) == 0)
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
	    sockin6->sin6_addr = in6addr_any;
	  else
#endif
	    sockin->sin_addr.s_addr = htonl (INADDR_ANY);
	}
      else if ((he = gethostbyname (val)))
	{
	  if (he->h_addrtype == AF_INET)
	    {
	      sockin->sin_family = AF_INET;
	      memcpy (&sockin->sin_addr, he->h_addr_list[0], he->h_length);
	    }
#ifdef WITH_IPV6
	  else if (he->h_addrtype == AF_INET6)
	    {
	      sockin6->sin6_family = AF_INET6;
	      memcpy (&sockin6->sin6_addr, he->h_addr_list[0], he->h_length);
	    }
#endif
	  else
	    error (EXIT_FAILURE, 0, "Unknown protocol family (%d) returned "
		   "by gethostbyname(\"%s\"): `%s'", he->h_addrtype,
		   val, ls->str);
	}
      else
	error (EXIT_FAILURE, 0, "Unknown host `%s' in listen spec: `%s'",
	       val, ls->str);
    }
}

const char version_etc_copyright[] =
  /* Do *not* mark this string for translation.  %s is a copyright
     symbol suitable for this locale, and %d is the copyright
     year.  */
  "Copyright %s %d Simon Josefsson.";

static void
usage (int status) __attribute__ ((__noreturn__));

static void
usage (int status)
{
  if (status != EXIT_SUCCESS)
    fprintf (stderr, _("Try `%s --help' for more information.\n"),
	     program_name);
  else
    {
      cmdline_parser_print_help ();
      /* TRANSLATORS: The placeholder indicates the bug-reporting address
	 for this package.  Please add _another line_ saying
	 "Report translation bugs to <...>\n" with the address for translation
	 bugs (typically your translation team's web or email address).  */
      printf (_("\nMandatory arguments to long options are "
		"mandatory for short options too.\n\nReport bugs to <%s>.\n"),
	      PACKAGE_BUGREPORT);
    }
  exit (status);
}

int
main (int argc, char *argv[])
{
  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);
  set_program_name (argv[0]);

  if (cmdline_parser (argc, argv, &arg) != 0)
    usage (EXIT_FAILURE);

  if (arg.version_given)
    {
      version_etc (stdout, "shishid", PACKAGE_NAME, VERSION,
		   "Simon Josefsson", (char *) NULL);
      return EXIT_SUCCESS;
    }

  if (arg.help_given)
    usage (EXIT_SUCCESS);

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
