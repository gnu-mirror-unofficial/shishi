/*
    rsh.c - remote shell client
    Copyright (C) 2003  Guus Sliepen <guus@sliepen.eu.org>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as published
	by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
*/

#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#ifdef SHISHI

#include <shishi.h>
#include <stdlib.h>

#define SERVICE "host"
#define AUTH_OK 0

#endif

#define BUFLEN 0x10000

char *argv0;

#ifdef SHISHI

void
usage (void)
{
  fprintf (stderr,
	   "Usage: %s [-46vsx] [-l user] [-p port] [user@]host command...\n",
	   argv0);
}

#else

void
usage (void)
{
  fprintf (stderr,
	   "Usage: %s [-46v] [-l user] [-p port] [user@]host command...\n",
	   argv0);
}

#endif

/* Make sure everything gets written */

ssize_t
safewrite (int fd, const void *buf, size_t count)
{
  int written = 0, result;

  while (count)
    {
      result = write (fd, buf, count);
      if (result == -1)
	{
	  if (errno == EINTR)
	    continue;
	  else
	    return result;
	}
      written += result;
      buf += result;
      count -= result;
    }

  return written;
}

/* Safe and fast string building */

void
safecpy (char **dest, int *len, char *source, bool terminate)
{
  while (*source && *len)
    {
      *(*dest)++ = *source++;
      (*len)--;
    }

  if (terminate && *len)
    {
      *(*dest)++ = 0;
      (*len)--;
    }
}

#ifdef SHISHI

/* read encrypted data on socket */
int
readenc (Shishi * h, int sock, char *buf, int *len, char *iv, int *ivlen,
	 Shishi_key * enckey)
{
  char *out;
  char *outbis;
  char *iv2;

  int rc;
  int val;
  int outlen;
  int dlen = 0, blocksize, enctype, hashsize;

  /* read size of message */
  read (sock, &dlen, sizeof (int));

  dlen = ntohl (dlen);
  /* if 0 put read size to 0 */
  if (!dlen)
    {
      *len = dlen;
      return SHISHI_OK;
    }

  /* convert size to encryption size */
  enctype = shishi_key_type (enckey);

  blocksize = shishi_cipher_blocksize (enctype);
  hashsize =
    shishi_checksum_cksumlen (shishi_cipher_defaultcksumtype (enctype));

  dlen += blocksize - 1 + 4;
  if (shishi_key_type (enckey) != SHISHI_DES3_CBC_HMAC_SHA1_KD)
    dlen += hashsize;
  else
    dlen += blocksize;

  dlen /= blocksize;
  dlen *= blocksize;

  if (shishi_key_type (enckey) == SHISHI_DES3_CBC_HMAC_SHA1_KD)
    dlen += hashsize;

  /* read encrypted data */
  outbis = malloc (dlen);
  if (outbis == NULL)
    {
      printf ("Malloc error!\n");
      return 1;
    }

  rc = read (sock, outbis, dlen);
  if (rc != dlen)
    {
      printf ("Error during read socket\n");
      return 1;
    }

  /* decrypt it */
  rc =
    shishi_decrypt_ivupdate (h, enckey, 1026, iv, *ivlen, &iv2, ivlen, outbis,
			     dlen, &out, &outlen);
  if (rc != SHISHI_OK)
    {
      printf ("decryption error\n");
      return 1;
    }

  /* len = first 4 bytes of decrypted data */
  *len = ntohl (*((int *) out));

  /* update iv */
  memcpy (iv, iv2, *ivlen);

  /* Temp patch to remove 5 unidentified bytes data from server */
  memset (buf, 0, BUFLEN);
  if ((unsigned char) out[4] == 255)
    val = 5 + sizeof (int);
  else
    val = sizeof (int);

  /* copy decrypted data to output */
  memcpy (buf, out + val, strlen (out + val));


  free (out);
  free (outbis);

  return SHISHI_OK;
}

/* write encrypted data to socket */
int
writeenc (Shishi * h, int sock, char *buf, int wlen, int *len, char *iv,
	  int *ivlen, Shishi_key * enckey)
{
  char *out;
  char *bufbis;

  char *iv2;

  int rc;
  int dlen, outlen;

  dlen = wlen;
  dlen = htonl (dlen);

  /* data to encrypt = size + data */
  bufbis = malloc (wlen + sizeof (int));
  memcpy (bufbis, (char *) &dlen, sizeof (int));
  memcpy (bufbis + sizeof (int), buf, wlen);

  /* encrypt it */
  rc =
    shishi_encrypt_ivupdate (h, enckey, 1026, iv, *ivlen, &iv2, ivlen, bufbis,
			     wlen + sizeof (int), &out, &outlen);
  if (rc != SHISHI_OK)
    {
      printf ("decryption error\n");
      return 1;
    }

  free (bufbis);

  /* data to send = original size + encrypted data */
  bufbis = malloc (outlen + sizeof (int));
  if (bufbis == NULL)
    {
      printf ("Malloc error!\n");
      return 1;
    }
  memcpy (bufbis, (char *) &dlen, sizeof (int));
  memcpy (bufbis + sizeof (int), out, outlen);

  /* send it */
  write (sock, bufbis, outlen + sizeof (int));
  *len = wlen;

  /* update iv */
  memcpy (iv, iv2, *ivlen);

  free (bufbis);
  free (out);

  return SHISHI_OK;


}

/* shishi authentication */
int
auth (Shishi * h, int verbose, const char *cname, const char *sname, int sock,
      char *cmd, char *port, Shishi_key ** enckey, Shishi_key * deckey)
{
  Shishi_ap *ap;
  Shishi_tkt *tkt;
  Shishi_tkts_hint hint;

  int rc;
  char *out;
  int outlen;
  int krb5len, msglen;
  char auth;
  /* KERBEROS 5 SENDAUTH MESSAGE */
  char krb5sendauth[] = "KRB5_SENDAUTH_V1.0";
  /* PROTOCOL VERSION */
  char krb5sendclient[] = "KCMDV0.2";
  /* to store error msg sent by server */
  char errormsg[101];
  char cksumdata[101];

  /* size of KRB5 auth message */
  krb5len = strlen (krb5sendauth) + 1;
  msglen = htonl (krb5len);
  safewrite (sock, &msglen, sizeof (int));
  /* KRB5 authentication message */
  safewrite (sock, krb5sendauth, krb5len);
  /* size of client message */
  krb5len = strlen (krb5sendclient) + 1;
  msglen = htonl (krb5len);
  safewrite (sock, &msglen, sizeof (int));
  /* KRB5 client message */
  safewrite (sock, krb5sendclient, krb5len);

  /* get answer from server 0 = ok, 1 = error with message */
  read (sock, &auth, 1);
  if (auth)
    {
      read (sock, errormsg, 100);
      errormsg[100] = '\0';

      printf ("Error during server authentication : %s\n", errormsg);
      return 1;
    }

  if (verbose)
    {
      printf ("Client: %s\n", cname);
      printf ("Server: %s\n", sname);
    }

  /* Get a ticket for the server. */

  memset (&hint, 0, sizeof (hint));

  hint.client = (char *) cname;
  hint.server = (char *) sname;

  tkt = shishi_tkts_get (shishi_tkts_default (h), &hint);
  if (!tkt)
    {
      printf ("cannot find ticket for \"%s\"\n", sname);
      return 1;
    }

  if (verbose)
    shishi_tkt_pretty_print (tkt, stderr);

  /* Create Authentication context */

  rc = shishi_ap_tktoptions (h, &ap, tkt, SHISHI_APOPTIONS_MUTUAL_REQUIRED);
  if (rc != SHISHI_OK)
    {
      printf ("cannot create authentication context\n");
      return 1;
    }


  /* checksum = port: terminal name */

  snprintf (cksumdata, 100, "%s:%s%s", port, cmd, cname);

  /* add checksum to authenticator */

  shishi_ap_authenticator_cksumdata_set (ap, cksumdata, strlen (cksumdata));
  /* To be compatible with MIT rlogind */
  shishi_ap_authenticator_cksumtype_set (ap, SHISHI_RSA_MD5);

  /* create der encoded AP-REQ */

  rc = shishi_ap_req_der (ap, &out, &outlen);
  if (rc != SHISHI_OK)
    {
      printf ("cannot build authentication request: %s\n",
	      shishi_strerror (rc));

      return 1;
    }

  if (verbose)
    shishi_authenticator_print (h, stderr, shishi_ap_authenticator (ap));

  /* extract subkey if present from ap exchange for secure connection */

  shishi_authenticator_get_subkey (h, shishi_ap_authenticator (ap), enckey);

  /* send size of AP-REQ to the server */

  msglen = htonl (outlen);
  safewrite (sock, (char *) &msglen, sizeof (int));

  /* send AP-REQ to the server */

  safewrite (sock, out, outlen);

  /* read a respond from server - what ? */

  read (sock, &auth, sizeof (int));

  /* For mutual authentication, wait for server reply. */

  if (shishi_apreq_mutual_required_p (h, shishi_ap_req (ap)))
    {
      if (verbose)
	printf ("Waiting for server to authenticate itself...\n");

      /* read size of the AP-REP */

      read (sock, (char *) &outlen, sizeof (int));

      /* read AP-REP */
      outlen = ntohl (outlen);
      outlen = read (sock, out, outlen);

      rc = shishi_ap_rep_verify_der (ap, out, outlen);
      if (rc == SHISHI_OK)
	{
	  if (verbose)
	    printf ("AP-REP verification OK...\n");
	}
      else
	{
	  if (rc == SHISHI_APREP_VERIFY_FAILED)
	    printf ("AP-REP verification failed...\n");
	  else
	    printf ("AP-REP verification error: %s\n", shishi_strerror (rc));
	  return 1;
	}

      /* The server is authenticated. */
      if (verbose)
	printf ("Server authenticated.\n");
    }

  /* We are now authenticated. */
  if (verbose)
    printf ("User authenticated.\n");

  return AUTH_OK;

}

#endif

int
main (int argc, char **argv)
{
  char *user = NULL;
  char *luser = NULL;
  char *host = NULL;
  char *port = "shell";
  char *p;
  char lport[5];

  struct passwd *pw;

  int af = AF_UNSPEC;
  struct addrinfo hint, *ai, *aip, *lai;
  struct sockaddr raddr;
  int raddrlen;
  int err, sock = -1, lsock = -1, esock = -1, i;

  int opt;

  bool verbose = false;

  char hostaddr[NI_MAXHOST];
  char portnr[NI_MAXSERV];

  char buf[3][BUFLEN], *bufp[3];
  int len[3], wlen;

  fd_set infd, outfd, infdset, outfdset, errfd;
  int maxfd;

  int flags;

#ifdef SHISHI

  Shishi *h;
  Shishi_key *enckey = NULL, *deckey = NULL;
  int rc;
  char *sname = NULL;
  int shishi = 0;
  int encryption = 0;
  int auth2 = 0;
  char *cmd, *tcmd;
  int hostlen, cmdlen;
  struct hostent *hostdata;
  char *iv = NULL;
  char *iv2 = NULL;
  char *iv3 = NULL;
  int ivlen;
  int ivlen2;
  int ivlen3;

#endif

  argv0 = argv[0];

  /* Lookup local username */

  if (!(pw = getpwuid (getuid ())))
    {
      fprintf (stderr, "%s: Could not lookup username: %s\n", argv0,
	       strerror (errno));
      return 1;
    }

  /* Process options */

#ifdef SHISHI
  while ((opt = getopt (argc, argv, "+l:p:46vsx")) != -1)
#else
  while ((opt = getopt (argc, argv, "+l:p:46v")) != -1)
#endif
    {

      switch (opt)
	{
	case 'l':
	  user = optarg;
	  break;
	case 'p':
	  port = optarg;
	  break;
	case '4':
	  af = AF_INET;
	  break;
	case '6':
	  af = AF_INET6;
	  break;
	case 'v':
	  verbose = true;
	  break;
#ifdef SHISHI
	case 's':
	  shishi = 1;
	  port = "544";
	  break;
	case 'x':
	  shishi = 1;
	  encryption = 1;
	  port = "544";
	  break;
#endif
	default:
	  fprintf (stderr, "%s: Unknown option!\n", argv0);
	  usage ();
	  return 1;
	}
    }

  if (optind == argc)
    {
      fprintf (stderr, "%s: No host specified!\n", argv0);
      usage ();
      return 1;
    }

#ifdef SHISHI

  if (!shishi)
    {
      luser = pw->pw_name;
      if (!user)
	user = luser;
    }
#endif

  host = argv[optind++];

  if ((p = strchr (host, '@')))
    {
      user = host;
      *p = '\0';
      host = p + 1;
    }

  /* Resolve hostname and try to make a connection */

  memset (&hint, '\0', sizeof (hint));
  hint.ai_family = af;
  hint.ai_socktype = SOCK_STREAM;

  err = getaddrinfo (host, port, &hint, &ai);

  if (err)
    {
      fprintf (stderr, "%s: Error looking up host: %s\n", argv0,
	       gai_strerror (err));
      return 1;
    }

  hint.ai_flags = AI_PASSIVE;

  for (aip = ai; aip; aip = aip->ai_next)
    {
      if (getnameinfo
	  (aip->ai_addr, aip->ai_addrlen, hostaddr, sizeof (hostaddr), portnr,
	   sizeof (portnr), NI_NUMERICHOST | NI_NUMERICSERV))
	{
	  fprintf (stderr, "%s: Error resolving address: %s\n", argv0,
		   strerror (errno));
	  return 1;
	}
      if (verbose)
	fprintf (stderr, "Trying %s port %s...", hostaddr, portnr);

      if ((sock =
	   socket (aip->ai_family, aip->ai_socktype, aip->ai_protocol)) == -1)
	{
	  if (verbose)
	    fprintf (stderr, " Could not open socket: %s\n",
		     strerror (errno));
	  continue;
	}

      hint.ai_family = aip->ai_family;

      /* Bind to a privileged port */

      for (i = 1023; i >= 512; i--)
	{
	  snprintf (lport, sizeof (lport), "%d", i);
	  err = getaddrinfo (NULL, lport, &hint, &lai);
	  if (err)
	    {
	      fprintf (stderr, " Error looking up localhost: %s\n",
		       gai_strerror (err));
	      return 1;
	    }

	  err = bind (sock, lai->ai_addr, lai->ai_addrlen);

	  freeaddrinfo (lai);

	  if (err)
	    continue;
	  else
	    break;
	}

      if (err)
	{
	  if (verbose)
	    fprintf (stderr, " Could not bind to privileged port: %s\n",
		     strerror (errno));
	  continue;
	}

      if (connect (sock, aip->ai_addr, aip->ai_addrlen) == -1)
	{
	  if (verbose)
	    fprintf (stderr, " Connection failed: %s\n", strerror (errno));
	  continue;
	}
      if (verbose)
	fprintf (stderr, " Connected.\n");
      break;
    }

  if (!aip)
    {
      fprintf (stderr, "%s: Could not make a connection.\n", argv0);
      return 1;
    }

  /* Create a socket for the incoming connection for stderr output */

  if ((lsock =
       socket (aip->ai_family, aip->ai_socktype, aip->ai_protocol)) == -1)
    {
      fprintf (stderr, "%s: Could not open socket: %s\n", argv0,
	       strerror (errno));
      return 1;
    }

  hint.ai_family = aip->ai_family;

  freeaddrinfo (ai);

  for (i--; i >= 512; i--)
    {
      snprintf (lport, sizeof (lport), "%d", i);
      err = getaddrinfo (NULL, lport, &hint, &lai);
      if (err)
	{
	  fprintf (stderr, "%s: Error looking up localhost: %s\n", argv0,
		   gai_strerror (err));
	  return 1;
	}

      err = bind (lsock, lai->ai_addr, lai->ai_addrlen);

      freeaddrinfo (lai);

      if (err)
	continue;
      else
	break;
    }

  if (err)
    {
      fprintf (stderr, "%s: Could not bind to privileged port: %s\n", argv0,
	       strerror (errno));
      return 1;
    }

  if (listen (lsock, 1))
    {
      fprintf (stderr, "%s: Could not listen: %s\n", argv0, strerror (errno));
      return 1;
    }

  /* Drop privileges */

  if (setuid (getuid ()))
    {
      fprintf (stderr, "%s: Unable to drop privileges: %s\n", argv0,
	       strerror (errno));
      return 1;
    }

  /* Send required information to the server */

  bufp[0] = buf[0];
  len[0] = sizeof (buf[0]);
#ifdef SHISHI

  if (shishi)
    {
      if (!shishi_check_version (SHISHI_VERSION))
	{
	  printf ("shishi_check_version() failed:\n"
		  "Header file incompatible with shared library.\n");
	  return 1;
	}

      rc = shishi_init (&h);
      if (rc != SHISHI_OK)
	{
	  printf ("error initializing shishi: %s\n", shishi_strerror (rc));
	  return 1;
	}

      hostdata = gethostbyname (host);
      hostlen = strlen (hostdata->h_name) + strlen (SERVICE) + 2;
      sname = malloc (hostlen);
      snprintf (sname, hostlen, "%s/%s", SERVICE, hostdata->h_name);

      rc = optind;
      cmdlen = BUFLEN;
      cmd = malloc (cmdlen);
      tcmd = cmd;

      if (encryption)
	safecpy (&tcmd, &cmdlen, "-x ", 0);

      for (; optind < argc; optind++)
	{
	  safecpy (&tcmd, &cmdlen, argv[optind], 0);
	  if (optind < argc - 1)
	    safecpy (&tcmd, &cmdlen, " ", 0);
	}

      safecpy (&tcmd, &cmdlen, "", 1);

      optind = rc;

      if (!user)
	user = (char *) shishi_principal_default (h);

      safewrite (sock, lport, strlen (lport) + 1);

      /* Wait for incoming connection from server */

      if ((esock = accept (lsock, &raddr, &raddrlen)) == -1)
	{
	  fprintf (stderr, "%s: Could not accept stderr connection: %s\n",
		   argv0, strerror (errno));
	  return 1;
	}

      close (lsock);

      if (auth (h, 0, user, sname, sock, cmd, port, &enckey, deckey) !=
	  AUTH_OK)
	return 1;

      free (cmd);

    }
  else
    {
      safecpy (&bufp[0], &len[0], lport, 1);
      safecpy (&bufp[0], &len[0], luser, 1);
    }

#else
  safecpy (&bufp[0], &len[0], lport, 1);
  safecpy (&bufp[0], &len[0], luser, 1);
#endif

  safecpy (&bufp[0], &len[0], user, 1);

#ifdef SHISHI
  if (encryption)
    safecpy (&bufp[0], &len[0], "-x ", 0);
#endif

  for (; optind < argc; optind++)
    {
      safecpy (&bufp[0], &len[0], argv[optind], 0);
      if (optind < argc - 1)
	safecpy (&bufp[0], &len[0], " ", 0);
    }

#ifdef SHISHI
  if (shishi)
    {
      safecpy (&bufp[0], &len[0], "", 1);
      safecpy (&bufp[0], &len[0], user, 1);
    }
  else
#endif

    safecpy (&bufp[0], &len[0], "", 1);

  if (!len[0])
    {
      fprintf (stderr, "%s: Arguments too long!\n", argv0);
      return 1;
    }

  if (safewrite (sock, buf[0], bufp[0] - buf[0]) == -1)
    {
      fprintf (stderr, "%s: Unable to send required information: %s\n", argv0,
	       strerror (errno));
      return 1;
    }

#ifdef SHISHI

  if (shishi)
    {
      safewrite (sock, &auth2, sizeof (int));
    }
#endif

  /* Wait for acknowledgement from server */

  errno = 0;

  if (read (sock, buf[0], 1) != 1 || *buf[0])
    {
      fprintf (stderr, "%s: Didn't receive NULL byte from server: %s\n",
	       argv0, strerror (errno));
      return 1;
    }

#ifdef SHISHI

  if (encryption)
    {
      ivlen = ivlen2 = ivlen3 = shishi_key_length (enckey);
      iv = malloc (ivlen);
      memset (iv, 1, ivlen);
      iv2 = malloc (ivlen2);
      memset (iv2, 3, ivlen2);
      iv3 = malloc (ivlen3);
      memset (iv3, 0, ivlen3);
    }

  if (!shishi)
    {

      /* Wait for incoming connection from server */

      if ((esock = accept (lsock, &raddr, &raddrlen)) == -1)
	{
	  fprintf (stderr, "%s: Could not accept stderr connection: %s\n",
		   argv0, strerror (errno));
	  return 1;
	}

      close (lsock);
    }

#else

  /* Wait for incoming connection from server */

  if ((esock = accept (lsock, &raddr, &raddrlen)) == -1)
    {
      fprintf (stderr, "%s: Could not accept stderr connection: %s\n", argv0,
	       strerror (errno));
      return 1;
    }

  close (lsock);

#endif

  /* Process input/output */

  flags = fcntl (sock, F_GETFL);
  fcntl (sock, F_SETFL, flags | O_NONBLOCK);
  flags = fcntl (esock, F_GETFL);
  fcntl (esock, F_SETFL, flags | O_NONBLOCK);

  bufp[0] = buf[0];
  bufp[1] = buf[1];
  bufp[2] = buf[2];

  FD_ZERO (&infdset);
  FD_ZERO (&outfdset);
  FD_SET (0, &infdset);
  FD_SET (sock, &infdset);
  FD_SET (esock, &infdset);

  maxfd = (sock > esock ? sock : esock) + 1;

  for (;;)
    {
      errno = 0;
      infd = infdset;
      outfd = outfdset;
      errfd = infdset;

      if (select (maxfd, &infd, &outfd, &errfd, NULL) <= 0)
	{
	  if (errno == EINTR)
	    continue;
	  else
	    break;
	}


      if (FD_ISSET (esock, &infd))
	{
#ifdef SHISHI
	  if (encryption)
	    {
	      rc = readenc (h, esock, buf[2], &len[2], iv2, &ivlen2, enckey);
	      if (rc != SHISHI_OK)
		break;
	    }
	  else
#endif
	    len[2] = read (esock, buf[2], BUFLEN);
	  if (len[2] <= 0)
	    {
	      if (errno != EINTR)
		{
		  if (FD_ISSET (sock, &infdset) || FD_ISSET (1, &outfdset))
		    FD_CLR (esock, &infdset);
		  else
		    break;
		}
	    }
	  else
	    {
	      FD_SET (2, &outfdset);
	      FD_CLR (esock, &infdset);
	    }
	}

      if (FD_ISSET (2, &outfd))
	{
	  wlen = write (2, bufp[2], len[2]);
	  if (wlen <= 0)
	    {
	      if (errno != EINTR)
		{
		  if (FD_ISSET (sock, &infdset) || FD_ISSET (1, &outfdset))
		    FD_CLR (esock, &infdset);
		  else
		    break;
		}
	    }
	  else
	    {
	      len[2] -= wlen;
	      bufp[2] += wlen;
	      if (!len[2])
		{
		  FD_CLR (2, &outfdset);
		  FD_SET (esock, &infdset);
		  bufp[2] = buf[2];
		}
	    }
	}

      if (FD_ISSET (sock, &infd))
	{
#ifdef SHISHI
	  if (encryption)
	    {
	      rc = readenc (h, sock, buf[1], &len[1], iv, &ivlen, enckey);
	      if (rc != SHISHI_OK)
		break;
	    }
	  else
#endif
	    len[1] = read (sock, buf[1], BUFLEN);
	  if (len[1] <= 0)
	    {
	      if (errno != EINTR)
		{
		  if (FD_ISSET (esock, &infdset) || FD_ISSET (2, &outfdset))
		    FD_CLR (sock, &infdset);
		  else
		    break;
		}
	    }
	  else
	    {
	      FD_SET (1, &outfdset);
	      FD_CLR (sock, &infdset);
	    }
	}

      if (FD_ISSET (1, &outfd))
	{
	  wlen = write (1, bufp[1], len[1]);
	  if (wlen <= 0)
	    {
	      if (errno != EINTR)
		{
		  if (FD_ISSET (esock, &infdset) || FD_ISSET (2, &outfdset))
		    FD_CLR (sock, &infdset);
		  else
		    break;
		}
	    }
	  else
	    {
	      len[1] -= wlen;
	      bufp[1] += wlen;
	      if (!len[1])
		{
		  FD_CLR (1, &outfdset);
		  FD_SET (sock, &infdset);
		  bufp[1] = buf[1];
		}
	    }
	}

      if (FD_ISSET (0, &infd))
	{
	  len[0] = read (0, buf[0], BUFLEN);
	  if (len[0] <= 0)
	    {
	      if (errno != EINTR)
		{
		  FD_CLR (0, &infdset);
		  shutdown (sock, SHUT_WR);
		}
	    }
	  else
	    {
	      FD_SET (sock, &outfdset);
	      FD_CLR (0, &infdset);
	    }
	}

      if (FD_ISSET (sock, &outfd))
	{
#ifdef SHISHI
	  if (encryption)
	    {
	      rc =
		writeenc (h, sock, bufp[0], len[0], &wlen, iv3, &ivlen3,
			  enckey);
	      if (rc != SHISHI_OK)
		break;
	    }
	  else
#endif
	    wlen = write (sock, bufp[0], len[0]);
	  if (wlen <= 0)
	    {
	      if (errno != EINTR)
		break;
	    }
	  else
	    {
	      len[0] -= wlen;
	      bufp[0] += wlen;
	      if (!len[0])
		{
		  FD_CLR (sock, &outfdset);
		  FD_SET (0, &infdset);
		  bufp[0] = buf[0];
		}
	    }
	}


    }

  if (errno)
    {
      fprintf (stderr, "%s: %s\n", argv0, strerror (errno));
      return 1;
    }

  close (sock);
  close (esock);

#ifdef SHISHI

  if (shishi)
    {
      shishi_done (h);
      if (encryption)
	{
	  free (iv);
	  free (iv2);
	  free (iv3);
	}
    }

#endif

  return 0;
}

