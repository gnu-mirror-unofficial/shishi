/* starttls.c --- Handle extended TCP connections (for TLS).
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

/* Note: only use syslog to report errors in this file. */

/* Get Shishid stuff. */
#include "kdc.h"

static const char *
bin2hex (const void *bin, size_t bin_size)
{
  static char printable[120];
  unsigned char *_bin;
  char *print;
  size_t i;

  print = printable;
  for (i = 0; i < bin_size; i++)
    {
      sprintf (print, "%.2x ", _bin[i]);
      print += 2;
    }

  return printable;
}

/* This function will print information about this session's peer
 * certificate.
 */
static void
print_x509_certificate_info (gnutls_session session)
{
  char serial[40];
  char dn[128];
  size_t size;
  unsigned int algo, bits;
  time_t expiration_time, activation_time;
  const gnutls_datum *cert_list;
  int cert_list_size = 0;
  gnutls_x509_crt cert;

  cert_list = gnutls_certificate_get_peers (session, &cert_list_size);

  if (cert_list_size > 0 &&
      gnutls_certificate_type_get (session) == GNUTLS_CRT_X509)
    {

      /* no error checking
       */
      gnutls_x509_crt_init (&cert);

      gnutls_x509_crt_import (cert, &cert_list[0], GNUTLS_X509_FMT_DER);

      printf (" - Certificate info:\n");

      expiration_time = gnutls_x509_crt_get_expiration_time (cert);
      activation_time = gnutls_x509_crt_get_activation_time (cert);

      printf (" - Certificate is valid since: %s", ctime (&activation_time));
      printf (" - Certificate expires: %s", ctime (&expiration_time));

      /* Print the serial number of the certificate.
       */
      size = sizeof (serial);
      gnutls_x509_crt_get_serial (cert, serial, &size);

      printf (" - Certificate serial number: %s\n", bin2hex (serial, size));

      /* Extract some of the public key algorithm's parameters
       */
      algo = gnutls_x509_crt_get_pk_algorithm (cert, &bits);

      printf ("Certificate public key: ");

      if (algo == GNUTLS_PK_RSA)
	{
	  printf ("RSA\n");
	  printf (" Modulus: %d bits\n", bits);
	}
      else if (algo == GNUTLS_PK_DSA)
	{
	  printf ("DSA\n");
	  printf (" Exponent: %d bits\n", bits);
	}
      else
	{
	  printf ("UNKNOWN\n");
	}

      /* Print the version of the X.509 certificate.
       */
      printf (" - Certificate version: #%d\n",
	      gnutls_x509_crt_get_version (cert));

      size = sizeof (dn);
      gnutls_x509_crt_get_dn (cert, dn, &size);
      printf (" - DN: %s\n", dn);

      size = sizeof (dn);
      gnutls_x509_crt_get_issuer_dn (cert, dn, &size);
      printf (" - Certificate Issuer's DN: %s\n", dn);

      gnutls_x509_crt_deinit (cert);

    }
}

/* This function will log some details of the given session. */
static void
logtlsinfo (gnutls_session session)
{
  gnutls_credentials_type cred;
  const char *protocol =
    gnutls_protocol_get_name (gnutls_protocol_get_version (session));
  gnutls_kx_algorithm kx = gnutls_kx_get (session);
  const char *keyexchange = gnutls_kx_get_name (kx);
  const char *certtype =
    gnutls_certificate_type_get_name (gnutls_certificate_type_get (session));
  const char *cipher = gnutls_cipher_get_name (gnutls_cipher_get (session));
  const char *mac = gnutls_mac_get_name (gnutls_mac_get (session));
  const char *compression =
    gnutls_compression_get_name (gnutls_compression_get (session));

  syslog (LOG_INFO, "TLS handshake negotiated protocol `%s', "
	  "key exchange `%s', certficate type `%s', cipher `%s', "
	  "mac `%s', compression `%s'",
	  protocol ? protocol : "N/A",
	  keyexchange ? keyexchange : "N/A",
	  certtype ? certtype : "N/A",
	  cipher ? cipher : "N/A",
	  mac ? mac : "N/A", compression ? compression : "N/A");

  cred = gnutls_auth_get_type (session);
  switch (cred)
    {
    case GNUTLS_CRD_ANON:
      syslog (LOG_INFO,
	      "TLS anonymous authentication with %d bit Diffie-Hellman",
	      gnutls_dh_get_prime_bits (session));
      break;

    case GNUTLS_CRD_CERTIFICATE:
      if (kx == GNUTLS_KX_DHE_RSA || kx == GNUTLS_KX_DHE_DSS)
	syslog (LOG_INFO, "TLS certificate authentication with %d bit "
		"ephemeral Diffie-Hellman",
		gnutls_dh_get_prime_bits (session));
      print_x509_certificate_info (session);
      break;

    default:
      syslog (LOG_ERR, "Unknown TLS authentication (%d)", cred);
      break;
    }
}

#define STARTTLS_CLIENT_REQUEST "\x70\x00\x00\x01"
#define STARTTLS_SERVER_ACCEPT "\x70\x00\x00\x02"
#define STARTTLS_LEN 4

/* Handle the high TCP length bit, currently only used for STARTTLS. */
int
kdc_extension (struct listenspec *ls)
{
  int rc;

  if (!ls->usetls && ls->type == SOCK_STREAM && ls->bufpos == 4 &&
      memcmp (ls->buf, STARTTLS_CLIENT_REQUEST, STARTTLS_LEN) == 0)
    {
      const int kx_prio[] = { GNUTLS_KX_ANON_DH, 0 };

      syslog (LOG_INFO, "Trying STARTTLS");

      memcpy (ls->buf, STARTTLS_SERVER_ACCEPT, STARTTLS_LEN);
      ls->bufpos = STARTTLS_LEN;

      kdc_send1 (ls);

      rc = gnutls_init (&ls->session, GNUTLS_SERVER);
      if (rc != GNUTLS_E_SUCCESS)
	{
	  syslog (LOG_ERR, "TLS initialization failed (%d): %s", rc,
		  gnutls_strerror (rc));
	  return -1;
	}

      rc = gnutls_set_default_priority (ls->session);
      if (rc != GNUTLS_E_SUCCESS)
	{
	  syslog (LOG_ERR, "TLS failed, gnutls_sdp %d: %s", rc,
		  gnutls_strerror (rc));
	  return -1;
	}

      rc = gnutls_kx_set_priority (ls->session, kx_prio);
      if (rc != GNUTLS_E_SUCCESS)
	{
	  syslog (LOG_ERR, "TLS failed, gnutls_ksp %d: %s", rc,
		  gnutls_strerror (rc));
	  return -1;
	}

      rc = gnutls_credentials_set (ls->session, GNUTLS_CRD_ANON, anoncred);
      if (rc != GNUTLS_E_SUCCESS)
	{
	  syslog (LOG_ERR, "TLS failed, gnutls_cs %d: %s", rc,
		  gnutls_strerror (rc));
	  return -1;
	}

      gnutls_dh_set_prime_bits (ls->session, DH_BITS);
      gnutls_transport_set_ptr (ls->session,
				(gnutls_transport_ptr) ls->sockfd);

      rc = gnutls_handshake (ls->session);
      if (rc < 0)
	{
	  syslog (LOG_ERR, "TLS handshake failed (%d): %s\n",
		  rc, gnutls_strerror (rc));
	  return -1;
	}

      logtlsinfo (ls->session);

      ls->bufpos = 0;
      ls->usetls = 1;
    }

  return 0;
}
