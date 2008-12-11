/* starttls.c --- Handle extended TCP connections (for TLS).
 * Copyright (C) 2002, 2003, 2006, 2007, 2008  Simon Josefsson
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

/* Note: only use syslog to report errors in this file. */

/* Get Shishid stuff. */
#include "kdc.h"

/* This function will print information about this session's peer
 * certificate. */
static void
logcertinfo (gnutls_session session)
{
  time_t now = time (NULL);
  const gnutls_datum *cert_list;
  unsigned cert_list_size = 0;
  gnutls_x509_crt cert;
  size_t i;
  int rc;

  cert_list = gnutls_certificate_get_peers (session, &cert_list_size);
  if (!cert_list)
    return;

  rc = gnutls_x509_crt_init (&cert);
  if (rc < 0)
    {
      syslog (LOG_ERR, "TLS xci failed (%d): %s", rc, gnutls_strerror (rc));
      return;
    }

  if (gnutls_certificate_type_get (session) == GNUTLS_CRT_X509)
    for (i = 0; i < cert_list_size; i++)
      {
	time_t expiration_time, activation_time;
	char *expiration_time_str = NULL, *activation_time_str = NULL;
	unsigned char *serial = NULL, *serialhex = NULL;
	char *issuer = NULL, *subject = NULL;
	size_t seriallen, issuerlen, subjectlen;
	unsigned char md5fingerprint[16], md5fingerprinthex[3 * 16 + 1];
	size_t md5fingerprintlen;
	int algo;
	unsigned bits;
	const char *keytype, *validity;

	rc = gnutls_x509_crt_import (cert, &cert_list[i],
				     GNUTLS_X509_FMT_DER);
	if (rc < 0)
	  {
	    syslog (LOG_ERR, "TLS xci[%d] failed (%d): %s", i,
		    rc, gnutls_strerror (rc));
	    goto cleanup;
	  }

	md5fingerprintlen = sizeof (md5fingerprint);
	rc = gnutls_fingerprint (GNUTLS_DIG_MD5, &cert_list[i],
				 md5fingerprint, &md5fingerprintlen);
	if (rc != GNUTLS_E_SUCCESS)
	  {
	    syslog (LOG_ERR, "TLS f[%d] failed (%d): %s", i,
		    rc, gnutls_strerror (rc));
	    goto cleanup;
	  }

	for (i = 0; i < md5fingerprintlen; i++)
	  sprintf ((char *) &md5fingerprinthex[3 * i], "%.2x:",
		   md5fingerprint[i]);

	expiration_time = gnutls_x509_crt_get_expiration_time (cert);
	if (expiration_time == (time_t) - 1)
	  {
	    syslog (LOG_ERR, "TLS xcget[%d] failed (%d): %s", i,
		    rc, gnutls_strerror (rc));
	    goto cleanup;
	  }

	activation_time = gnutls_x509_crt_get_activation_time (cert);
	if (expiration_time == (time_t) - 1)
	  {
	    syslog (LOG_ERR, "TLS xcgat[%d] failed (%d): %s", i,
		    rc, gnutls_strerror (rc));
	    goto cleanup;
	  }

	expiration_time_str = xstrdup (ctime (&expiration_time));
	if (expiration_time_str[strlen (expiration_time_str) - 1] == '\n')
	  expiration_time_str[strlen (expiration_time_str) - 1] = '\0';

	activation_time_str = xstrdup (ctime (&activation_time));
	if (activation_time_str[strlen (activation_time_str) - 1] == '\n')
	  activation_time_str[strlen (activation_time_str) - 1] = '\0';

	rc = gnutls_x509_crt_get_dn (cert, NULL, &subjectlen);
	if (rc != GNUTLS_E_SUCCESS && rc != GNUTLS_E_SHORT_MEMORY_BUFFER)
	  {
	    syslog (LOG_ERR, "TLS xcgd[%d] failed (%d): %s", i,
		    rc, gnutls_strerror (rc));
	    goto cleanup;
	  }
	subject = xmalloc (++subjectlen);
	rc = gnutls_x509_crt_get_dn (cert, subject, &subjectlen);
	if (rc != GNUTLS_E_SUCCESS)
	  {
	    syslog (LOG_ERR, "TLS xcgd2[%d] failed (%d): %s", i,
		    rc, gnutls_strerror (rc));
	    goto cleanup;
	  }

	rc = gnutls_x509_crt_get_issuer_dn (cert, NULL, &issuerlen);
	if (rc != GNUTLS_E_SUCCESS && rc != GNUTLS_E_SHORT_MEMORY_BUFFER)
	  {
	    syslog (LOG_ERR, "TLS xcgid[%d] failed (%d): %s", i,
		    rc, gnutls_strerror (rc));
	    goto cleanup;
	  }
	issuer = xmalloc (++issuerlen);
	rc = gnutls_x509_crt_get_issuer_dn (cert, issuer, &issuerlen);
	if (rc != GNUTLS_E_SUCCESS)
	  {
	    syslog (LOG_ERR, "TLS xcgid2[%d] failed (%d): %s", i,
		    rc, gnutls_strerror (rc));
	    goto cleanup;
	  }

	seriallen = 0;
	rc = gnutls_x509_crt_get_serial (cert, NULL, &seriallen);
	if (rc != GNUTLS_E_SUCCESS && rc != GNUTLS_E_SHORT_MEMORY_BUFFER)
	  {
	    syslog (LOG_ERR, "TLS xcgs[%d] failed (%d): %s", i,
		    rc, gnutls_strerror (rc));
	    goto cleanup;
	  }
	serial = xmalloc (seriallen);
	rc = gnutls_x509_crt_get_serial (cert, serial, &seriallen);
	if (rc != GNUTLS_E_SUCCESS)
	  {
	    syslog (LOG_ERR, "TLS xcgs2[%d] failed (%d): %s", i,
		    rc, gnutls_strerror (rc));
	    goto cleanup;
	  }

	serialhex = xmalloc (2 * seriallen + 1);
	for (i = 0; i < seriallen; i++)
	  sprintf ((char *) &serialhex[2 * i], "%.2x", serial[i]);

	algo = gnutls_x509_crt_get_pk_algorithm (cert, &bits);
	if (algo == GNUTLS_PK_RSA)
	  keytype = "RSA modulus";
	else if (algo == GNUTLS_PK_DSA)
	  keytype = "DSA exponent";
	else
	  keytype = "UNKNOWN";

	if (expiration_time < now)
	  validity = "EXPIRED";
	else if (activation_time > now)
	  validity = "NOT YET ACTIVATED";
	else
	  validity = "valid";

	syslog (LOG_INFO, "TLS client certificate `%s', issued by `%s', "
		"serial number `%s', MD5 fingerprint `%s', activated `%s', "
		"expires `%s', version #%d, key %s %d bits, currently %s",
		subject, issuer, serialhex, md5fingerprinthex,
		activation_time_str, expiration_time_str,
		gnutls_x509_crt_get_version (cert), keytype, bits, validity);

      cleanup:
	if (serialhex)
	  free (serialhex);
	if (serial)
	  free (serial);
	if (expiration_time_str)
	  free (expiration_time_str);
	if (activation_time_str)
	  free (activation_time_str);
	if (issuer)
	  free (issuer);
	if (subject)
	  free (subject);
      }

  gnutls_x509_crt_deinit (cert);

  rc = gnutls_certificate_verify_peers (session);
  if (rc != GNUTLS_E_SUCCESS)
    syslog (LOG_ERR, "TLS client certificate verify failed (%d): %s",
	    rc, gnutls_strerror (rc));
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
  int resumedp = gnutls_session_is_resumed (session);

  syslog (LOG_INFO, "TLS handshake negotiated protocol `%s', "
	  "key exchange `%s', certficate type `%s', cipher `%s', "
	  "mac `%s', compression `%s', %s",
	  protocol ? protocol : "N/A",
	  keyexchange ? keyexchange : "N/A",
	  certtype ? certtype : "N/A",
	  cipher ? cipher : "N/A",
	  mac ? mac : "N/A", compression ? compression : "N/A",
	  resumedp ? "resumed session" : "session not resumed");

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
      logcertinfo (session);
      break;

    case GNUTLS_CRD_SRP:
    case GNUTLS_CRD_PSK:
    case GNUTLS_CRD_IA:
    default:
      syslog (LOG_ERR, "Unknown TLS authentication (%d)", cred);
      break;
    }
}

#define STARTTLS_CLIENT_REQUEST "\x70\x00\x00\x01"
#define STARTTLS_SERVER_ACCEPT "\x00\x00\x00\x00"
#define STARTTLS_LEN 4

/* Handle the high TCP length bit, currently only used for STARTTLS. */
int
kdc_extension (struct listenspec *ls)
{
  int rc;

  if (!ls->usetls && ls->type == SOCK_STREAM && ls->bufpos == 4 &&
      memcmp (ls->buf, STARTTLS_CLIENT_REQUEST, STARTTLS_LEN) == 0)
    {
      const int kx_prio[] = { GNUTLS_KX_RSA, GNUTLS_KX_DHE_DSS,
	GNUTLS_KX_DHE_RSA, GNUTLS_KX_ANON_DH, 0
      };

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

      rc = gnutls_credentials_set (ls->session, GNUTLS_CRD_CERTIFICATE,
				   x509cred);
      if (rc != GNUTLS_E_SUCCESS)
	{
	  syslog (LOG_ERR, "TLS failed, gnutls_cs X.509 %d: %s", rc,
		  gnutls_strerror (rc));
	  return -1;
	}

      gnutls_certificate_server_set_request (ls->session,
					     GNUTLS_CERT_REQUEST);

      gnutls_dh_set_prime_bits (ls->session, DH_BITS);
      gnutls_transport_set_ptr (ls->session,
				(gnutls_transport_ptr) ls->sockfd);

      gnutls_db_set_retrieve_function (ls->session, resume_db_fetch);
      gnutls_db_set_store_function (ls->session, resume_db_store);
      gnutls_db_set_remove_function (ls->session, resume_db_delete);

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
