/* kdc.c --- Key distribution (AS/TGS) functions.
 * Copyright (C) 2002-2014 Simon Josefsson
 *
 * This file is part of Shishi.
 *
 * Shishi is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * Shishi is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Shishi; if not, see http://www.gnu.org/licenses or write
 * to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
 * Floor, Boston, MA 02110-1301, USA
 *
 */

#include "internal.h"

/**
 * shishi_as_derive_salt:
 * @handle: Shishi handle as allocated by shishi_init().
 * @asreq: Input AS-REQ variable.
 * @asrep: Input AS-REP variable.
 * @salt: Returned pointer to newly allocated output array.
 * @saltlen: Pointer to integer, returning size of output array.
 *
 * Computes the salt that should be used when deriving a key via
 * shishi_string_to_key() for an AS exchange.  Currently this
 * searches for PA-DATA of type %SHISHI_PA_PW_SALT in the AS-REP
 * provided by @asrep, and if present returns it.  Otherwise the
 * salt is composed from the client name and the realm, both are
 * extracted from the request @asreq.
 *
 * Return value: Returns %SHISHI_OK if successful.
 *   Failure conditions include various ASN.1 issues.
 **/
int
shishi_as_derive_salt (Shishi * handle,
		       Shishi_asn1 asreq,
		       Shishi_asn1 asrep, char **salt, size_t * saltlen)
{
  size_t i, n;
  char *format;
  int res;

  res = shishi_asn1_number_of_elements (handle, asrep, "padata", &n);
  if (res == SHISHI_ASN1_NO_ELEMENT)
    n = 0;
  else if (res != SHISHI_OK)
    return res;

  for (i = 1; i <= n; i++)
    {
      int patype;

      asprintf (&format, "padata.?%zu.padata-type", i);
      res = shishi_asn1_read_int32 (handle, asrep, format, &patype);
      free (format);
      if (res != SHISHI_OK)
	return res;

      if (patype == SHISHI_PA_PW_SALT)
	{
	  asprintf (&format, "padata.?%zu.padata-value", i);
	  res = shishi_asn1_read (handle, asrep, format, salt, saltlen);
	  free (format);
	  if (res != SHISHI_OK)
	    return res;

	  return SHISHI_OK;
	}
    }

  res = shishi_kdcreq_realm (handle, asreq, salt, saltlen);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_number_of_elements (handle, asreq,
					"req-body.cname.name-string", &n);
  if (res != SHISHI_OK)
    return res;

  for (i = 1; i <= n; i++)
    {
      char *tmp;
      size_t tmplen;

      asprintf (&format, "req-body.cname.name-string.?%zu", i);
      res = shishi_asn1_read (handle, asreq, format, &tmp, &tmplen);
      free (format);
      if (res != SHISHI_OK)
	return res;

      *saltlen += tmplen;

      *salt = xrealloc (*salt, *saltlen + 1);
      memcpy (*salt + *saltlen - tmplen, tmp, tmplen);
      (*salt)[*saltlen] = '\0';
      free (tmp);
    }

  return SHISHI_OK;
}

/**
 * shishi_kdcreq_sendrecv_hint:
 * @handle: Shishi library handle created by shishi_init().
 * @kdcreq: Input variable with a prepared AS-REQ.
 * @kdcrep: Output pointer variable for decoded AS-REP.
 * @hint: Input #Shishi_tkts_hint structure with flags.
 *
 * Sends a request to KDC, and receives the response.
 * The provided request @kdcreq and the hints structure @hint,
 * together determine transmitted data.  On reception the reply
 * is decoded as AS-REP into @kdcrep.
 *
 * Return value: Return code is %SHISHI_OK on success,
 *   %SHISHI_KDC_TIMEOUT on timeouts, %SHISHI_ASN1_ERROR on
 *   translation errors, and %SHISHI_GOT_KRBERROR for other
 *   corruptions.
 **/
int
shishi_kdcreq_sendrecv_hint (Shishi * handle,
			     Shishi_asn1 kdcreq,
			     Shishi_asn1 * kdcrep, Shishi_tkts_hint * hint)
{
  char *der;
  size_t der_len;
  size_t buflen;
  char *buffer;
  char *realm;
  size_t realmlen;
  int res;

  res = shishi_asn1_to_der (handle, kdcreq, &der, &der_len);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "Could not DER encode AS-REQ: %s\n",
			   shishi_strerror (res));
      return res;
    }

  res = shishi_asn1_read (handle, kdcreq, "req-body.realm",
			  &realm, &realmlen);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "Could not get realm: %s\n",
			   shishi_error (handle));
      return res;
    }
  realm = xrealloc (realm, realmlen + 1);
  realm[realmlen] = '\0';

  res = shishi_kdc_sendrecv_hint (handle, realm, der, der_len,
				  &buffer, &buflen, hint);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "Could not send to KDC: %s\n",
			   shishi_error (handle));
      return res;
    }
  free (realm);
  free (der);

  if (VERBOSEASN1 (handle))
    printf ("received %zu bytes\n", buflen);

  *kdcrep = shishi_der2asn1_asrep (handle, buffer, buflen);
  if (*kdcrep == NULL)
    {
      *kdcrep = shishi_der2asn1_tgsrep (handle, buffer, buflen);
      if (*kdcrep == NULL)
	{
	  *kdcrep = shishi_der2asn1_kdcrep (handle, buffer, buflen);
	  if (*kdcrep == NULL)
	    {
	      *kdcrep = shishi_der2asn1_krberror (handle, buffer, buflen);
	      if (*kdcrep == NULL)
		{
		  shishi_error_printf
		    (handle, "Could not DER decode AS-REP/KRB-ERROR: %s",
		     shishi_error (handle));
		  return SHISHI_ASN1_ERROR;
		}

	      shishi_error_clear (handle);
	      return SHISHI_GOT_KRBERROR;
	    }
	  else
	    {
	      printf
		("Buggy server replied with KDC-REP instead of AS-REP\n");
	    }
	}
    }
  free (buffer);

  return SHISHI_OK;
}

/**
 * shishi_kdcreq_sendrecv:
 * @handle: Shishi library handle created by shishi_init().
 * @kdcreq: Input variable with a prepared AS-REQ.
 * @kdcrep: Output pointer variable returning received AS-REP.
 *
 * Sends a request to KDC, and receives the response.
 * The provided AS-REQ, in @kdcreq, sets all data for the
 * request.  On reception the reply is decoded as AS-REP
 * into @kdcrep.
 *
 * Return value: Return code is %SHISHI_OK on success,
 *   %SHISHI_KDC_TIMEOUT on timeouts, %SHISHI_ASN1_ERROR on
 *   translation errors, and %SHISHI_GOT_KRBERROR for other
 *   corruptions.
 **/
int
shishi_kdcreq_sendrecv (Shishi * handle, Shishi_asn1 kdcreq,
			Shishi_asn1 * kdcrep)
{
  return shishi_kdcreq_sendrecv_hint (handle, kdcreq, kdcrep, NULL);
}

/**
 * shishi_kdc_copy_crealm:
 * @handle: Shishi handle as allocated by shishi_init().
 * @kdcrep: KDC-REP where the field "crealm" is updated.
 * @encticketpart: EncTicketPart providing "crealm" field.
 *
 * Reads the field "crealm" from the ticket @encticketpart
 * and copies the value into the reply @kdcrep.
 *
 * Return value: Returns %SHISHI_OK if successful, and ASN.1
 *   failures otherwise.
 **/
int
shishi_kdc_copy_crealm (Shishi * handle,
			Shishi_asn1 kdcrep, Shishi_asn1 encticketpart)
{
  char *buf;
  size_t buflen;
  int res;

  res = shishi_asn1_read (handle, encticketpart, "crealm", &buf, &buflen);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_write (handle, kdcrep, "crealm", buf, buflen);
  free (buf);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_as_check_crealm:
 * @handle: Shishi handle as allocated by shishi_init().
 * @asreq: Request of type AS-REQ.
 * @asrep: Reply structure of type AS-REP.
 *
 * Verifies that the fields @asreq.req-body.realm and @asrep.crealm
 * contain identical realm names.  This is one of the steps that
 * has to be performed when processing an exchange of AS-REQ and
 * AS-REP; see shishi_kdc_process() for more details.
 *
 * Return value: Returns %SHISHI_OK if successful,
 *   %SHISHI_REALM_MISMATCH whenever the realm names differ,
 *   and an error code otherwise.
 **/
int
shishi_as_check_crealm (Shishi * handle, Shishi_asn1 asreq, Shishi_asn1 asrep)
{
  char *reqrealm, *reprealm;
  size_t reqrealmlen, reprealmlen;
  int res;

  res = shishi_asn1_read (handle, asreq, "req-body.realm",
			  &reqrealm, &reqrealmlen);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "Could not read request realm: %s\n",
			   shishi_strerror (res));
      return res;
    }

  res = shishi_asn1_read (handle, asrep, "crealm", &reprealm, &reprealmlen);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "Could not read reply realm: %s\n",
			   shishi_strerror (res));
      return res;
    }

  reqrealm[reqrealmlen] = '\0';
  reprealm[reprealmlen] = '\0';

  if (VERBOSEASN1 (handle))
    {
      printf ("request realm: %s\n", reqrealm);
      printf ("reply realm: %s\n", reprealm);
    }

  res = strcmp (reqrealm, reprealm) != 0;

  free (reqrealm);
  free (reprealm);

  if (res)
    return SHISHI_REALM_MISMATCH;

  return SHISHI_OK;
}

/**
 * shishi_kdc_copy_cname:
 * @handle: Shishi handle as allocated by shishi_init().
 * @kdcrep: KDC-REP where the field "cname" is updated.
 * @encticketpart: EncTicketPart providing "cname" field.
 *
 * Reads the field "cname" from the ticket @encticketpart
 * and copies the value into the reply @kdcrep.
 *
 * Return value: Returns %SHISHI_OK if successful, and ASN.1
 *   failures otherwise.
 **/
int
shishi_kdc_copy_cname (Shishi * handle,
		       Shishi_asn1 kdcrep, Shishi_asn1 encticketpart)
{
  char *buf;
  char *format;
  size_t buflen, i, n;
  int res;

  res = shishi_asn1_read (handle, encticketpart,
			  "cname.name-type", &buf, &buflen);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_write (handle, kdcrep, "cname.name-type", buf, buflen);
  free (buf);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_number_of_elements (handle, encticketpart,
					"cname.name-string", &n);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_write (handle, kdcrep, "cname.name-string", NULL, 0);
  if (res != SHISHI_OK)
    return res;

  for (i = 1; i <= n; i++)
    {
      res = shishi_asn1_write (handle, kdcrep, "cname.name-string", "NEW", 1);
      if (res != SHISHI_OK)
	return res;

      asprintf (&format, "cname.name-string.?%zu", i);
      res = shishi_asn1_read (handle, encticketpart, format, &buf, &buflen);
      free (format);
      if (res != SHISHI_OK)
	return res;

      asprintf (&format, "cname.name-string.?%zu", i);
      res = shishi_asn1_write (handle, kdcrep, format, buf, buflen);
      free (format);
      free (buf);
      if (res != SHISHI_OK)
	return res;
    }

  return SHISHI_OK;
}

/**
 * shishi_as_check_cname:
 * @handle: Shishi handle as allocated by shishi_init().
 * @asreq: Request of type AS-REQ.
 * @asrep: Reply structure of type AS-REP.
 *
 * Verifies that the fields @asreq.req-body.cname and @asrep.cname
 * contain identical names.  This is one of the steps that has to
 * be performed when processing an exchange of AS-REQ and AS-REP;
 * see shishi_kdc_process() for more details.
 *
 * Return value: Returns %SHISHI_OK if successful,
 *   %SHISHI_CNAME_MISMATCH if the names differ,
 *   and an error code otherwise.
 **/
int
shishi_as_check_cname (Shishi * handle, Shishi_asn1 asreq, Shishi_asn1 asrep)
{
  char *reqcname, *repcname;
  size_t reqcnamelen, repcnamelen, i, j;
  char *format;
  int res;

  /* We do not compare msg-type as recommended on the ietf-krb-wg list */

  res = shishi_asn1_number_of_elements (handle, asreq,
					"req-body.cname.name-string", &i);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_number_of_elements (handle, asrep,
					"cname.name-string", &j);
  if (res != SHISHI_OK)
    return res;

  if (i != j)
    return SHISHI_CNAME_MISMATCH;

  for (i = 1; i <= j; i++)
    {
      asprintf (&format, "req-body.cname.name-string.?%zu", i);
      res = shishi_asn1_read (handle, asreq, format, &reqcname, &reqcnamelen);
      free (format);
      if (res != SHISHI_OK)
	return res;

      asprintf (&format, "cname.name-string.?%zu", i);
      res = shishi_asn1_read (handle, asrep, format, &repcname, &repcnamelen);
      free (format);
      if (res != SHISHI_OK)
	return res;

      if (VERBOSEASN1 (handle))
	{
	  reqcname[reqcnamelen] = '\0';
	  repcname[repcnamelen] = '\0';
	  printf ("request cname %zu: %s\n", i, reqcname);
	  printf ("reply cname %zu: %s\n", i, repcname);
	}

      res = (reqcnamelen != repcnamelen) ||
	(memcmp (reqcname, repcname, reqcnamelen) != 0);

      free (reqcname);
      free (repcname);

      if (res)
	return SHISHI_CNAME_MISMATCH;
    }

  return SHISHI_OK;
}

/**
 * shishi_kdc_copy_nonce:
 * @handle: Shishi handle as allocated by shishi_init().
 * @kdcreq: KDC-REQ providing "nonce" field.
 * @enckdcreppart: EncKDCRepPart where "nonce" field is updated.
 *
 * Sets the field "nonce" in @enckdcreppart to a value retreived
 * from the corresponding field in @kdcreq.
 *
 * Return value: Returns %SHISHI_OK if successful.
 **/
int
shishi_kdc_copy_nonce (Shishi * handle,
		       Shishi_asn1 kdcreq, Shishi_asn1 enckdcreppart)
{
  int res;
  uint32_t nonce;

  res = shishi_kdcreq_nonce (handle, kdcreq, &nonce);
  if (res != SHISHI_OK)
    return res;

  res = shishi_enckdcreppart_nonce_set (handle, enckdcreppart, nonce);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

static int
shishi_kdc_check_nonce_1 (Shishi * handle,
			  char *reqnonce, size_t reqnoncelen,
			  char *repnonce, size_t repnoncelen)
{
  if (VERBOSENOISE (handle))
    {
      size_t i;

      printf ("request nonce (len=%zu) ", reqnoncelen);
      for (i = 0; i < reqnoncelen; i++)
	printf ("%02x", reqnonce[i] & 0xFF);
      printf ("\n");
      printf ("reply nonce (len=%zu) ", repnoncelen);
      for (i = 0; i < repnoncelen; i++)
	printf ("%02x", repnonce[i] & 0xFF);
      printf ("\n");
    }

  if (reqnoncelen > 4 && repnoncelen == 4)
    {
      /* This case warrants some explanation.
       *
       * RFC 1510 didn't restrict nonce to 4 bytes, so the nonce field
       * may be longer. There are KDCs that will accept longer nonces
       * but truncate them to 4 bytes in the response.  If we happen
       * to parse such a KDC request, we consider it OK even though it
       * isn't.  I doubt this is a security problem, because you need
       * to break the integrity protection of the encryption system,
       * as well as guessing the nonce correctly.  The nonce doesn't
       * seem to serve any purpose at all, really.
       *
       */

      if (memcmp (reqnonce + reqnoncelen - 4, repnonce, 4) != 0)
	return SHISHI_NONCE_MISMATCH;

      shishi_warn (handle, "server truncated long nonce to 4 bytes");

      return SHISHI_OK;
    }

  if (reqnoncelen != repnoncelen ||
      memcmp (reqnonce, repnonce, repnoncelen) != 0)
    return SHISHI_NONCE_MISMATCH;

  return SHISHI_OK;
}

/**
 * shishi_kdc_check_nonce:
 * @handle: Shishi handle as allocated by shishi_init().
 * @kdcreq: Request of type KDC-REQ.
 * @enckdcreppart: Encrypted KDC-REP part.
 *
 * Verifies that @kdcreq.req-body.nonce and @enckdcreppart.nonce
 * contain matching values.  This is one of the steps that has to
 * be performed when processing an exchange of KDC-REQ and KDC-REP.
 *
 * Return value: Returns %SHISHI_OK if successful,
 *   %SHISHI_NONCE_MISMATCH whenever the nonces are of
 *   differing lengths (usually a sign that a buggy server
 *   truncates the nonce to 4 bytes) and the same code if the
 *   nonce values differ, or an error code otherwise.
 **/
int
shishi_kdc_check_nonce (Shishi * handle,
			Shishi_asn1 kdcreq, Shishi_asn1 enckdcreppart)
{
  char *reqnonce;
  char *repnonce;
  size_t reqnoncelen, repnoncelen;
  int res;

  res = shishi_asn1_read (handle, kdcreq, "req-body.nonce",
			  &reqnonce, &reqnoncelen);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "Could not read request nonce: %s\n",
			   shishi_strerror (res));
      return res;
    }

  res = shishi_asn1_read (handle, enckdcreppart, "nonce",
			  &repnonce, &repnoncelen);
  if (res != SHISHI_OK)
    {
      free (reqnonce);
      shishi_error_printf (handle, "Could not read reply nonce: %s\n",
			   shishi_strerror (res));
      return res;
    }

  res = shishi_kdc_check_nonce_1 (handle, reqnonce, reqnoncelen,
				  repnonce, repnoncelen);

  free (reqnonce);
  free (repnonce);

  return res;
}

/**
 * shishi_tgs_process:
 * @handle: Shishi handle as allocated by shishi_init().
 * @tgsreq: Input variable holding the transmitted KDC-REQ.
 * @tgsrep: Input variable holding the received KDC-REP.
 * @authenticator: Input variable with an authenticator extracted
 *   from the AP-REQ part of @tgsreq.
 * @oldenckdcreppart: Input variable with EncKDCRepPart used
 *   in the request.
 * @enckdcreppart: Output variable holding the new EncKDCRepPart.
 *
 * Processes a TGS client exchange and outputs the decrypted
 * EncKDCRepPart, holding details about the received ticket.
 * This function simply derives the encryption key from the
 * ticket used to construct the original TGS request, and then
 * calls shishi_kdc_process().
 *
 * Return value: Returns %SHISHI_OK if the TGS client exchange
 *   was successful.  Failures include ASN.1 and TGS conditions.
 **/
int
shishi_tgs_process (Shishi * handle,
		    Shishi_asn1 tgsreq,
		    Shishi_asn1 tgsrep,
		    Shishi_asn1 authenticator,
		    Shishi_asn1 oldenckdcreppart, Shishi_asn1 * enckdcreppart)
{
  Shishi_key *tktkey;
  Shishi_key *subkey;
  int use_subkey;
  int etype;
  int res;

  res = shishi_kdcrep_get_enc_part_etype (handle, tgsrep, &etype);
  if (res != SHISHI_OK)
    return res;

  res = shishi_authenticator_get_subkey (handle, authenticator, &subkey);
  use_subkey = (res != SHISHI_ASN1_NO_ELEMENT);
  if (res != SHISHI_OK && res != SHISHI_ASN1_NO_ELEMENT)
    return res;

  res = shishi_enckdcreppart_get_key (handle, oldenckdcreppart, &tktkey);
  if (res != SHISHI_OK)
    return res;

  if (etype != shishi_key_type (use_subkey ? subkey : tktkey))
    res = SHISHI_TGSREP_BAD_KEYTYPE;
  else
    res = shishi_kdc_process (handle, tgsreq, tgsrep,
			      use_subkey ? subkey : tktkey,
			      use_subkey ?
			      SHISHI_KEYUSAGE_ENCTGSREPPART_AUTHENTICATOR_KEY
			      : SHISHI_KEYUSAGE_ENCTGSREPPART_SESSION_KEY,
			      enckdcreppart);

  /* Entire if statement to work around buggy KDCs. */
  if (use_subkey && (res == SHISHI_CRYPTO_ERROR ||
		     res == SHISHI_TGSREP_BAD_KEYTYPE))
    {
      int tmpres;

      /* Try again using key from ticket instead of subkey */
      if (etype != shishi_key_type (tktkey))
	tmpres = SHISHI_TGSREP_BAD_KEYTYPE;
      else
	tmpres = shishi_kdc_process (handle, tgsreq, tgsrep, tktkey,
				     SHISHI_KEYUSAGE_ENCTGSREPPART_SESSION_KEY,
				     enckdcreppart);

      /* if bug workaround code didn't help, return original error. */
      if (tmpres != SHISHI_OK)
	return res;

      shishi_warn (handle, "KDC bug: Reply encrypted using wrong key.");

      res = tmpres;
    }

  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_as_process:
 * @handle: Shishi handle as allocated by shishi_init().
 * @asreq: Input variable holding the transmitted KDC-REQ.
 * @asrep: Input variable holding the received KDC-REP.
 * @string: Input variable with a null terminated password.
 * @enckdcreppart: Output variable returning a new EncKDCRepPart.
 *
 * Processes an AS client exchange and returns the decrypted
 * EncKDCRepPart, holding details about the received ticket.
 * This function simply derives the encryption key from the
 * password, and then calls shishi_kdc_process().
 *
 * Return value: Returns %SHISHI_OK if the AS client exchange was
 *   successful.  Multiple failure conditions are possible.
 **/
int
shishi_as_process (Shishi * handle,
		   Shishi_asn1 asreq,
		   Shishi_asn1 asrep,
		   const char *string, Shishi_asn1 * enckdcreppart)
{
  char *salt;
  size_t saltlen;
  int res;
  Shishi_key *key;
  int keytype;

  res = shishi_as_derive_salt (handle, asreq, asrep, &salt, &saltlen);
  if (res != SHISHI_OK)
    return res;

  res = shishi_kdcrep_get_enc_part_etype (handle, asrep, &keytype);
  if (res != SHISHI_OK)
    return res;

  res = shishi_key_from_string (handle, keytype,
				string, strlen (string),
				salt, saltlen, NULL, &key);
  if (res != SHISHI_OK)
    return res;

  if (VERBOSENOISE (handle))
    shishi_key_print (handle, stderr, key);

  res = shishi_kdc_process (handle, asreq, asrep, key,
			    SHISHI_KEYUSAGE_ENCASREPPART, enckdcreppart);

  return res;
}

/**
 * shishi_kdc_process:
 * @handle: Shishi handle as allocated by shishi_init().
 * @kdcreq: Input variable holding the transmitted KDC-REQ.
 * @kdcrep: Input variable holding the received KDC-REP.
 * @key: Input pointet to key for decrypting parts of @kdcrep.
 * @keyusage: Kerberos key usage code.
 * @enckdcreppart: Output pointer for the extracted EncKDCRepPart.
 *
 * Processes a KDC client exchange and extracts a decrypted
 * EncKDCRepPart, holding details about the received ticket.
 * Use shishi_kdcrep_get_ticket() to extract the ticket itself.
 * This function verifies the various conditions that must hold
 * if the response is to be considered valid.  In particular,
 * it compares nonces (using shishi_kdc_check_nonce()), and if
 * the exchange was an AS exchange, it also checks cname and
 * crealm (using shishi_as_check_cname(), shishi_as_check_crealm()).
 *
 * Usually shishi_as_process() and shishi_tgs_process() should be
 * used instead of this call, since they simplify computation of
 * the decryption key.
 *
 * Return value: Returns %SHISHI_OK if the KDC client exchange was
 * successful.  Multiple failure conditions are possible.
 **/
int
shishi_kdc_process (Shishi * handle,
		    Shishi_asn1 kdcreq,
		    Shishi_asn1 kdcrep,
		    Shishi_key * key, int keyusage,
		    Shishi_asn1 * enckdcreppart)
{
  int res;
  int msgtype;

  /*
     If the reply message type is KRB_AS_REP, then the client verifies
     that the cname and crealm fields in the cleartext portion of the
     reply match what it requested. If any padata fields are present,
     they may be used to derive the proper secret key to decrypt the
     message. The client decrypts the encrypted part of the response
     using its secret key, verifies that the nonce in the encrypted
     part matches the nonce it supplied in its request (to detect
     replays). It also verifies that the sname and srealm in the
     response match those in the request (or are otherwise expected
     values), and that the host address field is also correct. It then
     stores the ticket, session key, start and expiration times, and
     other information for later use. The key-expiration field from the
     encrypted part of the response may be checked to notify the user
     of impending key expiration (the client program could then suggest
     remedial action, such as a password change).
   */

  msgtype = 0;
  res = shishi_asn1_read_integer (handle, kdcrep, "msg-type", &msgtype);
  if (res != SHISHI_OK)
    return res;

  if (msgtype == SHISHI_MSGTYPE_AS_REP)
    {
      res = shishi_as_check_crealm (handle, kdcreq, kdcrep);
      if (res != SHISHI_OK)
	return res;

      res = shishi_as_check_cname (handle, kdcreq, kdcrep);
      if (res != SHISHI_OK)
	return res;
    }

  res = shishi_kdcrep_decrypt (handle, kdcrep, key, keyusage, enckdcreppart);
  if (res != SHISHI_OK)
    return res;

  res = shishi_kdc_check_nonce (handle, kdcreq, *enckdcreppart);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}
