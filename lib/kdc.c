/* kdc.c	Key distribution (AS/TGS) functions
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

#include "internal.h"

/**
 * shishi_as_derive_salt:
 * @handle: shishi handle as allocated by shishi_init().
 * @asrep: input AS-REP variable.
 * @asrep: input AS-REP variable.
 * @salt: output array with salt.
 * @saltlen: on input, maximum size of output array with salt, on output,
 *           holds actual size of output array with salt.
 *
 * Derive the salt that should be used when deriving a key via
 * shishi_string_to_key() for an AS exchange.  Currently this searches
 * for PA-DATA of type SHISHI_PA_PW_SALT in the AS-REP and returns it
 * if found, otherwise the salt is derived from the client name and
 * realm in AS-REQ.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_as_derive_salt (Shishi * handle,
		       Shishi_asn1 asreq,
		       Shishi_asn1 asrep, char *salt, size_t * saltlen)
{
  int len = *saltlen;
  int tmplen;
  char *format;
  int res;
  int i, n;

  res = shishi_asn1_number_of_elements (handle, asrep, "padata", &n);
  if (res == SHISHI_ASN1_NO_ELEMENT)
    n = 0;
  else if (res != SHISHI_OK)
    return res;

  for (i = 1; i <= n; i++)
    {
      int patype;

      asprintf (&format, "padata.?%d.padata-type", i);
      res = shishi_asn1_read_int32 (handle, asrep, format, &patype);
      free (format);
      if (res != SHISHI_OK)
	return res;

      if (patype == SHISHI_PA_PW_SALT)
	{
	  asprintf (&format, "padata.?%d.padata-value", i);
	  res = shishi_asn1_read (handle, asrep, format, salt, saltlen);
	  free (format);
	  if (res != SHISHI_OK)
	    return res;

	  return SHISHI_OK;
	}
    }

  len = *saltlen;
  res = shishi_asn1_read (handle, asreq, "req-body.realm", salt, &len);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_number_of_elements (handle, asreq,
					"req-body.cname.name-string", &n);
  if (res != SHISHI_OK)
    return res;

  for (i = 1; i <= n; i++)
    {
      tmplen = *saltlen - len;
      if (tmplen < 0)
	return SHISHI_TOO_SMALL_BUFFER;

      asprintf (&format, "req-body.cname.name-string.?%d", i);
      res = shishi_asn1_read (handle, asreq, format, salt + len, &tmplen);
      free (format);
      if (res != SHISHI_OK)
	return res;

      len += tmplen;
    }

  *saltlen = len;

  return SHISHI_OK;
}

int
shishi_kdcreq_sendrecv (Shishi * handle, Shishi_asn1 kdcreq,
			Shishi_asn1 * kdcrep)
{
  char *der;
  int der_len, out_len;
  char buffer[BUFSIZ];		/* XXX dynamically allocate this? */
  char realm[BUFSIZ];		/* XXX dynamically allocate this */
  int realmlen;
  int res;

  res = shishi_new_a2d (handle, kdcreq, &der, &der_len);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "Could not DER encode AS-REQ: %s\n",
			   shishi_strerror (res));
      return res;
    }

  realmlen = sizeof (realm);
  res = shishi_asn1_field (handle, kdcreq, realm, &realmlen,
			   "req-body.realm");
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "Could not get realm: %s\n",
			   shishi_strerror_details (handle));
      return res;
    }
  realm[realmlen] = '\0';

  out_len = sizeof (buffer);
  res = shishi_kdc_sendrecv (handle, realm, der, der_len, buffer, &out_len);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "Could not send to KDC: %s\n",
			   shishi_strerror_details (handle));
      return res;
    }
  free (der);

  if (VERBOSEASN1 (handle))
    printf ("received %d bytes\n", out_len);

  *kdcrep = shishi_der2asn1_asrep (handle, buffer, out_len);
  if (*kdcrep == NULL)
    {
      *kdcrep = shishi_der2asn1_tgsrep (handle, buffer, out_len);
      if (*kdcrep == NULL)
	{
	  *kdcrep = shishi_der2asn1_kdcrep (handle, buffer, out_len);
	  if (*kdcrep == NULL)
	    {
	      *kdcrep = shishi_der2asn1_krberror (handle, buffer, out_len);
	      if (*kdcrep == NULL)
		{
		  shishi_error_printf
		    (handle, "Could not DER decode AS-REP/KRB-ERROR: %s",
		     shishi_strerror_details (handle));
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

  return SHISHI_OK;
}

/**
 * shishi_kdc_copy_crealm:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcreq: KDC-REQ to read crealm from.
 * @encticketpart: EncTicketPart to set crealm in.
 *
 * Set crealm in KDC-REP to value in EncTicketPart.
 *
 * Return value: Returns SHISHI_OK if successful.
 **/
int
shishi_kdc_copy_crealm (Shishi * handle,
			Shishi_asn1 kdcrep, Shishi_asn1 encticketpart)
{
  unsigned char buf[BUFSIZ];
  int buflen;
  int res;

  buf[0] = '\0';		/* XXX if crealm is empty, buflen == 0 which
				   causes libtasn1 to strlen(buf)... */
  buflen = BUFSIZ;
  res = shishi_asn1_read (handle, encticketpart, "crealm", buf, &buflen);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_write (handle, kdcrep, "crealm", buf, buflen);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_as_check_crealm:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcreq: AS-REQ to compare realm field in.
 * @kdcrep: AS-REP to compare realm field in.
 *
 * Verify that AS-REQ.req-body.realm and AS-REP.crealm fields matches.
 * This is one of the steps that has to be performed when processing a
 * AS-REQ and AS-REP exchange, see shishi_kdc_process().
 *
 * Return value: Returns SHISHI_OK if successful,
 * SHISHI_REALM_MISMATCH if the values differ, or an error code.
 **/
int
shishi_as_check_crealm (Shishi * handle, Shishi_asn1 asreq, Shishi_asn1 asrep)
{
  char reqrealm[BUFSIZ], reprealm[BUFSIZ];
  int reqrealmlen = BUFSIZ, reprealmlen = BUFSIZ;
  int res;

  res = shishi_asn1_read (handle, asreq, "req-body.realm",
			  reqrealm, &reqrealmlen);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "Could not read request realm: %s\n",
			   shishi_strerror (res));
      return res;
    }

  res = shishi_asn1_read (handle, asrep, "crealm", reprealm, &reprealmlen);
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

  if (strcmp (reqrealm, reprealm) != 0)
    return SHISHI_REALM_MISMATCH;

  return SHISHI_OK;
}

/**
 * shishi_kdc_copy_crealm:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcreq: KDC-REQ to read cname from.
 * @encticketpart: EncTicketPart to set cname in.
 *
 * Set cname in KDC-REP to value in EncTicketPart.
 *
 * Return value: Returns SHISHI_OK if successful.
 **/
int
shishi_kdc_copy_cname (Shishi * handle,
		       Shishi_asn1 kdcrep, Shishi_asn1 encticketpart)
{
  unsigned char buf[BUFSIZ];
  char format[BUFSIZ];
  int buflen;
  int res;
  int i, n;

  buflen = BUFSIZ;
  res = shishi_asn1_read (handle, encticketpart,
			  "cname.name-type", buf, &buflen);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_write (handle, kdcrep, "cname.name-type", buf, buflen);
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

      sprintf (format, "cname.name-string.?%d", i);
      buflen = BUFSIZ;
      res = shishi_asn1_read (handle, encticketpart, format, buf, &buflen);
      if (res != SHISHI_OK)
	return res;

      sprintf (format, "cname.name-string.?%d", i);
      res = shishi_asn1_write (handle, kdcrep, format, buf, buflen);
      if (res != SHISHI_OK)
	return res;
    }

  return SHISHI_OK;
}

/**
 * shishi_as_check_cname:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcreq: AS-REQ to compare client name field in.
 * @kdcrep: AS-REP to compare client name field in.
 *
 * Verify that AS-REQ.req-body.realm and AS-REP.crealm fields matches.
 * This is one of the steps that has to be performed when processing a
 * AS-REQ and AS-REP exchange, see shishi_kdc_process().
 *
 * Return value: Returns SHISHI_OK if successful,
 * SHISHI_CNAME_MISMATCH if the values differ, or an error code.
 **/
int
shishi_as_check_cname (Shishi * handle, Shishi_asn1 asreq, Shishi_asn1 asrep)
{
  char reqcname[BUFSIZ], repcname[BUFSIZ];
  int reqcnamelen, repcnamelen;
  char format[BUFSIZ];
  int res;
  int i, j;

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
      sprintf (format, "req-body.cname.name-string.?%d", i);
      reqcnamelen = sizeof (reqcname);
      res = shishi_asn1_read (handle, asreq, format, reqcname, &reqcnamelen);
      if (res != SHISHI_OK)
	return res;

      sprintf (format, "cname.name-string.?%d", i);
      repcnamelen = sizeof (repcname);
      res = shishi_asn1_read (handle, asrep, format, repcname, &repcnamelen);
      if (res != SHISHI_OK)
	return res;

      if (VERBOSEASN1 (handle))
	{
	  reqcname[reqcnamelen] = '\0';
	  repcname[repcnamelen] = '\0';
	  printf ("request cname %d: %s\n", i, reqcname);
	  printf ("reply cname %d: %s\n", i, repcname);
	}

      if (reqcnamelen != repcnamelen)
	return SHISHI_CNAME_MISMATCH;

      if (memcmp (reqcname, repcname, reqcnamelen) != 0)
	return SHISHI_CNAME_MISMATCH;
    }

  return SHISHI_OK;
}

/**
 * shishi_kdc_copy_nonce:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcreq: KDC-REQ to read nonce from.
 * @enckdcreppart: EncKDCRepPart to set nonce in.
 *
 * Set nonce in EncKDCRepPart to value in KDC-REQ.
 *
 * Return value: Returns SHISHI_OK if successful.
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

/**
 * shishi_kdc_check_nonce:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcreq: KDC-REQ to compare nonce field in.
 * @enckdcreppart: Encrypted KDC-REP part to compare nonce field in.
 *
 * Verify that KDC-REQ.req-body.nonce and EncKDCRepPart.nonce fields
 * matches.  This is one of the steps that has to be performed when
 * processing a KDC-REQ and KDC-REP exchange.
 *
 * Return value: Returns SHISHI_OK if successful,
 * SHISHI_NONCE_LENGTH_MISMATCH if the nonces have different lengths
 * (usually indicates that buggy server truncated nonce to 4 bytes),
 * SHISHI_NONCE_MISMATCH if the values differ, or an error code.
 **/
int
shishi_kdc_check_nonce (Shishi * handle,
			Shishi_asn1 kdcreq, Shishi_asn1 enckdcreppart)
{
  unsigned char reqnonce[BUFSIZ];
  unsigned char repnonce[BUFSIZ];
  int reqnoncelen = BUFSIZ;
  int repnoncelen = BUFSIZ;
  int res;

  res = shishi_asn1_read (handle, kdcreq, "req-body.nonce",
			  reqnonce, &reqnoncelen);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "Could not read request nonce: %s\n",
			   shishi_strerror (res));
      return res;
    }

  res = shishi_asn1_read (handle, enckdcreppart, "nonce",
			  repnonce, &repnoncelen);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "Could not read reply nonce: %s\n",
			   shishi_strerror (res));
      return res;
    }

  if (VERBOSEASN1 (handle))
    {
      int i;

      printf ("request nonce (len=%d) ", reqnoncelen);
      for (i = 0; i < reqnoncelen; i++)
	printf ("%02X", reqnonce[i]);
      printf ("\n");
      printf ("reply nonce (len=%d) ", repnoncelen);
      for (i = 0; i < repnoncelen; i++)
	printf ("%02X", repnonce[i]);
      printf ("\n");
    }

  if (reqnoncelen > 4 && repnoncelen == 4)
    {
      /* This case warrants some explanation.
       *
       * RFC 1510 didn't restrict nonce to 4 bytes, so the nonce field
       * may be longer. There are KDCs that will accept longer nonces
       * but truncated them to 4 bytes in the response.  If we happen
       * to parse such a KDC request, we consider it OK even though it
       * isn't.  I doubt this is a security problem, because you need
       * to break the integrity protection of the encryption system
       * as well as guess the nonce correctly.  The nonce doesn't seem
       * to serve any purpose at all, really.
       *
       */

      if (memcmp (reqnonce + reqnoncelen - 4, repnonce, 4) != 0)
	return SHISHI_NONCE_MISMATCH;

      fprintf (stderr, "warning: server truncated long nonce to 4 bytes\n");

      return SHISHI_OK;
    }

  if (reqnoncelen != repnoncelen ||
      memcmp (reqnonce, repnonce, repnoncelen) != 0)
    return SHISHI_NONCE_MISMATCH;

  return SHISHI_OK;
}

/**
 * shishi_tgs_process:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcreq: input variable that holds the sent KDC-REQ.
 * @kdcrep: input variable that holds the received KDC-REP.
 * @oldenckdcreppart: input variable with EncKDCRepPart used in request.
 * @enckdcreppart: output variable that holds new EncKDCRepPart.
 *
 * Process a TGS client exchange and output decrypted EncKDCRepPart
 * which holds details for the new ticket received.  This function
 * simply derives the encryption key from the ticket used to construct
 * the TGS request and calls shishi_kdc_process(), which see.
 *
 * Return value: Returns SHISHI_OK iff the TGS client exchange was
 * successful.
 **/
int
shishi_tgs_process (Shishi * handle,
		    Shishi_asn1 tgsreq,
		    Shishi_asn1 tgsrep,
		    Shishi_asn1 oldenckdcreppart, Shishi_asn1 * enckdcreppart)
{
  Shishi_key *key;
  int etype;
  int res;

  res = shishi_kdcrep_get_enc_part_etype (handle, tgsrep, &etype);
  if (res != SHISHI_OK)
    return res;

  res = shishi_enckdcreppart_get_key (handle, oldenckdcreppart, &key);
  if (res != SHISHI_OK)
    return res;

  if (etype != shishi_key_type (key))
    return SHISHI_TGSREP_BAD_KEYTYPE;

  res = shishi_kdc_process (handle, tgsreq, tgsrep, key,
			    SHISHI_KEYUSAGE_ENCTGSREPPART_SESSION_KEY,
			    enckdcreppart);

  return res;
}

/**
 * shishi_as_process:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcreq: input variable that holds the sent KDC-REQ.
 * @kdcrep: input variable that holds the received KDC-REP.
 * @string: input variable with zero terminated password.
 * @enckdcreppart: output variable that holds new EncKDCRepPart.
 *
 * Process an AS client exchange and output decrypted EncKDCRepPart
 * which holds details for the new ticket received.  This function
 * simply derives the encryption key from the password and calls
 * shishi_kdc_process(), which see.
 *
 * Return value: Returns SHISHI_OK iff the AS client exchange was
 * successful.
 **/
int
shishi_as_process (Shishi * handle,
		   Shishi_asn1 asreq,
		   Shishi_asn1 asrep,
		   const char *string, Shishi_asn1 * enckdcreppart)
{
  unsigned char salt[BUFSIZ];
  int saltlen;
  int res;
  Shishi_key *key;
  int keytype;

  saltlen = sizeof (salt);
  res = shishi_as_derive_salt (handle, asreq, asrep, salt, &saltlen);
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

  if (VERBOSENOICE (handle))
    shishi_key_print (handle, stderr, key);

  res = shishi_kdc_process (handle, asreq, asrep, key,
			    SHISHI_KEYUSAGE_ENCASREPPART, enckdcreppart);

  return res;
}

/**
 * shishi_kdc_process:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcreq: input variable that holds the sent KDC-REQ.
 * @kdcrep: input variable that holds the received KDC-REP.
 * @keytype: input variable that holds type of key.
 * @key: input array with key to decrypt encrypted part of KDC-REP with.
 * @keylen: size of input array with key.
 * @enckdcreppart: output variable that holds new EncKDCRepPart.
 *
 * Process a KDC client exchange and output decrypted EncKDCRepPart
 * which holds details for the new ticket received.  Use
 * shishi_kdcrep_get_ticket() to extract the ticket.  This function
 * verifies the various conditions that must hold if the response is
 * to be considered valid, specifically it compares nonces
 * (shishi_check_nonces()) and if the exchange was a AS exchange, it
 * also compares cname and crealm (shishi_check_cname() and
 * shishi_check_crealm()).
 *
 * Usually the shishi_as_process() and shishi_tgs_process() functions
 * should be used instead, since they simplify the decryption key
 * computation.
 *
 * Return value: Returns SHISHI_OK iff the KDC client exchange was
 * successful.
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
