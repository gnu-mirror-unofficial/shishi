/* kdc.c	Key distribution (AS/TGS) functions
 * Copyright (C) 2002  Simon Josefsson
 *
 * This file is part of Shishi.
 *
 * Shishi is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * Shishi is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with Shishi; if not, write to the Free Software
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
		       ASN1_TYPE asreq,
		       ASN1_TYPE asrep, char *salt, int *saltlen)
{
  int len = *saltlen;
  int tmplen;
  unsigned char format[BUFSIZ];
  int res = ASN1_SUCCESS;
  char buf[BUFSIZ];
  int i, n;

  res = asn1_number_of_elements (asrep, "KDC-REP.padata", &n);
  if (res == ASN1_ELEMENT_NOT_FOUND)
    {
      n = 0;
    }
  else if (res != ASN1_SUCCESS)
    {
      shishi_error_set (handle, libtasn1_strerror (res));
      return SHISHI_ASN1_ERROR;
    }

  for (i = 1; i <= n; i++)
    {
      int patype;
      int patypelen;

      sprintf (format, "KDC-REP.padata.?%d.padata-type", i);
      patypelen = sizeof (patype);
      res = asn1_read_value (asrep, format, &patype, &patypelen);
      if (res != ASN1_SUCCESS)
	{
	  shishi_error_set (handle, libtasn1_strerror (res));
	  return SHISHI_ASN1_ERROR;
	}

      if (patype == SHISHI_PA_PW_SALT)
	{
	  sprintf (format, "KDC-REP.padata.?%d.padata-value", i);
	  res = asn1_read_value (asrep, format, salt, saltlen);
	  if (res != ASN1_SUCCESS)
	    {
	      shishi_error_set (handle, libtasn1_strerror (res));
	      return SHISHI_ASN1_ERROR;
	    }
	  return SHISHI_OK;
	}
    }

  len = *saltlen;
  res = asn1_read_value (asreq, "KDC-REQ.req-body.realm", salt, &len);
  if (res != ASN1_SUCCESS)
    {
      shishi_error_set (handle, libtasn1_strerror (res));
      return SHISHI_ASN1_ERROR;
    }

  res =
    asn1_number_of_elements (asreq, "KDC-REQ.req-body.cname.name-string", &n);
  if (res != ASN1_SUCCESS)
    {
      shishi_error_set (handle, libtasn1_strerror (res));
      return SHISHI_ASN1_ERROR;
    }

  for (i = 1; i <= n; i++)
    {
      tmplen = *saltlen - len;
      if (tmplen < 0)
	return SHISHI_TOO_SMALL_BUFFER;

      sprintf (format, "KDC-REQ.req-body.cname.name-string.?%d", i);
      res = asn1_read_value (asreq, format, salt + len, &tmplen);
      if (res != ASN1_SUCCESS)
	{
	  shishi_error_set (handle, libtasn1_strerror (res));
	  return SHISHI_ASN1_ERROR;
	}
      len += tmplen;
    }

  *saltlen = len;

  return SHISHI_OK;
}

int
shishi_kdcreq_sendrecv (Shishi * handle, ASN1_TYPE kdcreq, ASN1_TYPE * kdcrep)
{
  char der[BUFSIZ];		/* XXX dynamically allocate this */
  int der_len, out_len;
  char realm[BUFSIZ];		/* XXX dynamically allocate this */
  int realmlen;
  int res;
  char errorDescription[MAX_ERROR_DESCRIPTION_SIZE];

  res = asn1_der_coding (kdcreq, "KDC-REQ", der, &der_len, errorDescription);
  if (res != ASN1_SUCCESS)
    {
      shishi_error_printf (handle, "Could not DER encode AS-REQ: %s\n",
			   errorDescription);
      return !SHISHI_OK;
    }

  realmlen = sizeof(realm);
  res = _shishi_asn1_field (handle, kdcreq, realm, &realmlen, "KDC-REQ.req-body.realm");
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "Could not get realm: %s\n",
			   shishi_strerror_details (handle));
      return !SHISHI_OK;
    }
  realm[realmlen] = '\0';

  out_len = BUFSIZ;
  res = shishi_kdc_sendrecv (handle, realm, der, der_len, der, &out_len);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "Could not send to KDC: %s\n",
			   shishi_strerror_details (handle));
      return !SHISHI_OK;
    }
  der_len = out_len;

  if (DEBUGASN1(handle))
    printf ("received %d bytes\n", der_len);

  *kdcrep = shishi_der2asn1_as_rep (handle->asn1, der,
				    der_len, errorDescription);
  if (*kdcrep == ASN1_TYPE_EMPTY)
    {
      *kdcrep = shishi_der2asn1_tgs_rep (handle->asn1, der,
					 der_len, errorDescription);
      if (*kdcrep == ASN1_TYPE_EMPTY)
	{
	  *kdcrep = shishi_der2asn1_kdc_rep (handle->asn1, der,
					     der_len, errorDescription);
	  if (*kdcrep == ASN1_TYPE_EMPTY)
	    {
	      *kdcrep = shishi_der2asn1_krb_error (handle->asn1, der,
						   der_len, errorDescription);
	      if (*kdcrep == ASN1_TYPE_EMPTY)
		{
		  shishi_error_printf
		    (handle, "Could not DER decode AS-REP/KRB-ERROR: %s",
		     errorDescription);
		  return !SHISHI_OK;
		}

	      shishi_error_printf
		(handle, "Received KRB-ERROR. if tgs, try --short-nonce");

	      return !SHISHI_OK;
	    }
	  else
	    {
	      printf ("Buggy server replied with KDC-REP instead of AS-REP\n");
	    }
	}
    }

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
shishi_as_check_crealm (Shishi * handle, ASN1_TYPE asreq, ASN1_TYPE asrep)
{
  unsigned char reqrealm[BUFSIZ], reprealm[BUFSIZ];
  int reqrealmlen = BUFSIZ, reprealmlen = BUFSIZ;
  int res;

  res = asn1_read_value (asreq, "KDC-REQ.req-body.realm",
			 reqrealm, &reqrealmlen);
  if (res != ASN1_SUCCESS)
    {
      shishi_error_printf (handle, "Could not read request realm: %s\n",
			   libtasn1_strerror (res));
      return SHISHI_ASN1_ERROR;
    }

  res = asn1_read_value (asrep, "KDC-REP.crealm", reprealm, &reprealmlen);
  if (res != ASN1_SUCCESS)
    {
      shishi_error_printf (handle, "Could not read reply realm: %s\n",
			   libtasn1_strerror (res));
      return SHISHI_ASN1_ERROR;
    }

  reqrealm[reqrealmlen] = '\0';
  reprealm[reprealmlen] = '\0';

  if (DEBUGASN1(handle))
    {
      printf ("request realm: %s\n", reqrealm);
      printf ("reply realm: %s\n", reprealm);
    }

  if (strcmp (reqrealm, reprealm) != 0)
    return SHISHI_REALM_MISMATCH;

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
shishi_as_check_cname (Shishi * handle, ASN1_TYPE asreq, ASN1_TYPE asrep)
{
  char reqcname[BUFSIZ], repcname[BUFSIZ];
  int reqcnamelen, repcnamelen;
  char format[BUFSIZ];
  int res;
  int i, j;

  /* We do not compare msg-type as recommended on the ietf-krb-wg list */

  res =
    asn1_number_of_elements (asreq, "KDC-REQ.req-body.cname.name-string", &i);
  if (res != ASN1_SUCCESS)
    {
      shishi_error_set (handle, libtasn1_strerror (res));
      return SHISHI_ASN1_ERROR;
    }

  res = asn1_number_of_elements (asrep, "KDC-REP.cname.name-string", &j);
  if (res != ASN1_SUCCESS)
    {
      shishi_error_set (handle, libtasn1_strerror (res));
      return SHISHI_ASN1_ERROR;
    }

  if (i != j)
    return SHISHI_CNAME_MISMATCH;

  for (i = 1; i <= j; i++)
    {
      sprintf (format, "KDC-REQ.req-body.cname.name-string.?%d", i);
      reqcnamelen = sizeof (reqcname);
      res = asn1_read_value (asreq, format, reqcname, &reqcnamelen);
      if (res != ASN1_SUCCESS)
	{
	  shishi_error_set (handle, libtasn1_strerror (res));
	  return SHISHI_ASN1_ERROR;
	}

      sprintf (format, "KDC-REP.cname.name-string.?%d", i);
      repcnamelen = sizeof (repcname);
      res = asn1_read_value (asrep, format, repcname, &repcnamelen);
      if (res != ASN1_SUCCESS)
	{
	  shishi_error_set (handle, libtasn1_strerror (res));
	  return SHISHI_ASN1_ERROR;
	}

      if (DEBUGASN1(handle))
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
 * shishi_kdc_check_nonce:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcreq: KDC-REQ to compare nonce field in.
 * @enckdcreppart: Encrypted KDC-REP part to compare nonce field in.
 * 
 * Verify that KDC-REQ.req-body.nonce and EncKDCRepPart.nonce fields
 * matches.  This is one of the steps that has to be performed when
 * processing a KDC-REQ and KDC-REP exchange.
 *
 * If the "shortnonceworkaround" variable is set in the handle, this
 * function accepts truncated nonces in the response after printing an
 * warning to stderr. (Specifically, if the sent nonce was longer than
 * 4 byte and the received nonce 4 bytes and matched the last 4 bytes
 * of the sent nonce, it is accepted.)
 *
 * Return value: Returns SHISHI_OK if successful,
 * SHISHI_NONCE_LENGTH_MISMATCH if the nonces have different lengths
 * (usually indicates that buggy server truncated nonce to 4 bytes),
 * SHISHI_NONCE_MISMATCH if the values differ, or an error code.
 **/
int
shishi_kdc_check_nonce (Shishi * handle,
			ASN1_TYPE kdcreq, ASN1_TYPE enckdcreppart)
{
  unsigned char reqnonce[BUFSIZ];
  unsigned char repnonce[BUFSIZ];
  int reqnoncelen = BUFSIZ;
  int repnoncelen = BUFSIZ;
  int res;

  res = asn1_read_value (kdcreq, "KDC-REQ.req-body.nonce",
			 reqnonce, &reqnoncelen);
  if (res != ASN1_SUCCESS)
    {
      shishi_error_printf (handle, "Could not read request nonce: %s\n",
			   libtasn1_strerror (res));
      return SHISHI_ASN1_ERROR;
    }

  res = asn1_read_value (enckdcreppart, "EncKDCRepPart.nonce",
			 repnonce, &repnoncelen);
  if (res != ASN1_SUCCESS)
    {
      shishi_error_printf (handle, "Could not read reply nonce: %s\n",
			   libtasn1_strerror (res));
      return SHISHI_ASN1_ERROR;
    }

  if (DEBUGASN1(handle))
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

  if (handle->shortnonceworkaround && repnoncelen == 4 && reqnoncelen > 4)
    {
      fprintf (stderr, "warning: buggy server truncated nonce to 4 bytes\n");
      if (memcmp (reqnonce + reqnoncelen - 4, repnonce, 4) != 0)
	return SHISHI_NONCE_MISMATCH;

      return SHISHI_OK;
    }

  if (reqnoncelen != repnoncelen)
    return SHISHI_NONCE_LENGTH_MISMATCH;

  if (memcmp (reqnonce, repnonce, repnoncelen) != 0)
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
		    ASN1_TYPE tgsreq,
		    ASN1_TYPE tgsrep,
		    ASN1_TYPE oldenckdcreppart, ASN1_TYPE * enckdcreppart)
{
  unsigned char key[BUFSIZ];
  int keylen;
  int etype, keytype;
  int res;

  res = shishi_kdcrep_get_enc_part_etype (handle, tgsrep, &etype);
  if (res != SHISHI_OK)
    return res;

  keylen = sizeof (key);
  res = shishi_enckdcreppart_get_key (handle, oldenckdcreppart,
				      &keytype, key, &keylen);
  if (res != SHISHI_OK)
    return res;

  if (etype != keytype)
    return SHISHI_TGSREP_BAD_KEYTYPE;

  res = shishi_kdc_process (handle, tgsreq, tgsrep, 
			    SHISHI_KEYUSAGE_ENCTGSREPPART_SESSION_KEY, keytype,
			    key, keylen, enckdcreppart);

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
		   ASN1_TYPE asreq,
		   ASN1_TYPE asrep, char *string, ASN1_TYPE * enckdcreppart)
{
  unsigned char format[BUFSIZ];
  unsigned char salt[BUFSIZ];
  int saltlen;
  int res;
  unsigned char key[BUFSIZ];
  int keylen;
  int keytype;

  saltlen = sizeof (salt);
  res = shishi_as_derive_salt (handle, asreq, asrep, salt, &saltlen);
  if (res != SHISHI_OK)
    return res;

  res = shishi_kdcrep_get_enc_part_etype (handle, asrep, &keytype);
  if (res != SHISHI_OK)
    return res;

  keylen = sizeof (key);
  res = shishi_string_to_key (handle, keytype,
			      string, strlen (string),
			      salt, saltlen, NULL, key, &keylen);
  if (res != SHISHI_OK)
    return res;

  res = shishi_kdc_process (handle, asreq, asrep,
			    SHISHI_KEYUSAGE_ENCASREPPART, keytype, key, keylen,
			    enckdcreppart);

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
		    ASN1_TYPE kdcreq,
		    ASN1_TYPE kdcrep,
		    int keyusage,
		    int keytype,
		    char *key, int keylen, ASN1_TYPE * enckdcreppart)
{
  int res;
  int i, len;
  int buflen = BUFSIZ;
  unsigned char buf[BUFSIZ];
  unsigned char cipher[BUFSIZ];
  int realmlen = BUFSIZ;
  int cipherlen;
  unsigned char etype;
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
  len = sizeof (msgtype);
  res =
    _shishi_asn1_field (handle, kdcrep, &msgtype, &len, "KDC-REP.msg-type");
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

  res = shishi_kdcrep_decrypt (handle, kdcrep, keyusage, keytype, key, keylen, 
			       enckdcreppart);
  if (res != SHISHI_OK)
    return res;

  res = shishi_kdc_check_nonce (handle, kdcreq, *enckdcreppart);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}
