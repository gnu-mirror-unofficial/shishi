/* ap.c --- AP functions
 * Copyright (C) 2002, 2003, 2004, 2006, 2007  Simon Josefsson
 *
 * This file is part of Shishi.
 *
 * Shishi is free software; you can redistribute it and/or modify it it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * Shishi is distributed in the hope that it will be useful, but but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Shishi; if not, see http://www.gnu.org/licenses or write
 * to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
 * Floor, Boston, MA 02110-1301, USA
 *
 */

#include "internal.h"

struct Shishi_ap
{
  Shishi *handle;
  Shishi_tkt *tkt;
  Shishi_key *key;
  Shishi_asn1 authenticator;
  Shishi_asn1 apreq;
  Shishi_asn1 aprep;
  Shishi_asn1 encapreppart;
  /* Key usage for encryption entire Authenticator ASN.1 blob, stored
     in AP-REQ. */
  int authenticatorkeyusage;
  /* Key usage for computing checksum of authenticatorcksumdata in the
     Authenticator, in AP-REQ. */
  int authenticatorcksumkeyusage;
  /* Sets the checksum algorithm type in Authenticator, in AP-REQ.  If
     there is data in authenticatorcksumdata to compute a checksum on,
     this also indicate the algorithm to use for this computation. */
  int32_t authenticatorcksumtype;
  /* Auxilliary application data to compute checksum on and store in
     Authenticator, in AP-REQ.  Note that data is not stored in
     AP-REQ, only a checksum of it. */
  char *authenticatorcksumdata;
  size_t authenticatorcksumdatalen;
  /* Raw checksum data to store in Authenticator, in AP-REQ.
     Normally, this is the output of the checksum algorithm computed
     on the data in authenticatorcksumdata, but some applications
     (e.g., GSS-API) put something weird in the checksum field. */
  char *authenticatorcksumraw;
  size_t authenticatorcksumrawlen;
};

/**
 * shishi_ap:
 * @handle: shishi handle as allocated by shishi_init().
 * @ap: pointer to new structure that holds information about AP exchange
 *
 * Create a new AP exchange with a random subkey of the default
 * encryption type from configuration.  Note that there is no
 * guarantee that the receiver will understand that key type, you
 * should probably use shishi_ap_etype() or shishi_ap_nosubkey()
 * instead.  In the future, this function will likely behave as
 * shishi_ap_nosubkey() and shishi_ap_nosubkey() will be removed.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ap (Shishi * handle, Shishi_ap ** ap)
{
  int res;

  res = shishi_ap_nosubkey (handle, ap);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "Could not create Authenticator: %s\n",
			   shishi_error (handle));
      return res;
    }

  res = shishi_authenticator_add_random_subkey (handle, (*ap)->authenticator);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "Could not add random subkey in AP: %s\n",
			   shishi_strerror (res));
      return res;
    }

  return SHISHI_OK;
}

/**
 * shishi_ap_etype:
 * @handle: shishi handle as allocated by shishi_init().
 * @ap: pointer to new structure that holds information about AP exchange
 * @etype: encryption type of newly generated random subkey.
 *
 * Create a new AP exchange with a random subkey of indicated
 * encryption type.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ap_etype (Shishi * handle, Shishi_ap ** ap, int etype)
{
  int res;

  res = shishi_ap_nosubkey (handle, ap);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "Could not create Authenticator: %s\n",
			   shishi_error (handle));
      return res;
    }

  res = shishi_authenticator_add_random_subkey_etype (handle,
						      (*ap)->authenticator,
						      etype);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "Could not add random subkey in AP: %s\n",
			   shishi_strerror (res));
      return res;
    }

  return SHISHI_OK;
}

/**
 * shishi_ap_nosubkey:
 * @handle: shishi handle as allocated by shishi_init().
 * @ap: pointer to new structure that holds information about AP exchange
 *
 * Create a new AP exchange without subkey in authenticator.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ap_nosubkey (Shishi * handle, Shishi_ap ** ap)
{
  Shishi_ap *lap;

  *ap = xcalloc (1, sizeof (**ap));
  lap = *ap;

  lap->handle = handle;
  lap->authenticatorcksumtype = SHISHI_NO_CKSUMTYPE;
  lap->authenticatorcksumkeyusage = SHISHI_KEYUSAGE_APREQ_AUTHENTICATOR_CKSUM;
  lap->authenticatorkeyusage = SHISHI_KEYUSAGE_APREQ_AUTHENTICATOR;

  lap->authenticator = shishi_authenticator (handle);
  if (lap->authenticator == NULL)
    {
      shishi_error_printf (handle, "Could not create Authenticator: %s\n",
			   shishi_error (handle));
      return SHISHI_ASN1_ERROR;
    }

  lap->apreq = shishi_apreq (handle);
  if (lap->apreq == NULL)
    {
      shishi_error_printf (handle, "Could not create AP-REQ: %s\n",
			   shishi_error (handle));
      return SHISHI_ASN1_ERROR;
    }

  lap->aprep = shishi_aprep (handle);
  if (lap->aprep == NULL)
    {
      shishi_error_printf (handle, "Could not create AP-REP: %s\n",
			   shishi_error (handle));
      return SHISHI_ASN1_ERROR;
    }

  lap->encapreppart = shishi_encapreppart (handle);
  if (lap->encapreppart == NULL)
    {
      shishi_error_printf (handle, "Could not create EncAPRepPart: %s\n",
			   shishi_error (handle));
      return SHISHI_ASN1_ERROR;
    }

  return SHISHI_OK;
}

/**
 * shishi_ap_done:
 * @ap: structure that holds information about AP exchange
 *
 * Deallocate resources associated with AP exchange.  This should be
 * called by the application when it no longer need to utilize the AP
 * exchange handle.
 **/
void
shishi_ap_done (Shishi_ap * ap)
{
  if (ap->authenticatorcksumdata)
    free (ap->authenticatorcksumdata);
  if (ap->authenticatorcksumraw)
    free (ap->authenticatorcksumraw);
  shishi_asn1_done (ap->handle, ap->authenticator);
  shishi_asn1_done (ap->handle, ap->apreq);
  shishi_asn1_done (ap->handle, ap->aprep);
  shishi_asn1_done (ap->handle, ap->encapreppart);
  free (ap);
}

/**
 * shishi_ap_set_tktoptions:
 * @ap: structure that holds information about AP exchange
 * @tkt: ticket to set in AP.
 * @options: AP-REQ options to set in AP.
 *
 * Set the ticket (see shishi_ap_tkt_set()) and set the AP-REQ
 * apoptions (see shishi_apreq_options_set()).
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ap_set_tktoptions (Shishi_ap * ap, Shishi_tkt * tkt, int options)
{
  int rc;

  shishi_ap_tkt_set (ap, tkt);

  rc = shishi_apreq_options_set (ap->handle, shishi_ap_req (ap), options);
  if (rc != SHISHI_OK)
    {
      printf ("Could not set AP-Options: %s", shishi_strerror (rc));
      return rc;
    }

  return SHISHI_OK;
}

/**
 * shishi_ap_set_tktoptionsdata:
 * @ap: structure that holds information about AP exchange
 * @tkt: ticket to set in AP.
 * @options: AP-REQ options to set in AP.
 * @data: input array with data to checksum in Authenticator.
 * @len: length of input array with data to checksum in Authenticator.
 *
 * Set the ticket (see shishi_ap_tkt_set()) and set the AP-REQ
 * apoptions (see shishi_apreq_options_set()) and set the
 * Authenticator checksum data.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ap_set_tktoptionsdata (Shishi_ap * ap,
			      Shishi_tkt * tkt,
			      int options, const char *data, size_t len)
{
  int rc;

  shishi_ap_tkt_set (ap, tkt);

  rc = shishi_apreq_options_set (ap->handle, shishi_ap_req (ap), options);
  if (rc != SHISHI_OK)
    {
      printf ("Could not set AP-Options: %s", shishi_strerror (rc));
      return rc;
    }

  shishi_ap_authenticator_cksumdata_set (ap, data, len);

  return SHISHI_OK;
}


/**
 * shishi_ap_set_tktoptionsraw:
 * @ap: structure that holds information about AP exchange
 * @tkt: ticket to set in AP.
 * @options: AP-REQ options to set in AP.
 * @cksumtype: authenticator checksum type to set in AP.
 * @data: input array with data to store in checksum field in Authenticator.
 * @len: length of input array with data to store in checksum field in
 *   Authenticator.
 *
 * Set the ticket (see shishi_ap_tkt_set()) and set the AP-REQ
 * apoptions (see shishi_apreq_options_set()) and set the raw
 * Authenticator checksum data.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ap_set_tktoptionsraw (Shishi_ap * ap,
			     Shishi_tkt * tkt,
			     int options,
			     int32_t cksumtype, const char *data, size_t len)
{
  int rc;

  shishi_ap_tkt_set (ap, tkt);

  rc = shishi_apreq_options_set (ap->handle, shishi_ap_req (ap), options);
  if (rc != SHISHI_OK)
    {
      printf ("Could not set AP-Options: %s", shishi_strerror (rc));
      return rc;
    }

  shishi_ap_authenticator_cksumraw_set (ap, cksumtype, data, len);

  return SHISHI_OK;
}

/**
 * shishi_ap_set_tktoptionsasn1usage:
 * @ap: structure that holds information about AP exchange
 * @tkt: ticket to set in AP.
 * @options: AP-REQ options to set in AP.
 * @node: input ASN.1 structure to store as authenticator checksum data.
 * @field: field in ASN.1 structure to use.
 * @authenticatorcksumkeyusage: key usage for checksum in authenticator.
 * @authenticatorkeyusage: key usage for authenticator.
 *
 * Set ticket, options and authenticator checksum data using
 * shishi_ap_set_tktoptionsdata().  The authenticator checksum data is
 * the DER encoding of the ASN.1 field provided.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ap_set_tktoptionsasn1usage (Shishi_ap * ap,
				   Shishi_tkt * tkt,
				   int options,
				   Shishi_asn1 node,
				   const char *field,
				   int authenticatorcksumkeyusage,
				   int authenticatorkeyusage)
{
  char *buf;
  size_t buflen;
  int res;

  res = shishi_asn1_to_der_field (ap->handle, node, field, &buf, &buflen);
  if (res != SHISHI_OK)
    return res;

  res = shishi_ap_set_tktoptionsdata (ap, tkt, options, buf, buflen);
  if (res != SHISHI_OK)
    return res;

  ap->authenticatorcksumkeyusage = authenticatorcksumkeyusage;
  ap->authenticatorkeyusage = authenticatorkeyusage;

  return SHISHI_OK;
}

/**
 * shishi_ap_tktoptions:
 * @handle: shishi handle as allocated by shishi_init().
 * @ap: pointer to new structure that holds information about AP exchange
 * @tkt: ticket to set in newly created AP.
 * @options: AP-REQ options to set in newly created AP.
 *
 * Create a new AP exchange using shishi_ap(), and set the ticket and
 * AP-REQ apoptions using shishi_ap_set_tktoption().  A random session
 * key is added to the authenticator, using the same keytype as the
 * ticket.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ap_tktoptions (Shishi * handle,
		      Shishi_ap ** ap, Shishi_tkt * tkt, int options)
{
  int rc;

  rc = shishi_ap_etype (handle, ap, shishi_tkt_keytype_fast (tkt));
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_ap_set_tktoptions (*ap, tkt, options);
  if (rc != SHISHI_OK)
    return rc;

  return SHISHI_OK;
}

/**
 * shishi_ap_tktoptionsdata:
 * @handle: shishi handle as allocated by shishi_init().
 * @ap: pointer to new structure that holds information about AP exchange
 * @tkt: ticket to set in newly created AP.
 * @options: AP-REQ options to set in newly created AP.
 * @data: input array with data to checksum in Authenticator.
 * @len: length of input array with data to checksum in Authenticator.
 *
 * Create a new AP exchange using shishi_ap(), and set the ticket,
 * AP-REQ apoptions and the Authenticator checksum data using
 * shishi_ap_set_tktoptionsdata(). A random session key is added to
 * the authenticator, using the same keytype as the ticket.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ap_tktoptionsdata (Shishi * handle,
			  Shishi_ap ** ap,
			  Shishi_tkt * tkt, int options,
			  const char *data, size_t len)
{
  int rc;

  rc = shishi_ap_etype (handle, ap, shishi_tkt_keytype_fast (tkt));
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_ap_set_tktoptionsdata (*ap, tkt, options, data, len);
  if (rc != SHISHI_OK)
    return rc;

  return SHISHI_OK;
}

/**
 * shishi_ap_tktoptionsraw:
 * @handle: shishi handle as allocated by shishi_init().
 * @ap: pointer to new structure that holds information about AP exchange
 * @tkt: ticket to set in newly created AP.
 * @options: AP-REQ options to set in newly created AP.
 * @cksumtype: authenticator checksum type to set in AP.
 * @data: input array with data to store in checksum field in Authenticator.
 * @len: length of input array with data to store in checksum field in
 *   Authenticator.
 *
 * Create a new AP exchange using shishi_ap(), and set the ticket,
 * AP-REQ apoptions and the raw Authenticator checksum data field
 * using shishi_ap_set_tktoptionsraw().  A random session key is added
 * to the authenticator, using the same keytype as the ticket.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ap_tktoptionsraw (Shishi * handle,
			 Shishi_ap ** ap,
			 Shishi_tkt * tkt, int options,
			 int32_t cksumtype, const char *data, size_t len)
{
  int rc;

  rc = shishi_ap_etype (handle, ap, shishi_tkt_keytype_fast (tkt));
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_ap_set_tktoptionsraw (*ap, tkt, options, cksumtype, data, len);
  if (rc != SHISHI_OK)
    return rc;

  return SHISHI_OK;
}

/**
 * shishi_ap_etype_tktoptionsdata:
 * @handle: shishi handle as allocated by shishi_init().
 * @ap: pointer to new structure that holds information about AP exchange
 * @etype: encryption type of newly generated random subkey.
 * @tkt: ticket to set in newly created AP.
 * @options: AP-REQ options to set in newly created AP.
 * @data: input array with data to checksum in Authenticator.
 * @len: length of input array with data to checksum in Authenticator.
 *
 * Create a new AP exchange using shishi_ap(), and set the ticket,
 * AP-REQ apoptions and the Authenticator checksum data using
 * shishi_ap_set_tktoptionsdata(). A random session key is added to
 * the authenticator, using the same keytype as the ticket.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ap_etype_tktoptionsdata (Shishi * handle,
				Shishi_ap ** ap,
				int32_t etype,
				Shishi_tkt * tkt, int options,
				const char *data, size_t len)
{
  int rc;

  rc = shishi_ap_etype (handle, ap, etype);
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_ap_set_tktoptionsdata (*ap, tkt, options, data, len);
  if (rc != SHISHI_OK)
    return rc;

  return SHISHI_OK;
}

/**
 * shishi_ap_tktoptionsasn1usage:
 * @handle: shishi handle as allocated by shishi_init().
 * @ap: pointer to new structure that holds information about AP exchange
 * @tkt: ticket to set in newly created AP.
 * @options: AP-REQ options to set in newly created AP.
 * @node: input ASN.1 structure to store as authenticator checksum data.
 * @field: field in ASN.1 structure to use.
 * @authenticatorcksumkeyusage: key usage for checksum in authenticator.
 * @authenticatorkeyusage: key usage for authenticator.
 *
 * Create a new AP exchange using shishi_ap(), and set ticket, options
 * and authenticator checksum data from the DER encoding of the ASN.1
 * field using shishi_ap_set_tktoptionsasn1usage().  A random session
 * key is added to the authenticator, using the same keytype as the
 * ticket.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ap_tktoptionsasn1usage (Shishi * handle,
			       Shishi_ap ** ap,
			       Shishi_tkt * tkt,
			       int options,
			       Shishi_asn1 node,
			       const char *field,
			       int authenticatorcksumkeyusage,
			       int authenticatorkeyusage)
{
  int rc;

  rc = shishi_ap_etype (handle, ap, shishi_tkt_keytype_fast (tkt));
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_ap_set_tktoptionsasn1usage (*ap, tkt, options,
					  node, field,
					  authenticatorcksumkeyusage,
					  authenticatorkeyusage);
  if (rc != SHISHI_OK)
    return rc;

  return SHISHI_OK;
}

/**
 * shishi_ap_tkt:
 * @ap: structure that holds information about AP exchange
 *
 * Get Ticket from AP exchange.
 *
 * Return value: Returns the ticket from the AP exchange, or NULL if
 *               not yet set or an error occured.
 **/
Shishi_tkt *
shishi_ap_tkt (Shishi_ap * ap)
{
  return ap->tkt;
}

/**
 * shishi_ap_tkt_set:
 * @ap: structure that holds information about AP exchange
 * @tkt: ticket to store in AP.
 *
 * Set the Ticket in the AP exchange.
 **/
void
shishi_ap_tkt_set (Shishi_ap * ap, Shishi_tkt * tkt)
{
  ap->tkt = tkt;
}

/**
 * shishi_ap_authenticator_cksumdata:
 * @ap: structure that holds information about AP exchange
 * @out: output array that holds authenticator checksum data.
 * @len: on input, maximum length of output array that holds
 *       authenticator checksum data, on output actual length of
 *       output array that holds authenticator checksum data.
 *
 * Get checksum data from Authenticator.
 *
 * Return value: Returns SHISHI_OK if successful, or
 * SHISHI_TOO_SMALL_BUFFER if buffer provided was too small.
 **/
int
shishi_ap_authenticator_cksumdata (Shishi_ap * ap, char *out, size_t * len)
{
  if (*len < ap->authenticatorcksumdatalen)
    return SHISHI_TOO_SMALL_BUFFER;
  if (ap->authenticatorcksumdata)
    memcpy (out, ap->authenticatorcksumdata, ap->authenticatorcksumdatalen);
  *len = ap->authenticatorcksumdatalen;
  return SHISHI_OK;
}

/**
 * shishi_ap_authenticator_cksumdata_set:
 * @ap: structure that holds information about AP exchange
 * @authenticatorcksumdata: input array with data to compute checksum
 *   on and store in Authenticator in AP-REQ.
 * @authenticatorcksumdatalen: length of input array with data to
 *   compute checksum on and store in Authenticator in AP-REQ.
 *
 * Set the Authenticator Checksum Data in the AP exchange.  This is
 * the data that will be checksumed, and the checksum placed in the
 * checksum field.  It is not the actual checksum field.  See also
 * shishi_ap_authenticator_cksumraw_set.
 **/
void
shishi_ap_authenticator_cksumdata_set (Shishi_ap * ap,
				       const char *authenticatorcksumdata,
				       size_t authenticatorcksumdatalen)
{
  ap->authenticatorcksumdata = xmemdup (authenticatorcksumdata,
					authenticatorcksumdatalen);
  ap->authenticatorcksumdatalen = authenticatorcksumdatalen;
}

/**
 * shishi_ap_authenticator_cksumraw_set:
 * @ap: structure that holds information about AP exchange
 * @authenticatorcksumtype: authenticator checksum type to set in AP.
 * @authenticatorcksumraw: input array with authenticator checksum
 *   field value to set in Authenticator in AP-REQ.
 * @authenticatorcksumrawlen: length of input array with
 *   authenticator checksum field value to set in Authenticator in AP-REQ.
 *
 * Set the Authenticator Checksum Data in the AP exchange.  This is
 * the actual checksum field, not data to compute checksum on and then
 * store in the checksum field.  See also
 * shishi_ap_authenticator_cksumdata_set.
 **/
void
shishi_ap_authenticator_cksumraw_set (Shishi_ap * ap,
				      int32_t authenticatorcksumtype,
				      const char *authenticatorcksumraw,
				      size_t authenticatorcksumrawlen)
{
  shishi_ap_authenticator_cksumtype_set (ap, authenticatorcksumtype);
  ap->authenticatorcksumraw = xmemdup (authenticatorcksumraw,
				       authenticatorcksumrawlen);
  ap->authenticatorcksumrawlen = authenticatorcksumrawlen;
}

/**
 * shishi_ap_authenticator_cksumtype:
 * @ap: structure that holds information about AP exchange
 *
 * Get the Authenticator Checksum Type in the AP exchange.
 *
 * Return value: Return the authenticator checksum type.
 **/
int32_t
shishi_ap_authenticator_cksumtype (Shishi_ap * ap)
{
  return ap->authenticatorcksumtype;
}

/**
 * shishi_ap_authenticator_cksumtype_set:
 * @ap: structure that holds information about AP exchange
 * @cksumtype: authenticator checksum type to set in AP.
 *
 * Set the Authenticator Checksum Type in the AP exchange.
 **/
void
shishi_ap_authenticator_cksumtype_set (Shishi_ap * ap, int32_t cksumtype)
{
  ap->authenticatorcksumtype = cksumtype;
}

/**
 * shishi_ap_authenticator:
 * @ap: structure that holds information about AP exchange
 *
 * Get ASN.1 Authenticator structure from AP exchange.
 *
 * Return value: Returns the Authenticator from the AP exchange, or
 *               NULL if not yet set or an error occured.
 **/

Shishi_asn1
shishi_ap_authenticator (Shishi_ap * ap)
{
  return ap->authenticator;
}

/**
 * shishi_ap_authenticator_set:
 * @ap: structure that holds information about AP exchange
 * @authenticator: authenticator to store in AP.
 *
 * Set the Authenticator in the AP exchange.
 **/
void
shishi_ap_authenticator_set (Shishi_ap * ap, Shishi_asn1 authenticator)
{
  if (ap->authenticator)
    shishi_asn1_done (ap->handle, ap->authenticator);
  ap->authenticator = authenticator;
}

/**
 * shishi_ap_req:
 * @ap: structure that holds information about AP exchange
 *
 * Get ASN.1 AP-REQ structure from AP exchange.
 *
 * Return value: Returns the AP-REQ from the AP exchange, or NULL if
 *               not yet set or an error occured.
 **/
Shishi_asn1
shishi_ap_req (Shishi_ap * ap)
{
  return ap->apreq;
}


/**
 * shishi_ap_req_set:
 * @ap: structure that holds information about AP exchange
 * @apreq: apreq to store in AP.
 *
 * Set the AP-REQ in the AP exchange.
 **/
void
shishi_ap_req_set (Shishi_ap * ap, Shishi_asn1 apreq)
{
  if (ap->apreq)
    shishi_asn1_done (ap->handle, ap->apreq);
  ap->apreq = apreq;
}

/**
 * shishi_ap_req_der:
 * @ap: structure that holds information about AP exchange
 * @out: pointer to output array with der encoding of AP-REQ.
 * @outlen: pointer to length of output array with der encoding of AP-REQ.
 *
 * Build AP-REQ using shishi_ap_req_build() and DER encode it.  @out
 * is allocated by this function, and it is the responsibility of
 * caller to deallocate it.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ap_req_der (Shishi_ap * ap, char **out, size_t * outlen)
{
  int rc;

  rc = shishi_ap_req_build (ap);
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_asn1_to_der (ap->handle, ap->apreq, out, outlen);
  if (rc != SHISHI_OK)
    return rc;

  return SHISHI_OK;
}

/**
 * shishi_ap_req_der_set:
 * @ap: structure that holds information about AP exchange
 * @der: input array with DER encoded AP-REQ.
 * @derlen: length of input array with DER encoded AP-REQ.
 *
 * DER decode AP-REQ and set it AP exchange.  If decoding fails, the
 * AP-REQ in the AP exchange is lost.
 *
 * Return value: Returns SHISHI_OK.
 **/
int
shishi_ap_req_der_set (Shishi_ap * ap, char *der, size_t derlen)
{
  ap->apreq = shishi_der2asn1_apreq (ap->handle, der, derlen);

  if (ap->apreq)
    return SHISHI_OK;
  else
    return SHISHI_ASN1_ERROR;
}

/**
 * shishi_ap_req_build:
 * @ap: structure that holds information about AP exchange
 *
 * Checksum data in authenticator and add ticket and authenticator to
 * AP-REQ.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ap_req_build (Shishi_ap * ap)
{
  int res;
  int cksumtype;

  if (VERBOSE (ap->handle))
    printf ("Building AP-REQ...\n");

  if (VERBOSEASN1 (ap->handle))
    {
      shishi_ticket_print (ap->handle, stdout, shishi_tkt_ticket (ap->tkt));
      shishi_key_print (ap->handle, stdout, shishi_tkt_key (ap->tkt));
    }


  res = shishi_apreq_set_ticket (ap->handle, ap->apreq,
				 shishi_tkt_ticket (ap->tkt));
  if (res != SHISHI_OK)
    {
      shishi_error_printf (ap->handle, "Could not set ticket in AP-REQ: %s\n",
			   shishi_error (ap->handle));
      return res;
    }

  cksumtype = shishi_ap_authenticator_cksumtype (ap);
  if (ap->authenticatorcksumraw && ap->authenticatorcksumrawlen > 0)
    res = shishi_authenticator_set_cksum (ap->handle, ap->authenticator,
					  cksumtype,
					  ap->authenticatorcksumraw,
					  ap->authenticatorcksumrawlen);
  else if (cksumtype == SHISHI_NO_CKSUMTYPE)
    res = shishi_authenticator_add_cksum (ap->handle, ap->authenticator,
					  shishi_tkt_key (ap->tkt),
					  ap->authenticatorcksumkeyusage,
					  ap->authenticatorcksumdata,
					  ap->authenticatorcksumdatalen);
  else
    res = shishi_authenticator_add_cksum_type (ap->handle, ap->authenticator,
					       shishi_tkt_key (ap->tkt),
					       ap->authenticatorcksumkeyusage,
					       cksumtype,
					       ap->authenticatorcksumdata,
					       ap->authenticatorcksumdatalen);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (ap->handle,
			   "Could not add checksum to authenticator: %s\n",
			   shishi_error (ap->handle));
      return res;
    }

  if (VERBOSE (ap->handle))
    printf ("Got Authenticator...\n");

  if (VERBOSEASN1 (ap->handle))
    shishi_authenticator_print (ap->handle, stdout, ap->authenticator);

  res = shishi_apreq_add_authenticator (ap->handle, ap->apreq,
					shishi_tkt_key (ap->tkt),
					ap->authenticatorkeyusage,
					ap->authenticator);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (ap->handle, "Could not set authenticator: %s\n",
			   shishi_error (ap->handle));
      return res;
    }

  if (VERBOSEASN1 (ap->handle))
    shishi_apreq_print (ap->handle, stdout, ap->apreq);

  return SHISHI_OK;
}

/**
 * shishi_ap_req_decode:
 * @ap: structure that holds information about AP exchange
 *
 * Decode ticket in AP-REQ and set the Ticket fields in the AP
 * exchange.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ap_req_decode (Shishi_ap * ap)
{
  Shishi_asn1 ticket;
  int rc;

  if (VERBOSEASN1 (ap->handle))
    shishi_apreq_print (ap->handle, stdout, ap->apreq);

  rc = shishi_apreq_get_ticket (ap->handle, ap->apreq, &ticket);
  if (rc != SHISHI_OK)
    {
      shishi_error_printf (ap->handle,
			   "Could not extract ticket from AP-REQ: %s\n",
			   shishi_strerror (rc));
      return rc;
    }

  if (VERBOSEASN1 (ap->handle))
    shishi_ticket_print (ap->handle, stdout, ticket);

  rc = shishi_tkt (ap->handle, &ap->tkt);
  if (rc != SHISHI_OK)
    return rc;

  shishi_tkt_ticket_set (ap->tkt, ticket);

  return SHISHI_OK;
}

/**
 * shishi_ap_req_process_keyusage:
 * @ap: structure that holds information about AP exchange
 * @key: cryptographic key used to decrypt ticket in AP-REQ.
 * @keyusage: key usage to use during decryption, for normal
 *   AP-REQ's this is normally SHISHI_KEYUSAGE_APREQ_AUTHENTICATOR,
 *   for AP-REQ's part of TGS-REQ's, this is normally
 *   SHISHI_KEYUSAGE_TGSREQ_APREQ_AUTHENTICATOR.
 *
 * Decrypt ticket in AP-REQ using supplied key and decrypt
 * Authenticator in AP-REQ using key in decrypted ticket, and on
 * success set the Ticket and Authenticator fields in the AP exchange.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ap_req_process_keyusage (Shishi_ap * ap,
				Shishi_key * key, int32_t keyusage)
{
  Shishi_asn1 authenticator;
  Shishi_key *tktkey;
  int rc;

  rc = shishi_ap_req_decode (ap);
  if (rc != SHISHI_OK)
    {
      shishi_error_printf (ap->handle, "Error decoding ticket: %s\n",
			   shishi_strerror (rc));
      return rc;
    }

  rc = shishi_tkt_decrypt (ap->tkt, key);
  if (rc != SHISHI_OK)
    {
      shishi_error_printf (ap->handle, "Error decrypting ticket: %s\n",
			   shishi_strerror (rc));
      return rc;
    }

  rc = shishi_encticketpart_get_key (ap->handle,
				     shishi_tkt_encticketpart (ap->tkt),
				     &tktkey);
  if (rc != SHISHI_OK)
    {
      shishi_error_printf (ap->handle, "Could not get key from ticket: %s\n",
			   shishi_strerror (rc));
      return rc;
    }

  if (VERBOSEASN1 (ap->handle))
    shishi_encticketpart_print (ap->handle, stdout,
				shishi_tkt_encticketpart (ap->tkt));

  rc = shishi_apreq_decrypt (ap->handle, ap->apreq, tktkey,
			     keyusage, &authenticator);
  if (rc != SHISHI_OK)
    {
      shishi_error_printf (ap->handle, "Error decrypting apreq: %s\n",
			   shishi_strerror (rc));
      return rc;
    }

  /* XXX? verify checksum in authenticator. */

  if (VERBOSEASN1 (ap->handle))
    shishi_authenticator_print (ap->handle, stdout, authenticator);

  if (ap->authenticatorcksumdata)
    free (ap->authenticatorcksumdata);

  rc = shishi_authenticator_cksum (ap->handle, authenticator,
				   &ap->authenticatorcksumtype,
				   &ap->authenticatorcksumdata,
				   &ap->authenticatorcksumdatalen);
  if (rc != SHISHI_OK)
    {
      shishi_error_printf (ap->handle,
			   "Error extracting authenticator checksum: %s\n",
			   shishi_strerror (rc));
      return rc;
    }

  ap->authenticator = authenticator;

  return SHISHI_OK;
}

/**
 * shishi_ap_req_process:
 * @ap: structure that holds information about AP exchange
 * @key: cryptographic key used to decrypt ticket in AP-REQ.
 *
 * Decrypt ticket in AP-REQ using supplied key and decrypt
 * Authenticator in AP-REQ using key in decrypted ticket, and on
 * success set the Ticket and Authenticator fields in the AP exchange.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ap_req_process (Shishi_ap * ap, Shishi_key * key)
{
  return shishi_ap_req_process_keyusage (ap, key,
					 SHISHI_KEYUSAGE_APREQ_AUTHENTICATOR);
}

/**
 * shishi_ap_req_asn1:
 * @ap: structure that holds information about AP exchange
 * @apreq: output AP-REQ variable.
 *
 * Build AP-REQ using shishi_ap_req_build() and return it.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ap_req_asn1 (Shishi_ap * ap, Shishi_asn1 * apreq)
{
  int rc;

  rc = shishi_ap_req_build (ap);
  if (rc != SHISHI_OK)
    return rc;

  *apreq = ap->apreq;

  return SHISHI_OK;
}

/**
 * shishi_ap_key:
 * @ap: structure that holds information about AP exchange
 *
 * Extract the application key from AP.  If subkeys are used, it is
 * taken from the Authenticator, otherwise the session key is used.
 *
 * Return value: Return application key from AP.
 **/
Shishi_key *
shishi_ap_key (Shishi_ap * ap)
{
  int rc;

  /* XXX do real check if subkey is present, don't just assume error
     means no subkey */

  rc = shishi_authenticator_get_subkey (ap->handle, ap->authenticator,
					&ap->key);
  if (rc != SHISHI_OK)
    ap->key = shishi_tkt_key (ap->tkt);

  return ap->key;
}

/**
 * shishi_ap_rep:
 * @ap: structure that holds information about AP exchange
 *
 * Get ASN.1 AP-REP structure from AP exchange.
 *
 * Return value: Returns the AP-REP from the AP exchange, or NULL if
 *               not yet set or an error occured.
 **/
Shishi_asn1
shishi_ap_rep (Shishi_ap * ap)
{
  return ap->aprep;
}

/**
 * shishi_ap_rep_set:
 * @ap: structure that holds information about AP exchange
 * @aprep: aprep to store in AP.
 *
 * Set the AP-REP in the AP exchange.
 **/
void
shishi_ap_rep_set (Shishi_ap * ap, Shishi_asn1 aprep)
{
  if (ap->aprep)
    shishi_asn1_done (ap->handle, ap->aprep);
  ap->aprep = aprep;
}

/**
 * shishi_ap_rep_der:
 * @ap: structure that holds information about AP exchange
 * @out: output array with newly allocated DER encoding of AP-REP.
 * @outlen: length of output array with DER encoding of AP-REP.
 *
 * Build AP-REP using shishi_ap_rep_build() and DER encode it.  @out
 * is allocated by this function, and it is the responsibility of
 * caller to deallocate it.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ap_rep_der (Shishi_ap * ap, char **out, size_t * outlen)
{
  int rc;

  rc = shishi_ap_rep_build (ap);
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_asn1_to_der (ap->handle, ap->aprep, out, outlen);
  if (rc != SHISHI_OK)
    return rc;

  return SHISHI_OK;
}

/**
 * shishi_ap_rep_der_set:
 * @ap: structure that holds information about AP exchange
 * @der: input array with DER encoded AP-REP.
 * @derlen: length of input array with DER encoded AP-REP.
 *
 * DER decode AP-REP and set it AP exchange.  If decoding fails, the
 * AP-REP in the AP exchange remains.
 *
 * Return value: Returns SHISHI_OK.
 **/
int
shishi_ap_rep_der_set (Shishi_ap * ap, char *der, size_t derlen)
{
  Shishi_asn1 aprep;

  aprep = shishi_der2asn1_aprep (ap->handle, der, derlen);

  if (!aprep)
    return SHISHI_ASN1_ERROR;

  ap->aprep = aprep;

  return SHISHI_OK;
}

/**
 * shishi_ap_rep_build:
 * @ap: structure that holds information about AP exchange
 *
 * Checksum data in authenticator and add ticket and authenticator to
 * AP-REP.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ap_rep_build (Shishi_ap * ap)
{
  Shishi_asn1 aprep;
  int rc;

  if (VERBOSE (ap->handle))
    printf ("Building AP-REP...\n");

  aprep = shishi_aprep (ap->handle);
  rc = shishi_aprep_enc_part_make (ap->handle, aprep, ap->encapreppart,
				   ap->authenticator,
				   shishi_tkt_encticketpart (ap->tkt));
  if (rc != SHISHI_OK)
    {
      shishi_error_printf (ap->handle, "Error creating AP-REP: %s\n",
			   shishi_strerror (rc));
      return rc;
    }

  if (VERBOSEASN1 (ap->handle))
    shishi_aprep_print (ap->handle, stdout, aprep);

  shishi_ap_rep_set (ap, aprep);

  return SHISHI_OK;
}

/**
 * shishi_ap_rep_asn1:
 * @ap: structure that holds information about AP exchange
 * @aprep: output AP-REP variable.
 *
 * Build AP-REP using shishi_ap_rep_build() and return it.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ap_rep_asn1 (Shishi_ap * ap, Shishi_asn1 * aprep)
{
  int rc;

  rc = shishi_ap_rep_build (ap);
  if (rc != SHISHI_OK)
    return rc;

  *aprep = ap->aprep;

  return SHISHI_OK;
}

/**
 * shishi_ap_rep_verify:
 * @ap: structure that holds information about AP exchange
 *
 * Verify AP-REP compared to Authenticator.
 *
 * Return value: Returns SHISHI_OK, SHISHI_APREP_VERIFY_FAILED or an
 * error.
 **/
int
shishi_ap_rep_verify (Shishi_ap * ap)
{
  int res;

  if (VERBOSE (ap->handle))
    printf ("Decrypting AP-REP...\n");

  if (VERBOSEASN1 (ap->handle))
    shishi_aprep_print (ap->handle, stdout, ap->aprep);

  res = shishi_aprep_decrypt (ap->handle, ap->aprep,
			      shishi_tkt_key (ap->tkt),
			      SHISHI_KEYUSAGE_ENCAPREPPART,
			      &ap->encapreppart);
  if (res != SHISHI_OK)
    return res;

  if (VERBOSEASN1 (ap->handle))
    shishi_encapreppart_print (ap->handle, stdout, ap->encapreppart);

  res = shishi_aprep_verify (ap->handle, ap->authenticator, ap->encapreppart);
  if (res != SHISHI_OK)
    return res;

  if (VERBOSE (ap->handle))
    printf ("Verified AP-REP successfully...\n");

  return SHISHI_OK;
}

/**
 * shishi_ap_rep_verify_der:
 * @ap: structure that holds information about AP exchange
 * @der: input array with DER encoded AP-REP.
 * @derlen: length of input array with DER encoded AP-REP.
 *
 * DER decode AP-REP and set it in AP exchange using
 * shishi_ap_rep_der_set() and verify it using shishi_ap_rep_verify().
 *
 * Return value: Returns SHISHI_OK, SHISHI_APREP_VERIFY_FAILED or an
 * error.
 **/
int
shishi_ap_rep_verify_der (Shishi_ap * ap, char *der, size_t derlen)
{
  int res;

  res = shishi_ap_rep_der_set (ap, der, derlen);
  if (res != SHISHI_OK)
    return res;

  res = shishi_ap_rep_verify (ap);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_ap_rep_verify_asn1:
 * @ap: structure that holds information about AP exchange
 * @aprep: input AP-REP.
 *
 * Set the AP-REP in the AP exchange using shishi_ap_rep_set() and
 * verify it using shishi_ap_rep_verify().
 *
 * Return value: Returns SHISHI_OK, SHISHI_APREP_VERIFY_FAILED or an
 * error.
 **/
int
shishi_ap_rep_verify_asn1 (Shishi_ap * ap, Shishi_asn1 aprep)
{
  int res;

  shishi_ap_rep_set (ap, aprep);

  res = shishi_ap_rep_verify (ap);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_ap_encapreppart:
 * @ap: structure that holds information about AP exchange
 *
 * Get ASN.1 EncAPRepPart structure from AP exchange.
 *
 * Return value: Returns the EncAPREPPart from the AP exchange, or
 *               NULL if not yet set or an error occured.
 **/
Shishi_asn1
shishi_ap_encapreppart (Shishi_ap * ap)
{
  return ap->encapreppart;
}

/**
 * shishi_ap_encapreppart_set:
 * @ap: structure that holds information about AP exchange
 * @encapreppart: EncAPRepPart to store in AP.
 *
 * Set the EncAPRepPart in the AP exchange.
 **/
void
shishi_ap_encapreppart_set (Shishi_ap * ap, Shishi_asn1 encapreppart)
{
  if (ap->encapreppart)
    shishi_asn1_done (ap->handle, ap->encapreppart);
  ap->encapreppart = encapreppart;
}

#define APOPTION_RESERVED "reserved"
#define APOPTION_USE_SESSION_KEY "use-session-key"
#define APOPTION_MUTUAL_REQUIRED "mutual-required"
#define APOPTION_UNKNOWN "unknown"

/**
 * shishi_ap_option2string:
 * @option: enumerated AP-Option type, see Shishi_apoptions.
 *
 * Convert AP-Option type to AP-Option name string.  Note that @option
 * must be just one of the AP-Option types, it cannot be an binary
 * ORed indicating several AP-Options.
 *
 * Return value: Returns static string with name of AP-Option that
 *   must not be deallocated, or "unknown" if AP-Option was not understood.
 **/
const char *
shishi_ap_option2string (Shishi_apoptions option)
{
  const char *str;

  switch (option)
    {
    case SHISHI_APOPTIONS_RESERVED:
      str = APOPTION_RESERVED;
      break;

    case SHISHI_APOPTIONS_USE_SESSION_KEY:
      str = APOPTION_USE_SESSION_KEY;
      break;

    case SHISHI_APOPTIONS_MUTUAL_REQUIRED:
      str = APOPTION_MUTUAL_REQUIRED;
      break;

    default:
      str = APOPTION_UNKNOWN;
      break;
    }

  return str;
}

/**
 * shishi_ap_string2option:
 * @str: zero terminated character array with name of AP-Option,
 *   e.g. "use-session-key".
 *
 * Convert AP-Option name to AP-Option type.
 *
 * Return value: Returns enumerated type member corresponding to AP-Option,
 *   or 0 if string was not understood.
 **/
Shishi_apoptions
shishi_ap_string2option (const char *str)
{
  int option;

  if (strcasecmp (str, APOPTION_RESERVED) == 0)
    option = SHISHI_APOPTIONS_RESERVED;
  else if (strcasecmp (str, APOPTION_USE_SESSION_KEY) == 0)
    option = SHISHI_APOPTIONS_USE_SESSION_KEY;
  else if (strcasecmp (str, APOPTION_MUTUAL_REQUIRED) == 0)
    option = SHISHI_APOPTIONS_MUTUAL_REQUIRED;
  else
    option = strtol (str, (char **) NULL, 0);

  return option;
}
