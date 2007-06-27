/* priv.c --- Application data privacy protection.
 * Copyright (C) 2002, 2003, 2004, 2006, 2007  Simon Josefsson
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

/* Get _shishi_print_armored_data, etc. */
#include "diskio.h"

struct Shishi_priv
{
  Shishi *handle;
  Shishi_key *key;
  Shishi_asn1 priv;
  Shishi_asn1 encprivpart;
  unsigned long seqnumber;
};

/**
 * shishi_priv:
 * @handle: shishi handle as allocated by shishi_init().
 * @priv: pointer to new structure that holds information about PRIV exchange
 *
 * Create a new PRIV exchange.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_priv (Shishi * handle, Shishi_priv ** priv)
{
  Shishi_priv *lpriv;
  struct timeval tv;
  char *usec;
  int rc;

  *priv = xcalloc (1, sizeof (**priv));
  lpriv = *priv;

  lpriv->handle = handle;
  rc = shishi_key (handle, &lpriv->key);
  if (rc != SHISHI_OK)
    return rc;

  lpriv->priv = shishi_asn1_priv (handle);
  if (lpriv->priv == NULL)
    return SHISHI_ASN1_ERROR;

  rc = shishi_asn1_write (handle, lpriv->priv, "pvno", "5", 0);
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_asn1_write (handle, lpriv->priv, "msg-type", "21", 0);
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_asn1_write (handle, lpriv->priv, "enc-part.kvno", "0", 0);
  if (rc != SHISHI_OK)
    return rc;

  lpriv->encprivpart = shishi_asn1_encprivpart (handle);
  if (lpriv->priv == NULL)
    return SHISHI_ASN1_ERROR;

  rc = shishi_asn1_write (handle, lpriv->encprivpart, "timestamp",
			  shishi_generalize_time (handle, time (NULL)), 0);
  if (rc != SHISHI_OK)
    return rc;

  rc = gettimeofday (&tv, NULL);
  if (rc != 0)
    return SHISHI_GETTIMEOFDAY_ERROR;
  usec = xasprintf ("%ld", tv.tv_usec % 1000000);
  rc = shishi_asn1_write (handle, lpriv->encprivpart, "usec", usec, 0);
  free (usec);
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_asn1_write (handle, lpriv->encprivpart, "seq-number", NULL, 0);
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_asn1_write (handle, lpriv->encprivpart, "s-address.addr-type",
			  /* directional */
			  "3", 0);
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_asn1_write (handle, lpriv->encprivpart, "s-address.address",
			  /* sender */
			  "\x00\x00\x00\x00", 4);
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_asn1_write (handle, lpriv->encprivpart, "r-address", NULL, 0);
  if (rc != SHISHI_OK)
    return rc;

  return SHISHI_OK;
}

/**
 * shishi_priv_done:
 * @priv: structure that holds information about PRIV exchange
 *
 * Deallocate resources associated with PRIV exchange.  This should be
 * called by the application when it no longer need to utilize the
 * PRIV exchange handle.
 **/
void
shishi_priv_done (Shishi_priv * priv)
{
  shishi_asn1_done (priv->handle, priv->priv);
  shishi_asn1_done (priv->handle, priv->encprivpart);
  shishi_key_done (priv->key);
  free (priv);
}

/**
 * shishi_priv_key:
 * @priv: structure that holds information about PRIV exchange
 *
 * Get key from PRIV exchange.
 *
 * Return value: Returns the key used in the PRIV exchange, or NULL if
 *               not yet set or an error occured.
 **/
Shishi_key *
shishi_priv_key (Shishi_priv * priv)
{
  return priv->key;
}

/**
 * shishi_priv_key_set:
 * @priv: structure that holds information about PRIV exchange
 * @key: key to store in PRIV.
 *
 * Set the Key in the PRIV exchange.
 **/
void
shishi_priv_key_set (Shishi_priv * priv, Shishi_key * key)
{
  shishi_key_copy (priv->key, key);
}

/**
 * shishi_priv_priv:
 * @priv: structure that holds information about PRIV exchange
 *
 * Get ASN.1 PRIV structure in PRIV exchange.
 *
 * Return value: Returns the ASN.1 priv in the PRIV exchange, or NULL if
 *               not yet set or an error occured.
 **/
Shishi_asn1
shishi_priv_priv (Shishi_priv * priv)
{
  return priv->priv;
}

/**
 * shishi_priv_priv_set:
 * @priv: structure that holds information about PRIV exchange
 * @asn1priv: KRB-PRIV to store in PRIV exchange.
 *
 * Set the KRB-PRIV in the PRIV exchange.
 **/
void
shishi_priv_priv_set (Shishi_priv * priv, Shishi_asn1 asn1priv)
{
  if (priv->priv)
    shishi_asn1_done (priv->handle, priv->priv);
  priv->priv = asn1priv;
}

/**
 * shishi_priv_priv_der:
 * @priv: priv as allocated by shishi_priv().
 * @out: output array with newly allocated DER encoding of PRIV.
 * @outlen: length of output array with DER encoding of PRIV.
 *
 * DER encode PRIV structure.  Typically shishi_priv_build() is used
 * to build the PRIV structure first.  @out is allocated by this
 * function, and it is the responsibility of caller to deallocate it.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_priv_priv_der (Shishi_priv * priv, char **out, size_t * outlen)
{
  int rc;

  rc = shishi_asn1_to_der (priv->handle, priv->priv, out, outlen);
  if (rc != SHISHI_OK)
    return rc;

  return SHISHI_OK;
}

/**
 * shishi_priv_priv_der_set:
 * @priv: priv as allocated by shishi_priv().
 * @der: input array with DER encoded KRB-PRIV.
 * @derlen: length of input array with DER encoded KRB-PRIV.
 *
 * DER decode KRB-PRIV and set it PRIV exchange.  If decoding fails, the
 * KRB-PRIV in the PRIV exchange remains.
 *
 * Return value: Returns SHISHI_OK.
 **/
int
shishi_priv_priv_der_set (Shishi_priv * priv, char *der, size_t derlen)
{
  Shishi_asn1 asn1priv;

  asn1priv = shishi_der2asn1_priv (priv->handle, der, derlen);

  if (asn1priv == NULL)
    return SHISHI_ASN1_ERROR;

  shishi_priv_priv_set (priv, asn1priv);

  return SHISHI_OK;
}

/**
 * shishi_priv_encprivpart:
 * @priv: structure that holds information about PRIV exchange
 *
 * Get ASN.1 EncPrivPart structure from PRIV exchange.
 *
 * Return value: Returns the ASN.1 encprivpart in the PRIV exchange, or NULL if
 *               not yet set or an error occured.
 **/
Shishi_asn1
shishi_priv_encprivpart (Shishi_priv * priv)
{
  return priv->encprivpart;
}

/**
 * shishi_priv_encprivpart_set:
 * @priv: structure that holds information about PRIV exchange
 * @asn1encprivpart: ENCPRIVPART to store in PRIV exchange.
 *
 * Set the ENCPRIVPART in the PRIV exchange.
 **/
void
shishi_priv_encprivpart_set (Shishi_priv * priv, Shishi_asn1 asn1encprivpart)
{
  if (priv->encprivpart)
    shishi_asn1_done (priv->handle, priv->encprivpart);
  priv->encprivpart = asn1encprivpart;
}

/**
 * shishi_priv_encprivpart_der:
 * @priv: priv as allocated by shishi_priv().
 * @out: output array with newly allocated DER encoding of ENCPRIVPART.
 * @outlen: length of output array with DER encoding of ENCPRIVPART.
 *
 * DER encode ENCPRIVPART structure.  Typically
 * shishi_encprivpart_build() is used to build the ENCPRIVPART
 * structure first.  @out is allocated by this function, and it is the
 * responsibility of caller to deallocate it.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_priv_encprivpart_der (Shishi_priv * priv, char **out, size_t * outlen)
{
  int rc;

  rc = shishi_asn1_to_der (priv->handle, priv->encprivpart, out, outlen);
  if (rc != SHISHI_OK)
    return rc;

  return SHISHI_OK;
}

/**
 * shishi_priv_encprivpart_der_set:
 * @priv: priv as allocated by shishi_priv().
 * @der: input array with DER encoded ENCPRIVPART.
 * @derlen: length of input array with DER encoded ENCPRIVPART.
 *
 * DER decode ENCPRIVPART and set it PRIV exchange.  If decoding
 * fails, the ENCPRIVPART in the PRIV exchange remains.
 *
 * Return value: Returns SHISHI_OK.
 **/
int
shishi_priv_encprivpart_der_set (Shishi_priv * priv, char *der, size_t derlen)
{
  Shishi_asn1 asn1encprivpart;

  asn1encprivpart = shishi_der2asn1_encprivpart (priv->handle, der, derlen);

  if (asn1encprivpart == NULL)
    return SHISHI_ASN1_ERROR;

  shishi_priv_encprivpart_set (priv, asn1encprivpart);

  return SHISHI_OK;
}

/**
 * shishi_priv_print:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle open for writing.
 * @priv: PRIV to print.
 *
 * Print ASCII armored DER encoding of PRIV to file.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_priv_print (Shishi * handle, FILE * fh, Shishi_asn1 priv)
{
  return _shishi_print_armored_data (handle, fh, priv, "KRB-PRIV", NULL);
}

/**
 * shishi_priv_save:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle open for writing.
 * @priv: PRIV to save.
 *
 * Save DER encoding of PRIV to file.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_priv_save (Shishi * handle, FILE * fh, Shishi_asn1 priv)
{
  return _shishi_save_data (handle, fh, priv, "PRIV");
}

/**
 * shishi_priv_to_file:
 * @handle: shishi handle as allocated by shishi_init().
 * @priv: PRIV to save.
 * @filetype: input variable specifying type of file to be written,
 *            see Shishi_filetype.
 * @filename: input variable with filename to write to.
 *
 * Write PRIV to file in specified TYPE.  The file will be
 * truncated if it exists.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_priv_to_file (Shishi * handle, Shishi_asn1 priv,
		     int filetype, const char *filename)
{
  FILE *fh;
  int res;

  if (VERBOSE (handle))
    printf (_("Writing PRIV to %s...\n"), filename);

  fh = fopen (filename, "w");
  if (fh == NULL)
    return SHISHI_FOPEN_ERROR;

  if (VERBOSE (handle))
    printf (_("Writing PRIV in %s format...\n"),
	    filetype == SHISHI_FILETYPE_TEXT ? "TEXT" : "DER");

  if (filetype == SHISHI_FILETYPE_TEXT)
    res = shishi_priv_print (handle, fh, priv);
  else
    res = shishi_priv_save (handle, fh, priv);
  if (res != SHISHI_OK)
    return res;

  res = fclose (fh);
  if (res != 0)
    return SHISHI_IO_ERROR;

  if (VERBOSE (handle))
    printf (_("Writing PRIV to %s...done\n"), filename);

  return SHISHI_OK;
}

/**
 * shishi_priv_parse:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle open for reading.
 * @priv: output variable with newly allocated PRIV.
 *
 * Read ASCII armored DER encoded PRIV from file and populate given
 * variable.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_priv_parse (Shishi * handle, FILE * fh, Shishi_asn1 * priv)
{
  return _shishi_priv_input (handle, fh, priv, 0);
}

/**
 * shishi_priv_read:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle open for reading.
 * @priv: output variable with newly allocated PRIV.
 *
 * Read DER encoded PRIV from file and populate given variable.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_priv_read (Shishi * handle, FILE * fh, Shishi_asn1 * priv)
{
  return _shishi_priv_input (handle, fh, priv, 1);
}

/**
 * shishi_priv_from_file:
 * @handle: shishi handle as allocated by shishi_init().
 * @priv: output variable with newly allocated PRIV.
 * @filetype: input variable specifying type of file to be read,
 *            see Shishi_filetype.
 * @filename: input variable with filename to read from.
 *
 * Read PRIV from file in specified TYPE.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_priv_from_file (Shishi * handle, Shishi_asn1 * priv,
		       int filetype, const char *filename)
{
  int res;
  FILE *fh;

  if (VERBOSE (handle))
    printf (_("Reading PRIV from %s...\n"), filename);

  fh = fopen (filename, "r");
  if (fh == NULL)
    return SHISHI_FOPEN_ERROR;

  if (VERBOSE (handle))
    printf (_("Reading PRIV in %s format...\n"),
	    filetype == SHISHI_FILETYPE_TEXT ? "TEXT" : "DER");

  if (filetype == SHISHI_FILETYPE_TEXT)
    res = shishi_priv_parse (handle, fh, priv);
  else
    res = shishi_priv_read (handle, fh, priv);
  if (res != SHISHI_OK)
    return res;

  res = fclose (fh);
  if (res != 0)
    return SHISHI_IO_ERROR;

  if (VERBOSE (handle))
    printf (_("Reading PRIV from %s...done\n"), filename);

  return SHISHI_OK;
}

/**
 * shishi_priv_enc_part_etype:
 * @handle: shishi handle as allocated by shishi_init().
 * @priv: PRIV variable to get value from.
 * @etype: output variable that holds the value.
 *
 * Extract PRIV.enc-part.etype.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_priv_enc_part_etype (Shishi * handle,
			    Shishi_asn1 priv, int32_t * etype)
{
  return shishi_asn1_read_int32 (handle, priv, "enc-part.etype", etype);
}

/**
 * shishi_priv_set_enc_part:
 * @handle: shishi handle as allocated by shishi_init().
 * @priv: priv as allocated by shishi_priv().
 * @etype: input encryption type to store in PRIV.
 * @encpart: input encrypted data to store in PRIV.
 * @encpartlen: size of input encrypted data to store in PRIV.
 *
 * Store encrypted data in PRIV.  The encrypted data is usually
 * created by calling shishi_encrypt() on some application specific
 * data using the key from the ticket that is being used.  To save
 * time, you may want to use shishi_priv_build() instead, which
 * encryptes the data and calls this function in one step.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_priv_set_enc_part (Shishi * handle,
			  Shishi_asn1 priv,
			  int32_t etype,
			  const char *encpart, size_t encpartlen)
{
  int res;

  res = shishi_asn1_write_integer (handle, priv, "enc-part.etype", etype);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_write (handle, priv, "enc-part.cipher",
			   encpart, encpartlen);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_encprivpart_user_data:
 * @handle: shishi handle as allocated by shishi_init().
 * @encprivpart: encprivpart as allocated by shishi_priv().
 * @userdata: output array with newly allocated user data from KRB-PRIV.
 * @userdatalen: output size of output user data buffer.
 *
 * Read user data value from KRB-PRIV.  @userdata is allocated by this
 * function, and it is the responsibility of caller to deallocate it.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_encprivpart_user_data (Shishi * handle,
			      Shishi_asn1 encprivpart,
			      char **userdata, size_t * userdatalen)
{
  int res;

  res = shishi_asn1_read (handle, encprivpart, "user-data",
			  userdata, userdatalen);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_encprivpart_set_user_data:
 * @handle: shishi handle as allocated by shishi_init().
 * @encprivpart: encprivpart as allocated by shishi_priv().
 * @userdata: input user application to store in PRIV.
 * @userdatalen: size of input user application to store in PRIV.
 *
 * Set the application data in PRIV.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_encprivpart_set_user_data (Shishi * handle,
				  Shishi_asn1 encprivpart,
				  const char *userdata, size_t userdatalen)
{
  int res;

  res = shishi_asn1_write (handle, encprivpart, "user-data",
			   userdata, userdatalen);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_priv_build:
 * @priv: priv as allocated by shishi_priv().
 * @key: key for session, used to encrypt data.
 *
 * Build checksum and set it in KRB-PRIV.  Note that this follows RFC
 * 1510bis and is incompatible with RFC 1510, although presumably few
 * implementations use the RFC1510 algorithm.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_priv_build (Shishi_priv * priv, Shishi_key * key)
{
  int res;
  char *buf;
  size_t buflen;
  char *der;
  size_t derlen;

  res = shishi_asn1_to_der (priv->handle, priv->encprivpart, &der, &derlen);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (priv->handle,
			   "Could not DER encode EncPrivPart: %s\n",
			   shishi_strerror (res));
      return res;
    }

  res = shishi_encrypt (priv->handle, key, SHISHI_KEYUSAGE_KRB_PRIV,
			der, derlen, &buf, &buflen);

  free (der);

  if (res != SHISHI_OK)
    {
      shishi_error_printf (priv->handle, "Cannot encrypt EncPrivPart.\n");
      return res;
    }

  res = shishi_priv_set_enc_part (priv->handle, priv->priv,
				  shishi_key_type (key), buf, buflen);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_priv_process:
 * @priv: priv as allocated by shishi_priv().
 * @key: key to use to decrypt EncPrivPart.
 *
 * Decrypt encrypted data in KRB-PRIV and set the EncPrivPart in the
 * PRIV exchange.
 *
 * Return value: Returns SHISHI_OK iff successful,
 *   SHISHI_PRIV_BAD_KEYTYPE if an incompatible key type is used, or
 *   SHISHI_CRYPTO_ERROR if the actual decryption failed.
 **/
int
shishi_priv_process (Shishi_priv * priv, Shishi_key * key)
{
  int res;
  int i;
  char *buf;
  size_t buflen;
  char *cipher;
  size_t cipherlen;
  int32_t etype;

  res = shishi_priv_enc_part_etype (priv->handle, priv->priv, &etype);
  if (res != SHISHI_OK)
    return res;

  if (etype != shishi_key_type (key))
    return SHISHI_PRIV_BAD_KEYTYPE;

  res = shishi_asn1_read (priv->handle, priv->priv, "enc-part.cipher",
			  &cipher, &cipherlen);
  if (res != SHISHI_OK)
    return res;

  res = shishi_decrypt (priv->handle, key, SHISHI_KEYUSAGE_KRB_PRIV,
			cipher, cipherlen, &buf, &buflen);
  free (cipher);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (priv->handle,
			   "PRIV decryption failed, bad key?\n");
      return res;
    }

  /* The crypto is so 1980; no length indicator. Trim off pad bytes
     until we can parse it. */
  for (i = 0; i < 8; i++)
    {
      if (VERBOSEASN1 (priv->handle))
	printf ("Trying with %d pad in enckdcrep...\n", i);

      priv->encprivpart = shishi_der2asn1_encprivpart (priv->handle, &buf[0],
						       buflen - i);
      if (priv->encprivpart != NULL)
	break;
    }

  free (buf);

  if (priv->encprivpart == NULL)
    {
      shishi_error_printf (priv->handle, "Could not DER decode EncPrivPart. "
			   "Key probably correct (decrypt ok) though\n");
      return SHISHI_ASN1_ERROR;
    }

  return SHISHI_OK;
}
