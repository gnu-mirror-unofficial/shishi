/* authenticator.c	functions for authenticators
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
 * shishi_authenticator:
 * @handle: shishi handle as allocated by shishi_init().
 *
 * This function creates a new Authenticator, populated with some
 * default values.  It uses the current time as returned by the system
 * for the ctime and cusec fields.
 *
 * Return value: Returns the authenticator or NULL on
 * failure.
 **/
Shishi_asn1
shishi_authenticator (Shishi * handle)
{
  int res;
  Shishi_asn1 node = NULL;
  struct timeval tv;
  struct timezone tz;
  char usec[BUFSIZ];

  node = shishi_asn1_authenticator (handle);
  if (!node)
    return NULL;

  res =
    shishi_asn1_write (handle, node, "Authenticator.authenticator-vno", "5",
		       0);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_authenticator_set_crealm (handle, node,
					 shishi_realm_default (handle));
  if (res != SHISHI_OK)
    goto error;

  res = shishi_authenticator_set_cname (handle, node, SHISHI_NT_PRINCIPAL,
					shishi_principal_default (handle));
  if (res != SHISHI_OK)
    goto error;

  gettimeofday (&tv, &tz);
  sprintf (usec, "%ld", tv.tv_usec % 1000000);
  res = shishi_asn1_write (handle, node, "Authenticator.cusec", usec, 0);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_write (handle, node, "Authenticator.ctime",
			   shishi_generalize_time (handle, time (NULL)), 0);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_write (handle, node, "Authenticator.subkey", NULL, 0);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_write (handle, node, "Authenticator.seq-number", NULL, 0);
  if (res != SHISHI_OK)
    goto error;

#if 0
  res =
    shishi_asn1_write (handle, node, "Authenticator.authorization-data", NULL,
		       0);
  if (res != SHISHI_OK)
    goto error;
#endif

  return node;

error:
  shishi_asn1_done (handle, node);
  return NULL;
}

/**
 * shishi_authenticator_print:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle open for writing.
 * @authenticator: authenticator as allocated by shishi_authenticator().
 *
 * Print ASCII armored DER encoding of authenticator to file.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_authenticator_print (Shishi * handle,
			    FILE * fh, Shishi_asn1 authenticator)
{
  return _shishi_print_armored_data (handle, fh, authenticator,
				     "Authenticator", NULL);
}

/**
 * shishi_authenticator_save:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle open for writing.
 * @authenticator: authenticator as allocated by shishi_authenticator().
 *
 * Save DER encoding of authenticator to file.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_authenticator_save (Shishi * handle,
			   FILE * fh, Shishi_asn1 authenticator)
{
  return _shishi_save_data (handle, fh, authenticator, "Authenticator");
}

/**
 * shishi_authenticator_to_file:
 * @handle: shishi handle as allocated by shishi_init().
 * @authenticator: Authenticator to save.
 * @filetype: input variable specifying type of file to be written,
 *            see Shishi_filetype.
 * @filename: input variable with filename to write to.
 *
 * Write Authenticator to file in specified TYPE.  The file will be
 * truncated if it exists.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_authenticator_to_file (Shishi * handle, Shishi_asn1 authenticator,
			      int filetype, char *filename)
{
  FILE *fh;
  int res;

  if (VERBOSE (handle))
    printf (_("Writing Authenticator to %s...\n"), filename);

  fh = fopen (filename, "w");
  if (fh == NULL)
    return SHISHI_FOPEN_ERROR;

  if (VERBOSE (handle))
    printf (_("Writing Authenticator in %s format...\n"),
	    filetype == SHISHI_FILETYPE_TEXT ? "TEXT" : "DER");

  if (filetype == SHISHI_FILETYPE_TEXT)
    res = shishi_authenticator_print (handle, fh, authenticator);
  else
    res = shishi_authenticator_save (handle, fh, authenticator);
  if (res != SHISHI_OK)
    return res;

  res = fclose (fh);
  if (res != 0)
    return SHISHI_FCLOSE_ERROR;

  if (VERBOSE (handle))
    printf (_("Writing Authenticator to %s...done\n"), filename);

  return SHISHI_OK;
}

/**
 * shishi_authenticator_parse:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle open for reading.
 * @authenticator: output variable with newly allocated authenticator.
 *
 * Read ASCII armored DER encoded authenticator from file and populate
 * given authenticator variable.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_authenticator_parse (Shishi * handle,
			    FILE * fh, Shishi_asn1 * authenticator)
{
  return _shishi_authenticator_input (handle, fh, authenticator, 0);
}

/**
 * shishi_authenticator_read:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle open for reading.
 * @authenticator: output variable with newly allocated authenticator.
 *
 * Read DER encoded authenticator from file and populate given
 * authenticator variable.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_authenticator_read (Shishi * handle,
			   FILE * fh, Shishi_asn1 * authenticator)
{
  return _shishi_authenticator_input (handle, fh, authenticator, 1);
}

/**
 * shishi_authenticator_from_file:
 * @handle: shishi handle as allocated by shishi_init().
 * @authenticator: output variable with newly allocated Authenticator.
 * @filetype: input variable specifying type of file to be read,
 *            see Shishi_filetype.
 * @filename: input variable with filename to read from.
 *
 * Read Authenticator from file in specified TYPE.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_authenticator_from_file (Shishi * handle, Shishi_asn1 * authenticator,
				int filetype, char *filename)
{
  int res;
  FILE *fh;

  if (VERBOSE (handle))
    printf (_("Reading Authenticator from %s...\n"), filename);

  fh = fopen (filename, "r");
  if (fh == NULL)
    return SHISHI_FOPEN_ERROR;

  if (VERBOSE (handle))
    printf (_("Reading Authenticator in %s format...\n"),
	    filetype == SHISHI_FILETYPE_TEXT ? "TEXT" : "DER");

  if (filetype == SHISHI_FILETYPE_TEXT)
    res = shishi_authenticator_parse (handle, fh, authenticator);
  else
    res = shishi_authenticator_read (handle, fh, authenticator);
  if (res != SHISHI_OK)
    return res;

  res = fclose (fh);
  if (res != 0)
    return SHISHI_FCLOSE_ERROR;

  if (VERBOSE (handle))
    printf (_("Reading Authenticator from %s...done\n"), filename);

  return SHISHI_OK;
}

/**
 * shishi_authenticator_set_crealm:
 * @handle: shishi handle as allocated by shishi_init().
 * @authenticator: authenticator as allocated by shishi_authenticator().
 * @crealm: input array with realm.
 *
 * Set realm field in authenticator to specified value.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_authenticator_set_crealm (Shishi * handle,
				 Shishi_asn1 authenticator,
				 const char *crealm)
{
  int res;

  res = shishi_asn1_write (handle, authenticator, "Authenticator.crealm",
			   crealm, 0);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_authenticator_set_cname:
 * @handle: shishi handle as allocated by shishi_init().
 * @authenticator: authenticator as allocated by shishi_authenticator().
 * @name_type: type of principial, see Shishi_name_type, usually
 *             SHISHI_NT_UNKNOWN.
 * @principal: input array with principal name.
 *
 * Set principal field in authenticator to specified value.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_authenticator_set_cname (Shishi * handle,
				Shishi_asn1 node,
				Shishi_name_type name_type,
				const char *principal)
{
  int res;
  char buf[BUFSIZ];

  sprintf (buf, "%d", name_type);

  res = shishi_asn1_write (handle, node, "Authenticator.cname.name-type",
			   buf, 0);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_write (handle, node, "Authenticator.cname.name-string",
			   NULL, 0);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_write (handle, node, "Authenticator.cname.name-string",
			   "NEW", 1);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_write (handle, node, "Authenticator.cname.name-string.?1",
			   principal, strlen (principal));
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

int
shishi_authenticator_ctime_get (Shishi * handle,
				Shishi_asn1 authenticator, char *ctime)
{
  int len;
  int res;

  len = GENERALIZEDTIME_TIME_LEN + 1;
  res = shishi_asn1_field (handle, authenticator,
			   ctime, &len, "Authenticator.ctime");
  if (res == SHISHI_OK && len == GENERALIZEDTIME_TIME_LEN)
    ctime[len] = '\0';

  return res;
}

int
shishi_authenticator_cusec_get (Shishi * handle,
				Shishi_asn1 authenticator, int *cusec)
{
  int res;

  res = shishi_asn1_integer_field (handle, authenticator, cusec,
				   "Authenticator.cusec");
  *cusec = ntohl (*cusec);

  return res;
}

int
shishi_authenticator_cname_get (Shishi * handle,
				Shishi_asn1 authenticator,
				char *cname, int *cnamelen)
{
  return shishi_principal_name_get (handle, authenticator,
				    "Authenticator.cname", cname, cnamelen);
}

int
shishi_authenticator_cnamerealm_get (Shishi * handle,
				     Shishi_asn1 authenticator,
				     char *cnamerealm, int *cnamerealmlen)
{
  return shishi_principal_name_realm_get (handle, authenticator,
					  "Authenticator.cname",
					  authenticator,
					  "Authenticator.crealm",
					  cnamerealm, cnamerealmlen);
}

int
shishi_authenticator_remove_cksum (Shishi * handle, Shishi_asn1 authenticator)
{
  int res;

  res = shishi_asn1_write (handle, authenticator, "Authenticator.cksum",
			   NULL, 0);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_authenticator_cksum:
 * @handle: shishi handle as allocated by shishi_init().
 * @authenticator: authenticator as allocated by shishi_authenticator().
 * @cksumtype: output checksum type.
 * @cksum: output checksum data from authenticator.
 * @cksumlen: on input, maximum size of output checksum data buffer,
 *            on output, actual size of output checksum data buffer.
 *
 * Read checksum value from authenticator.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_authenticator_cksum (Shishi * handle,
			    Shishi_asn1 authenticator,
			    int *cksumtype, char *cksum, size_t * cksumlen)
{
  int res;

  res = shishi_asn1_integer_field (handle, authenticator, cksumtype,
				   "Authenticator.cksum.cksumtype");
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_field (handle, authenticator, cksum, cksumlen,
			   "Authenticator.cksum.checksum");
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_authenticator_set_cksum:
 * @handle: shishi handle as allocated by shishi_init().
 * @authenticator: authenticator as allocated by shishi_authenticator().
 * @cksumtype: input checksum type to store in authenticator.
 * @cksum: input checksum data to store in authenticator.
 * @cksumlen: size of input checksum data to store in authenticator.
 *
 * Store checksum value in authenticator.  A checksum is usually created
 * by calling shishi_checksum() on some application specific data using
 * the key from the ticket that is being used.  To save time, you may
 * want to use shishi_authenticator_add_cksum() instead, which calculates
 * the checksum and calls this function in one step.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_authenticator_set_cksum (Shishi * handle,
				Shishi_asn1 authenticator,
				int cksumtype, char *cksum, int cksumlen)
{
  char format[BUFSIZ];
  int res;

  sprintf (format, "%i", cksumtype);
  res =
    shishi_asn1_write (handle, authenticator, "Authenticator.cksum.cksumtype",
		       format, 0);
  if (res != SHISHI_OK)
    return SHISHI_ASN1_ERROR;

  res =
    shishi_asn1_write (handle, authenticator, "Authenticator.cksum.checksum",
		       cksum, cksumlen);
  if (res != SHISHI_OK)
    return SHISHI_ASN1_ERROR;

  return SHISHI_OK;
}

/**
 * shishi_authenticator_clear_authorizationdata:
 * @handle: shishi handle as allocated by shishi_init().
 * @authenticator: Authenticator as allocated by shishi_authenticator().
 *
 * Remove the authorization-data field from Authenticator.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_authenticator_clear_authorizationdata (Shishi * handle,
					      Shishi_asn1 authenticator)
{
  int res;

  res =
    shishi_asn1_write (handle, authenticator,
		       "Authenticator.authorization-data", NULL, 0);
  if (res != SHISHI_OK)
    return SHISHI_ASN1_ERROR;

  return SHISHI_OK;
}

/**
 * shishi_authenticator_add_authorizationdata:
 * @handle: shishi handle as allocated by shishi_init().
 * @authenticator: authenticator as allocated by shishi_authenticator().
 * @adtype: input authorization data type to add.
 * @addata: input authorization data to add.
 * @addatalen: size of input authorization data to add.
 *
 * Add authorization data to authenticator.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_authenticator_add_authorizationdata (Shishi * handle,
					    Shishi_asn1 authenticator,
					    int adtype,
					    char *addata, int addatalen)
{
  char format[BUFSIZ];
  char buf[BUFSIZ];
  int res;
  int i;

  res = shishi_asn1_write (handle, authenticator,
			   "Authenticator.authorization-data", "NEW", 1);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_number_of_elements (handle, authenticator,
					"Authenticator.authorization-data",
					&i);
  if (res != SHISHI_OK)
    return res;

  sprintf (buf, "%d", adtype);
  sprintf (format, "Authenticator.authorization-data.?%d.ad-type", i);
  res = shishi_asn1_write (handle, authenticator, format, buf, 0);
  if (res != SHISHI_OK)
    return res;

  sprintf (format, "Authenticator.authorization-data.?%d.ad-data", i);
  res = shishi_asn1_write (handle, authenticator, format, addata, addatalen);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_authenticator_authorizationdata:
 * @handle: shishi handle as allocated by shishi_init().
 * @authenticator: authenticator as allocated by shishi_authenticator().
 * @adtype: output authorization data type.
 * @addata: output authorization data.
 * @addatalen: on input, maximum size of output authorization data,
               on output, actual size of authorization data.
 * @nth: element number of authorization-data to extract.
 *
 * Extract n:th authorization data from authenticator.  The first
 * field is 1.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_authenticator_authorizationdata (Shishi * handle,
					Shishi_asn1 authenticator,
					int *adtype,
					char *addata, int *addatalen, int nth)
{
  char *format;
  int res;
  int i;

  res = shishi_asn1_number_of_elements (handle, authenticator,
					"Authenticator.authorization-data",
					&i);
  if (res != SHISHI_OK)
    return SHISHI_ASN1_ERROR;

  if (nth > i)
    return SHISHI_OUT_OF_RANGE;

  shishi_asprintf (&format, "Authenticator.authorization-data.?%d.ad-type",
		   nth);
  res = shishi_asn1_integer_field (handle, authenticator, adtype, format);
  free (format);
  if (res != SHISHI_OK)
    return res;

  shishi_asprintf (&format, "Authenticator.authorization-data.?%d.ad-data",
		   i);
  res = shishi_asn1_field (handle, authenticator, addata, addatalen, format);
  free (format);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_authenticator_add_cksum:
 * @handle: shishi handle as allocated by shishi_init().
 * @authenticator: authenticator as allocated by shishi_authenticator().
 * @enckdcreppart: ticket information where the key is taken from.
 * @data: input array with data to calculate checksum on.
 * @datalen: size of input array with data to calculate checksum on.
 *
 * Calculate checksum for data and store it in the authenticator.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_authenticator_add_cksum (Shishi * handle,
				Shishi_asn1 authenticator,
				Shishi_key * key,
				int keyusage, char *data, int datalen)
{
  int res;

  if (data && datalen > 0)
    {
      char cksum[BUFSIZ];
      int cksumlen;
      int cksumtype = shishi_cipher_defaultcksumtype (shishi_key_type (key));

      cksumlen = sizeof (cksum);
      res = shishi_checksum (handle, key, keyusage, cksumtype,
			     data, datalen, cksum, &cksumlen);
      if (res != SHISHI_OK)
	return res;

      res = shishi_authenticator_set_cksum (handle, authenticator,
					    cksumtype, cksum, cksumlen);
    }
  else
    res = shishi_authenticator_remove_cksum (handle, authenticator);

  return res;
}
