/* encapreppart.c	Key distribution encrypted reply part functions
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

ASN1_TYPE
shishi_encapreppart (Shishi * handle)
{
  int res;
  ASN1_TYPE node = ASN1_TYPE_EMPTY;
  struct timeval tv;
  struct timezone tz;
  char usec[BUFSIZ];

  res = asn1_create_element (handle->asn1, "Kerberos5.EncAPRepPart",
			     &node, "EncAPRepPart");
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (node, "EncAPRepPart.ctime",
			  shishi_generalize_time (handle, time (NULL)), 0);
  if (res != ASN1_SUCCESS)
    goto error;

  gettimeofday (&tv, &tz);
  sprintf (usec, "%d", tv.tv_usec % 1000000);
  res = asn1_write_value (node, "EncAPRepPart.cusec", usec, 0);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (node, "EncAPRepPart.subkey", NULL, 0);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (node, "EncAPRepPart.seq-number", NULL, 0);
  if (res != ASN1_SUCCESS)
    goto error;

  /* see shishi_last_encapreppart() */
  handle->lastencapreppart = node;

  return node;

error:
  shishi_error_set (handle, libtasn1_strerror (res));
  if (node != ASN1_TYPE_EMPTY)
    asn1_delete_structure (&node);
  return ASN1_TYPE_EMPTY;
}

/**
 * shishi_encapreppart_print:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle open for writing.
 * @encapreppart: EncAPRepPart to print.
 * 
 * Print ASCII armored DER encoding of EncAPRepPart to file.
 * 
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_encapreppart_print (Shishi * handle, FILE * fh, ASN1_TYPE encapreppart)
{
  return _shishi_print_armored_data (handle, fh, encapreppart,
				     "EncAPRepPart", NULL);
}

/**
 * shishi_encapreppart_save:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle open for writing.
 * @encapreppart: EncAPRepPart to save.
 * 
 * Save DER encoding of EncAPRepPart to file.
 * 
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_encapreppart_save (Shishi * handle, FILE * fh, ASN1_TYPE encapreppart)
{
  return _shishi_save_data (handle, fh, encapreppart, "EncAPRepPart");
}

/**
 * shishi_encapreppart_to_file:
 * @handle: shishi handle as allocated by shishi_init().
 * @encapreppart: EncAPRepPart to save.
 * @filetype: input variable specifying type of file to be written,
 *            see Shishi_filetype.
 * @filename: input variable with filename to write to.
 * 
 * Write EncAPRepPart to file in specified TYPE.  The file will be
 * truncated if it exists.
 * 
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_encapreppart_to_file (Shishi * handle, ASN1_TYPE encapreppart,
			     int filetype, char *filename)
{
  FILE *fh;
  int res;

  if (!SILENT (handle))
    printf (_("Writing EncAPRepPart to %s...\n"), filename);

  fh = fopen (filename, "w");
  if (fh == NULL)
    return SHISHI_FOPEN_ERROR;

  if (!SILENT (handle))
    printf (_("Writing EncAPRepPart in %s format...\n"),
	    filetype == SHISHI_FILETYPE_TEXT ? "TEXT" : "DER");

  if (filetype == SHISHI_FILETYPE_TEXT)
    res = shishi_encapreppart_print (handle, fh, encapreppart);
  else
    res = shishi_encapreppart_save (handle, fh, encapreppart);
  if (res != SHISHI_OK)
    return res;

  res = fclose (fh);
  if (res != 0)
    return SHISHI_FCLOSE_ERROR;

  if (!SILENT (handle))
    printf (_("Writing EncAPRepPart to %s...done\n"), filename);

  return SHISHI_OK;
}

/**
 * shishi_encapreppart_parse:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle open for reading.
 * @encapreppart: output variable with newly allocated EncAPRepPart.
 * 
 * Read ASCII armored DER encoded EncAPRepPart from file and populate given
 * variable.
 * 
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_encapreppart_parse (Shishi * handle, FILE * fh,
			   ASN1_TYPE * encapreppart)
{
  return _shishi_encapreppart_input (handle, fh, encapreppart, 0);
}

/**
 * shishi_encapreppart_read:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle open for reading.
 * @encapreppart: output variable with newly allocated EncAPRepPart.
 * 
 * Read DER encoded EncAPRepPart from file and populate given variable.
 * 
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_encapreppart_read (Shishi * handle, FILE * fh,
			  ASN1_TYPE * encapreppart)
{
  return _shishi_encapreppart_input (handle, fh, encapreppart, 1);
}

/**
 * shishi_encapreppart_from_file:
 * @handle: shishi handle as allocated by shishi_init().
 * @encapreppart: output variable with newly allocated EncAPRepPart.
 * @filetype: input variable specifying type of file to be read,
 *            see Shishi_filetype.
 * @filename: input variable with filename to read from.
 * 
 * Read EncAPRepPart from file in specified TYPE.
 * 
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_encapreppart_from_file (Shishi * handle, ASN1_TYPE * encapreppart,
			       int filetype, char *filename)
{
  int res;
  FILE *fh;

  if (!SILENT (handle))
    printf (_("Reading EncAPRepPart from %s...\n"), filename);

  fh = fopen (filename, "r");
  if (fh == NULL)
    return SHISHI_FOPEN_ERROR;

  if (!SILENT (handle))
    printf (_("Reading EncAPRepPart in %s format...\n"),
	    filetype == SHISHI_FILETYPE_TEXT ? "TEXT" : "DER");

  if (filetype == SHISHI_FILETYPE_TEXT)
    res = shishi_encapreppart_parse (handle, fh, encapreppart);
  else
    res = shishi_encapreppart_read (handle, fh, encapreppart);
  if (res != SHISHI_OK)
    return res;

  res = fclose (fh);
  if (res != 0)
    return SHISHI_FCLOSE_ERROR;

  if (!SILENT (handle))
    printf (_("Reading EncAPRepPart from %s...done\n"), filename);

  return SHISHI_OK;
}

/**
 * shishi_encapreppart_get_key:
 * @handle: shishi handle as allocated by shishi_init().
 * @encapreppart: input EncAPRepPart variable.
 * @keytype: output variable that holds key type.
 * @keyvalue: output array with key.
 * @keyvalue_len: on input, maximum size of output array with key,
 *                on output, holds the actual size of output array with key.
 * 
 * Extract the subkey from the encrypted AP-REP part.
 * 
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_encapreppart_get_key (Shishi * handle,
			     ASN1_TYPE encapreppart,
			     int *keytype,
			     unsigned char *keyvalue, int *keyvalue_len)
{
  int res;
  unsigned char buf[BUFSIZ];
  int buflen;

  *keytype = 0;
  buflen = sizeof (*keytype);
  res = _shishi_asn1_field (handle, encapreppart,
			    keytype, &buflen, "EncAPRepPart.subkey.keytype");
  if (res != SHISHI_OK)
    return res;

  res = _shishi_asn1_field (handle, encapreppart,
			    keyvalue, keyvalue_len,
			    "EncAPRepPart.subkey.keyvalue");
  if (res != ASN1_SUCCESS)
    return res;

  return SHISHI_OK;
}

int
shishi_encapreppart_ctime_get (Shishi * handle,
			       ASN1_TYPE encapreppart, char *ctime)
{
  int len;
  int res;

  len = GENERALIZEDTIME_TIME_LEN + 1;
  res = _shishi_asn1_field (handle, encapreppart,
			    ctime, &len, "EncAPRepPart.ctime");
  if (res == SHISHI_OK && len == GENERALIZEDTIME_TIME_LEN)
    ctime[len] = '\0';

  return res;
}

int
shishi_encapreppart_ctime_set (Shishi * handle,
			       ASN1_TYPE encapreppart, char *ctime)
{
  int res;

  res = asn1_write_value (encapreppart, "EncAPRepPart.ctime",
			  ctime, strlen (ctime));
  if (res != ASN1_SUCCESS)
    {
      shishi_error_set (handle, libtasn1_strerror (res));
      return SHISHI_ASN1_ERROR;
    }

  return SHISHI_OK;
}

int
shishi_encapreppart_cusec_get (Shishi * handle,
			       ASN1_TYPE encapreppart, int *cusec)
{
  int len;
  int res;

  len = sizeof (*cusec);
  *cusec = 0;
  res = _shishi_asn1_field (handle, encapreppart, cusec, &len,
			    "EncAPRepPart.cusec");
  *cusec = ntohl (*cusec);

  return res;
}

int
shishi_encapreppart_cusec_set (Shishi * handle,
			       ASN1_TYPE encapreppart, int cusec)
{
  char usec[BUFSIZ];
  int res;

  sprintf (usec, "%d", cusec);
  res = asn1_write_value (encapreppart, "EncAPRepPart.cusec", usec, 0);
  if (res != ASN1_SUCCESS)
    {
      shishi_error_set (handle, libtasn1_strerror (res));
      return SHISHI_ASN1_ERROR;
    }

  return SHISHI_OK;
}

int
shishi_encapreppart_time_copy (Shishi * handle,
			       ASN1_TYPE encapreppart,
			       ASN1_TYPE authenticator)
{
  char buf[BUFSIZ];
  int buflen;
  int res;

  buflen = BUFSIZ;
  res = asn1_read_value (authenticator, "Authenticator.cusec", buf, &buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (encapreppart, "EncAPRepPart.cusec", buf, buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  buflen = BUFSIZ;
  res = asn1_read_value (authenticator, "Authenticator.ctime", buf, &buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (encapreppart, "EncAPRepPart.ctime", buf, buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  return SHISHI_OK;

error:
  shishi_error_printf (handle, "shishi_encapreppart_time_copy() failure: %s",
		       libtasn1_strerror (res));
  return SHISHI_ASN1_ERROR;
}
