/* encapreppart.c	Key distribution encrypted reply part functions
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

Shishi_asn1
shishi_encapreppart (Shishi * handle)
{
  int res;
  Shishi_asn1 node = NULL;
  struct timeval tv;
  struct timezone tz;

  node = shishi_asn1_encapreppart (handle);
  if (!node)
    return NULL;

  res = shishi_asn1_write (handle, node, "ctime",
			   shishi_generalize_time (handle, time (NULL)), 0);
  if (res != SHISHI_OK)
    goto error;

  gettimeofday (&tv, &tz);
  res = shishi_asn1_write_integer (handle, node, "cusec",
				   tv.tv_usec % 1000000);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_write (handle, node, "subkey", NULL, 0);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_write (handle, node, "seq-number", NULL, 0);
  if (res != SHISHI_OK)
    goto error;

  return node;

error:
  shishi_asn1_done (handle, node);
  return NULL;
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
shishi_encapreppart_print (Shishi * handle, FILE * fh,
			   Shishi_asn1 encapreppart)
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
shishi_encapreppart_save (Shishi * handle, FILE * fh,
			  Shishi_asn1 encapreppart)
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
shishi_encapreppart_to_file (Shishi * handle, Shishi_asn1 encapreppart,
			     int filetype, char *filename)
{
  FILE *fh;
  int res;

  if (VERBOSE (handle))
    printf (_("Writing EncAPRepPart to %s...\n"), filename);

  fh = fopen (filename, "w");
  if (fh == NULL)
    return SHISHI_FOPEN_ERROR;

  if (VERBOSE (handle))
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

  if (VERBOSE (handle))
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
			   Shishi_asn1 * encapreppart)
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
			  Shishi_asn1 * encapreppart)
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
shishi_encapreppart_from_file (Shishi * handle, Shishi_asn1 * encapreppart,
			       int filetype, char *filename)
{
  int res;
  FILE *fh;

  if (VERBOSE (handle))
    printf (_("Reading EncAPRepPart from %s...\n"), filename);

  fh = fopen (filename, "r");
  if (fh == NULL)
    return SHISHI_FOPEN_ERROR;

  if (VERBOSE (handle))
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

  if (VERBOSE (handle))
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
			     Shishi_asn1 encapreppart,
			     int32_t *keytype,
			     char *keyvalue,
			     size_t *keyvalue_len)
{
  int res;

  *keytype = 0;
  res = shishi_asn1_read_int32 (handle, encapreppart,
				"subkey.keytype", keytype);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_read (handle, encapreppart,
			  "subkey.keyvalue",
			  keyvalue, keyvalue_len);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

int
shishi_encapreppart_ctime_get (Shishi * handle,
			       Shishi_asn1 encapreppart, char *ctime)
{
  int len;
  int res;

  len = GENERALIZEDTIME_TIME_LEN + 1;
  res = shishi_asn1_field (handle, encapreppart,
			   ctime, &len, "ctime");
  if (res == SHISHI_OK && len == GENERALIZEDTIME_TIME_LEN)
    ctime[len] = '\0';

  return res;
}

/**
 * shishi_encapreppart_ctime_set:
 * @handle: shishi handle as allocated by shishi_init().
 * @encapreppart: EncAPRepPart as allocated by shishi_encapreppart().
 * @ctime: string with generalized time value to store in EncAPRepPart.
 *
 * Store client time in EncAPRepPart.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_encapreppart_ctime_set (Shishi * handle,
			       Shishi_asn1 encapreppart, char *ctime)
{
  int res;

  res = shishi_asn1_write (handle, encapreppart, "ctime",
			   ctime, GENERALIZEDTIME_TIME_LEN);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_encapreppart_cusec_get:
 * @handle: shishi handle as allocated by shishi_init().
 * @encapreppart: EncAPRepPart as allocated by shishi_encapreppart().
 * @cusec: output integer with client microseconds field.
 *
 * Extract client microseconds field from EncAPRepPart.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_encapreppart_cusec_get (Shishi * handle,
			       Shishi_asn1 encapreppart, int *cusec)
{
  int res;

  res = shishi_asn1_read_integer (handle, encapreppart, "cusec", cusec);
  if (res != SHISHI_OK)
    return res;

  return res;
}

/**
 * shishi_encapreppart_cusec_set:
 * @handle: shishi handle as allocated by shishi_init().
 * @encapreppart: EncAPRepPart as allocated by shishi_encapreppart().
 * @cusec: client microseconds to set in authenticator, 0-999999.
 *
 * Set the cusec field in the Authenticator.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_encapreppart_cusec_set (Shishi * handle,
				Shishi_asn1 encapreppart,
				int cusec)
{
  int res;

  res = shishi_asn1_write_integer (handle, encapreppart, "cusec", cusec);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_encapreppart_seqnumber_get:
 * @handle: shishi handle as allocated by shishi_init().
 * @encapreppart: EncAPRepPart as allocated by shishi_encapreppart().
 * @seqnumber: output integer with sequence number field.
 *
 * Extract sequence number field from EncAPRepPart.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_encapreppart_seqnumber_get (Shishi * handle,
				   Shishi_asn1 encapreppart, int *seqnumber)
{
  int res;

  res = shishi_asn1_read_integer (handle, encapreppart,
				  "seq-number", seqnumber);
  if (res != SHISHI_OK)
    return res;

  return res;
}

int
shishi_encapreppart_time_copy (Shishi * handle,
			       Shishi_asn1 encapreppart,
			       Shishi_asn1 authenticator)
{
  char buf[BUFSIZ];
  int buflen;
  int res;

  buflen = BUFSIZ;
  res = shishi_asn1_read (handle, authenticator, "cusec",
			  buf, &buflen);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_write (handle, encapreppart, "cusec",
			   buf, buflen);
  if (res != SHISHI_OK)
    return res;

  buflen = BUFSIZ;
  res = shishi_asn1_read (handle, authenticator, "ctime",
			  buf, &buflen);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_write (handle, encapreppart, "ctime",
			   buf, buflen);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}
