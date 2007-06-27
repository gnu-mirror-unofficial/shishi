/* encapreppart.c --- Encrypted authentication reply part functions.
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

/**
 * shishi_encapreppart:
 * @handle: shishi handle as allocated by shishi_init().
 *
 * This function creates a new EncAPRepPart, populated with some
 * default values.  It uses the current time as returned by the system
 * for the ctime and cusec fields.
 *
 * Return value: Returns the encapreppart or NULL on failure.
 **/
Shishi_asn1
shishi_encapreppart (Shishi * handle)
{
  int res;
  Shishi_asn1 node = NULL;
  struct timeval tv;
  uint32_t seqnr;

  res = gettimeofday (&tv, NULL);
  if (res)
    return NULL;

  node = shishi_asn1_encapreppart (handle);
  if (!node)
    return NULL;

  res = shishi_asn1_write (handle, node, "ctime",
			   shishi_generalize_time (handle, time (NULL)), 0);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_encapreppart_cusec_set (handle, node, tv.tv_usec % 1000000);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_write (handle, node, "subkey", NULL, 0);
  if (res != SHISHI_OK)
    goto error;

  /*
   * For sequence numbers to adequately support the detection of
   * replays they SHOULD be non-repeating, even across connection
   * boundaries. The initial sequence number SHOULD be random and
   * uniformly distributed across the full space of possible sequence
   * numbers, so that it cannot be guessed by an attacker and so that
   * it and the successive sequence numbers do not repeat other
   * sequences.
   */
  shishi_randomize (handle, 0, &seqnr, sizeof (seqnr));

  /*
   * Implementation note: as noted before, some implementations omit
   * the optional sequence number when its value would be zero.
   * Implementations MAY accept an omitted sequence number when
   * expecting a value of zero, and SHOULD NOT transmit an
   * Authenticator with a initial sequence number of zero.
   */
  if (seqnr == 0)
    seqnr++;

  res = shishi_encapreppart_seqnumber_set (handle, node, seqnr);
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
			     int filetype, const char *filename)
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
    return SHISHI_IO_ERROR;

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
			       int filetype, const char *filename)
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
    return SHISHI_IO_ERROR;

  if (VERBOSE (handle))
    printf (_("Reading EncAPRepPart from %s...done\n"), filename);

  return SHISHI_OK;
}

/**
 * shishi_encapreppart_get_key:
 * @handle: shishi handle as allocated by shishi_init().
 * @encapreppart: input EncAPRepPart variable.
 * @key: newly allocated key.
 *
 * Extract the subkey from the encrypted AP-REP part.
 *
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_encapreppart_get_key (Shishi * handle,
			     Shishi_asn1 encapreppart, Shishi_key ** key)
{
  int res;
  char *buf;
  size_t buflen;
  int32_t keytype;

  res = shishi_asn1_read_int32 (handle, encapreppart,
				"subkey.keytype", &keytype);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_read (handle, encapreppart, "subkey.keyvalue",
			  &buf, &buflen);
  if (res != SHISHI_OK)
    return res;

  if (shishi_cipher_keylen (keytype) != buflen)
    return SHISHI_ENCAPREPPART_BAD_KEYTYPE;

  res = shishi_key_from_value (handle, keytype, buf, key);
  free (buf);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_encapreppart_ctime:
 * @handle: shishi handle as allocated by shishi_init().
 * @encapreppart: EncAPRepPart as allocated by shishi_encapreppart().
 * @t: newly allocated zero-terminated character array with client time.
 *
 * Extract client time from EncAPRepPart.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_encapreppart_ctime (Shishi * handle,
			   Shishi_asn1 encapreppart, char **t)
{
  return shishi_time (handle, encapreppart, "ctime", t);
}

/**
 * shishi_encapreppart_ctime_set:
 * @handle: shishi handle as allocated by shishi_init().
 * @encapreppart: EncAPRepPart as allocated by shishi_encapreppart().
 * @t: string with generalized time value to store in EncAPRepPart.
 *
 * Store client time in EncAPRepPart.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_encapreppart_ctime_set (Shishi * handle,
			       Shishi_asn1 encapreppart, const char *t)
{
  int res;

  res = shishi_asn1_write (handle, encapreppart, "ctime",
			   t, SHISHI_GENERALIZEDTIME_LENGTH);
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
			       Shishi_asn1 encapreppart, uint32_t * cusec)
{
  int res;

  res = shishi_asn1_read_uint32 (handle, encapreppart, "cusec", cusec);
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
			       Shishi_asn1 encapreppart, uint32_t cusec)
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
				   Shishi_asn1 encapreppart,
				   uint32_t * seqnumber)
{
  int res;

  res = shishi_asn1_read_uint32 (handle, encapreppart,
				 "seq-number", seqnumber);
  if (res != SHISHI_OK)
    return res;

  return res;
}

/**
 * shishi_encapreppart_seqnumber_remove:
 * @handle: shishi handle as allocated by shishi_init().
 * @encapreppart: encapreppart as allocated by shishi_encapreppart().
 *
 * Remove sequence number field in EncAPRepPart.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_encapreppart_seqnumber_remove (Shishi * handle,
				      Shishi_asn1 encapreppart)
{
  int res;

  res = shishi_asn1_write (handle, encapreppart, "seq-number", NULL, 0);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_encapreppart_seqnumber_set:
 * @handle: shishi handle as allocated by shishi_init().
 * @encapreppart: encapreppart as allocated by shishi_encapreppart().
 * @seqnumber: integer with sequence number field to store in encapreppart.
 *
 * Store sequence number field in EncAPRepPart.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_encapreppart_seqnumber_set (Shishi * handle,
				   Shishi_asn1 encapreppart,
				   uint32_t seqnumber)
{
  int res;

  res = shishi_asn1_write_uint32 (handle, encapreppart,
				  "seq-number", seqnumber);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_encapreppart_time_copy:
 * @handle: shishi handle as allocated by shishi_init().
 * @encapreppart: EncAPRepPart as allocated by shishi_encapreppart().
 * @authenticator: Authenticator to copy time fields from.
 *
 * Copy time fields from Authenticator into EncAPRepPart.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_encapreppart_time_copy (Shishi * handle,
			       Shishi_asn1 encapreppart,
			       Shishi_asn1 authenticator)
{
  char *buf;
  size_t buflen;
  int res;

  res = shishi_asn1_read (handle, authenticator, "cusec", &buf, &buflen);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_write (handle, encapreppart, "cusec", buf, buflen);
  free (buf);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_read (handle, authenticator, "ctime", &buf, &buflen);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_write (handle, encapreppart, "ctime", buf, buflen);
  free (buf);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}
