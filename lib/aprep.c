/* aprep.c --- AP-REP functions.
 * Copyright (C) 2002, 2003, 2004, 2007  Simon Josefsson
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

/* Get _shishi_print_armored_data, etc. */
#include "diskio.h"

#define SHISHI_APREP_DEFAULT_PVNO "5"
#define SHISHI_APREP_DEFAULT_PVNO_LEN 0
#define SHISHI_APREP_DEFAULT_MSG_TYPE      "15"	/* KRB_AP_REP */
#define SHISHI_APREP_DEFAULT_MSG_TYPE_LEN  0
#define SHISHI_APREP_DEFAULT_ENC_PART_ETYPE "0"
#define SHISHI_APREP_DEFAULT_ENC_PART_ETYPE_LEN 0
#define SHISHI_APREP_DEFAULT_ENC_PART_KVNO "0"
#define SHISHI_APREP_DEFAULT_ENC_PART_KVNO_LEN 0
#define SHISHI_APREP_DEFAULT_ENC_PART_CIPHER ""
#define SHISHI_APREP_DEFAULT_ENC_PART_CIPHER_LEN 0

/**
 * shishi_aprep:
 * @handle: shishi handle as allocated by shishi_init().
 *
 * This function creates a new AP-REP, populated with some default
 * values.
 *
 * Return value: Returns the authenticator or NULL on
 * failure.
 **/
Shishi_asn1
shishi_aprep (Shishi * handle)
{
  Shishi_asn1 node;
  int res;

  node = shishi_asn1_aprep (handle);
  if (!node)
    return NULL;

  res = shishi_asn1_write (handle, node, "pvno",
			   SHISHI_APREP_DEFAULT_PVNO,
			   SHISHI_APREP_DEFAULT_PVNO_LEN);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_write (handle, node, "msg-type",
			   SHISHI_APREP_DEFAULT_MSG_TYPE,
			   SHISHI_APREP_DEFAULT_MSG_TYPE_LEN);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_write (handle, node, "enc-part.etype",
			   SHISHI_APREP_DEFAULT_ENC_PART_ETYPE,
			   SHISHI_APREP_DEFAULT_ENC_PART_ETYPE_LEN);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_write (handle, node, "enc-part.kvno",
			   SHISHI_APREP_DEFAULT_ENC_PART_KVNO,
			   SHISHI_APREP_DEFAULT_ENC_PART_KVNO_LEN);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_write (handle, node, "enc-part.cipher",
			   SHISHI_APREP_DEFAULT_ENC_PART_CIPHER,
			   SHISHI_APREP_DEFAULT_ENC_PART_CIPHER_LEN);
  if (res != SHISHI_OK)
    goto error;

  return node;

error:
  shishi_asn1_done (handle, node);
  return NULL;
}

/**
 * shishi_aprep_print:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle open for writing.
 * @aprep: AP-REP to print.
 *
 * Print ASCII armored DER encoding of AP-REP to file.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_aprep_print (Shishi * handle, FILE * fh, Shishi_asn1 aprep)
{
  return _shishi_print_armored_data (handle, fh, aprep, "AP-REP", NULL);
}

/**
 * shishi_aprep_save:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle open for writing.
 * @aprep: AP-REP to save.
 *
 * Save DER encoding of AP-REP to file.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_aprep_save (Shishi * handle, FILE * fh, Shishi_asn1 aprep)
{
  return _shishi_save_data (handle, fh, aprep, "AP-REP");
}

/**
 * shishi_aprep_to_file:
 * @handle: shishi handle as allocated by shishi_init().
 * @aprep: AP-REP to save.
 * @filetype: input variable specifying type of file to be written,
 *            see Shishi_filetype.
 * @filename: input variable with filename to write to.
 *
 * Write AP-REP to file in specified TYPE.  The file will be
 * truncated if it exists.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_aprep_to_file (Shishi * handle, Shishi_asn1 aprep,
		      int filetype, const char *filename)
{
  FILE *fh;
  int res;

  if (VERBOSE (handle))
    printf (_("Writing AP-REP to %s...\n"), filename);

  fh = fopen (filename, "w");
  if (fh == NULL)
    return SHISHI_FOPEN_ERROR;

  if (VERBOSE (handle))
    printf (_("Writing AP-REP in %s format...\n"),
	    filetype == SHISHI_FILETYPE_TEXT ? "TEXT" : "DER");

  if (filetype == SHISHI_FILETYPE_TEXT)
    res = shishi_aprep_print (handle, fh, aprep);
  else
    res = shishi_aprep_save (handle, fh, aprep);
  if (res != SHISHI_OK)
    return res;

  res = fclose (fh);
  if (res != 0)
    return SHISHI_IO_ERROR;

  if (VERBOSE (handle))
    printf (_("Writing AP-REP to %s...done\n"), filename);

  return SHISHI_OK;
}

/**
 * shishi_aprep_parse:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle open for reading.
 * @aprep: output variable with newly allocated AP-REP.
 *
 * Read ASCII armored DER encoded AP-REP from file and populate given
 * variable.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_aprep_parse (Shishi * handle, FILE * fh, Shishi_asn1 * aprep)
{
  return _shishi_aprep_input (handle, fh, aprep, 0);
}

/**
 * shishi_aprep_read:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle open for reading.
 * @aprep: output variable with newly allocated AP-REP.
 *
 * Read DER encoded AP-REP from file and populate given variable.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_aprep_read (Shishi * handle, FILE * fh, Shishi_asn1 * aprep)
{
  return _shishi_aprep_input (handle, fh, aprep, 1);
}

/**
 * shishi_aprep_from_file:
 * @handle: shishi handle as allocated by shishi_init().
 * @aprep: output variable with newly allocated AP-REP.
 * @filetype: input variable specifying type of file to be read,
 *            see Shishi_filetype.
 * @filename: input variable with filename to read from.
 *
 * Read AP-REP from file in specified TYPE.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_aprep_from_file (Shishi * handle, Shishi_asn1 * aprep,
			int filetype, const char *filename)
{
  int res;
  FILE *fh;

  if (VERBOSE (handle))
    printf (_("Reading AP-REP from %s...\n"), filename);

  fh = fopen (filename, "r");
  if (fh == NULL)
    return SHISHI_FOPEN_ERROR;

  if (VERBOSE (handle))
    printf (_("Reading AP-REP in %s format...\n"),
	    filetype == SHISHI_FILETYPE_TEXT ? "TEXT" : "DER");

  if (filetype == SHISHI_FILETYPE_TEXT)
    res = shishi_aprep_parse (handle, fh, aprep);
  else
    res = shishi_aprep_read (handle, fh, aprep);
  if (res != SHISHI_OK)
    return res;

  res = fclose (fh);
  if (res != 0)
    return SHISHI_IO_ERROR;

  if (VERBOSE (handle))
    printf (_("Reading AP-REP from %s...done\n"), filename);

  return SHISHI_OK;
}

int
shishi_aprep_enc_part_set (Shishi * handle,
			   Shishi_asn1 aprep,
			   int etype, const char *buf, size_t buflen)
{
  int res;

  res = shishi_asn1_write (handle, aprep, "enc-part.cipher", buf, buflen);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_write_integer (handle, aprep, "enc-part.etype", etype);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

int
shishi_aprep_enc_part_add (Shishi * handle,
			   Shishi_asn1 aprep,
			   Shishi_asn1 encticketpart,
			   Shishi_asn1 encapreppart)
{
  int res;
  char *buf;
  size_t buflen;
  char *der;
  size_t derlen;
  Shishi_key *key;

  res = shishi_encticketpart_get_key (handle, encticketpart, &key);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_to_der (handle, encapreppart, &der, &derlen);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "Could not DER encode authenticator: %s\n",
			   shishi_strerror (res));
      return !SHISHI_OK;
    }

  der = xrealloc (der, derlen + 8);

  while ((derlen % 8) != 0)
    {
      der[derlen] = '\0';
      derlen++;
    }

  res = shishi_encrypt (handle, key, SHISHI_KEYUSAGE_ENCAPREPPART,
			der, derlen, &buf, &buflen);

  free (der);

  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "APRep encryption failed\n");
      return res;
    }

  res = shishi_aprep_enc_part_set (handle, aprep, shishi_key_type (key),
				   buf, buflen);

  free (buf);

  return res;
}

int
shishi_aprep_enc_part_make (Shishi * handle,
			    Shishi_asn1 aprep,
			    Shishi_asn1 encapreppart,
			    Shishi_asn1 authenticator,
			    Shishi_asn1 encticketpart)
{
  int res;

  res = shishi_encapreppart_time_copy (handle, encapreppart, authenticator);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "Could not copy time: %s\n",
			   shishi_error (handle));
      return res;
    }

  res = shishi_aprep_enc_part_add (handle, aprep, encticketpart,
				   encapreppart);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "Could not add encapreppart: %s\n",
			   shishi_error (handle));
      return res;
    }

  return SHISHI_OK;
}

/**
 * shishi_aprep_get_enc_part_etype:
 * @handle: shishi handle as allocated by shishi_init().
 * @aprep: AP-REP variable to get value from.
 * @etype: output variable that holds the value.
 *
 * Extract AP-REP.enc-part.etype.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_aprep_get_enc_part_etype (Shishi * handle,
				 Shishi_asn1 aprep, int32_t * etype)
{
  return shishi_asn1_read_int32 (handle, aprep, "enc-part.etype", etype);
}

int
shishi_aprep_decrypt (Shishi * handle,
		      Shishi_asn1 aprep,
		      Shishi_key * key,
		      int keyusage, Shishi_asn1 * encapreppart)
{
  int res;
  int i;
  char *buf;
  size_t buflen;
  char *cipher;
  size_t cipherlen;
  int etype;

  res = shishi_aprep_get_enc_part_etype (handle, aprep, &etype);
  if (res != SHISHI_OK)
    return res;

  if (etype != shishi_key_type (key))
    return SHISHI_APREP_BAD_KEYTYPE;

  res = shishi_asn1_read (handle, aprep, "enc-part.cipher",
			  &cipher, &cipherlen);
  if (res != SHISHI_OK)
    return res;

  res = shishi_decrypt (handle, key, keyusage, cipher, cipherlen,
			&buf, &buflen);
  free (cipher);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle,
			   "APRep decryption failed, wrong password?\n");
      return res;
    }

  /* The crypto is so 1980; no length indicator. Trim off pad bytes
     until we can parse it. */
  for (i = 0; i < 8; i++)
    {
      if (VERBOSEASN1 (handle))
	printf ("Trying with %d pad in enckdcrep...\n", i);

      *encapreppart = shishi_der2asn1_encapreppart (handle, &buf[0],
						    buflen - i);
      if (*encapreppart != NULL)
	break;
    }

  if (*encapreppart == NULL)
    {
      shishi_error_printf (handle, "Could not DER decode EncAPRepPart. "
			   "Password probably correct (decrypt ok) though\n");
      return SHISHI_ASN1_ERROR;
    }

  return SHISHI_OK;
}

int
shishi_aprep_verify (Shishi * handle,
		     Shishi_asn1 authenticator, Shishi_asn1 encapreppart)
{
  char *authenticatorctime;
  char *encapreppartctime;
  uint32_t authenticatorcusec, encapreppartcusec;
  int res;
  int different;

  /*
     3.2.5. Receipt of KRB_AP_REP message

     If a KRB_AP_REP message is returned, the client uses the session key from
     the credentials obtained for the server[3.10] to decrypt the message, and
     verifies that the timestamp and microsecond fields match those in the
     Authenticator it sent to the server. If they match, then the client is
     assured that the server is genuine. The sequence number and subkey (if
     present) are retained for later use.

   */

  res = shishi_authenticator_ctime (handle, authenticator,
				    &authenticatorctime);
  if (res != SHISHI_OK)
    return res;

  res = shishi_authenticator_cusec_get (handle, authenticator,
					&authenticatorcusec);
  if (res != SHISHI_OK)
    return res;

  res = shishi_encapreppart_ctime (handle, encapreppart, &encapreppartctime);
  if (res != SHISHI_OK)
    return res;

  res = shishi_encapreppart_cusec_get (handle, encapreppart,
				       &encapreppartcusec);
  if (res != SHISHI_OK)
    return res;

  if (VERBOSE (handle))
    {
      printf ("authenticator cusec %08x ctime %s\n", authenticatorcusec,
	      authenticatorctime);
      printf ("encapreppart cusec %08x ctime %s\n", encapreppartcusec,
	      encapreppartctime);
    }

  different = authenticatorcusec != encapreppartcusec ||
    strcmp (authenticatorctime, encapreppartctime) != 0;

  free (authenticatorctime);
  free (encapreppartctime);

  if (different)
    return SHISHI_APREP_VERIFY_FAILED;

  return SHISHI_OK;
}
