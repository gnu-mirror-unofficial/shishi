/* aprep.c	AP-REP functions
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
 * Return value: Returns the authenticator or ASN1_TYPE_EMPTY on
 * failure.
 **/
ASN1_TYPE
shishi_aprep (Shishi * handle)
{
  int res = ASN1_SUCCESS;
  ASN1_TYPE node = ASN1_TYPE_EMPTY;

  res =
    asn1_create_element (handle->asn1, "Kerberos5.AP-REP", &node, "AP-REP");
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (node, "AP-REP.pvno",
			  SHISHI_APREP_DEFAULT_PVNO,
			  SHISHI_APREP_DEFAULT_PVNO_LEN);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (node, "AP-REP.msg-type",
			  SHISHI_APREP_DEFAULT_MSG_TYPE,
			  SHISHI_APREP_DEFAULT_MSG_TYPE_LEN);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (node, "AP-REP.enc-part.etype",
			  SHISHI_APREP_DEFAULT_ENC_PART_ETYPE,
			  SHISHI_APREP_DEFAULT_ENC_PART_ETYPE_LEN);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (node, "AP-REP.enc-part.kvno",
			  SHISHI_APREP_DEFAULT_ENC_PART_KVNO,
			  SHISHI_APREP_DEFAULT_ENC_PART_KVNO_LEN);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (node, "AP-REP.enc-part.cipher",
			  SHISHI_APREP_DEFAULT_ENC_PART_CIPHER,
			  SHISHI_APREP_DEFAULT_ENC_PART_CIPHER_LEN);
  if (res != ASN1_SUCCESS)
    goto error;

  /* see shishi_last_aprep() */
  handle->lastaprep = node;

  return node;

error:
  shishi_error_set (handle, libtasn1_strerror (res));
  if (node != ASN1_TYPE_EMPTY)
    asn1_delete_structure (&node);
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
shishi_aprep_print (Shishi * handle, FILE * fh, ASN1_TYPE aprep)
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
shishi_aprep_save (Shishi * handle, FILE * fh, ASN1_TYPE aprep)
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
shishi_aprep_to_file (Shishi * handle, ASN1_TYPE aprep,
		      int filetype, char *filename)
{
  FILE *fh;
  int res;

  if (!SILENT(handle))
    printf (_("Writing AP-REP to %s...\n"), filename);

  fh = fopen (filename, "w");
  if (fh == NULL)
    return SHISHI_FOPEN_ERROR;

  if (!SILENT(handle))
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
    return SHISHI_FCLOSE_ERROR;

  if (!SILENT(handle))
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
shishi_aprep_parse (Shishi * handle, FILE * fh, ASN1_TYPE * aprep)
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
shishi_aprep_read (Shishi * handle, FILE * fh, ASN1_TYPE * aprep)
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
shishi_aprep_from_file (Shishi * handle, ASN1_TYPE * aprep,
			int filetype, char *filename)
{
  int res;
  FILE *fh;

  if (!SILENT(handle))
    printf (_("Reading AP-REP from %s...\n"), filename);

  fh = fopen (filename, "r");
  if (fh == NULL)
    return SHISHI_FOPEN_ERROR;

  if (!SILENT(handle))
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
    return SHISHI_FCLOSE_ERROR;

  if (!SILENT(handle))
    printf (_("Reading AP-REP from %s...done\n"), filename);

  return SHISHI_OK;
}

int
shishi_aprep_enc_part_set (Shishi * handle,
			   ASN1_TYPE aprep,
			   int etype, char *buf, int buflen)
{
  char format[BUFSIZ];
  int res = ASN1_SUCCESS;

  res = asn1_write_value (aprep, "AP-REP.enc-part.cipher", buf, buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  sprintf (format, "%d", etype);
  res = asn1_write_value (aprep, "AP-REP.enc-part.etype", format, 0);
  if (res != ASN1_SUCCESS)
    goto error;

  return SHISHI_OK;

error:
  shishi_error_set (handle, libtasn1_strerror (res));
  return SHISHI_ASN1_ERROR;
}

int
shishi_aprep_enc_part_add (Shishi * handle,
			   ASN1_TYPE aprep,
			   ASN1_TYPE encticketpart,
			   ASN1_TYPE encapreppart)
{
  int res = ASN1_SUCCESS;
  char errorDescription[MAX_ERROR_DESCRIPTION_SIZE];
  unsigned char buf[BUFSIZ];
  int buflen;
  unsigned char der[BUFSIZ];
  int derlen;
  unsigned char key[BUFSIZ];
  int keylen;
  int keytype;

  keylen = sizeof (key);
  res = shishi_encticketpart_get_key (handle, encticketpart,
				      &keytype, key, &keylen);
  if (res != SHISHI_OK)
    return res;

  res = asn1_der_coding (encapreppart, "EncAPRepPart", der, &derlen,
			 errorDescription);
  if (res != ASN1_SUCCESS)
    {
      shishi_error_printf (handle, "Could not DER encode authenticator: %s\n",
			   errorDescription);
      return !SHISHI_OK;
    }

  while ((derlen % 8) != 0)
    {
      der[derlen] = '\0';
      derlen++;
    }

  buflen = BUFSIZ;
  res = shishi_encrypt (handle, keytype, buf, &buflen,
			der, derlen, key, keylen);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "des_encrypt fail\n");
      return res;
    }

  res = shishi_aprep_enc_part_set (handle, aprep, keytype, buf, buflen);

  return res;
}

int
shishi_aprep_enc_part_make (Shishi * handle,
			    ASN1_TYPE aprep,
			    ASN1_TYPE authenticator,
			    ASN1_TYPE encticketpart)
{
  ASN1_TYPE encapreppart = ASN1_TYPE_EMPTY;
  int res;

  encapreppart = shishi_encapreppart (handle);
  if (encapreppart == NULL)
    {
      shishi_error_printf (handle, "Could not create EncAPRepPart: %s\n",
			   shishi_strerror_details (handle));
      return SHISHI_ASN1_ERROR;
    }

  res = shishi_encapreppart_time_copy (handle, encapreppart, authenticator);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "Could not copy time: %s\n",
			   shishi_strerror_details (handle));
      return res;
    }

  res = shishi_aprep_enc_part_add (handle, aprep, encticketpart, 
				   encapreppart);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "Could not add encapreppart: %s\n",
			   shishi_strerror_details (handle));
      return res;
    }

  return SHISHI_OK;
}
