/* kdcrep.c	Key distribution (AS/TGS) Reply functions
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

#define SHISHI_KDCREP_DEFAULT_PVNO      "5"
#define SHISHI_KDCREP_DEFAULT_PVNO_LEN  0
#define SHISHI_AS_REP_DEFAULT_MSG_TYPE      "11"
#define SHISHI_AS_REP_DEFAULT_MSG_TYPE_LEN  0
#define SHISHI_TGS_REP_DEFAULT_MSG_TYPE      "13"
#define SHISHI_TGS_REP_DEFAULT_MSG_TYPE_LEN  0

ASN1_TYPE
_shishi_kdcrep (Shishi * handle, int as)
{
  int res = ASN1_SUCCESS;
  ASN1_TYPE node = ASN1_TYPE_EMPTY;

  if (as)
    res = 
      asn1_create_element (handle->asn1, "Kerberos5.AS-REP", &node, "KDC-REP");
  else
    res =
      asn1_create_element (handle->asn1, "Kerberos5.TGS-REP", &node, 
			   "KDC-REP");
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (node, "KDC-REP.pvno",
			  SHISHI_KDCREP_DEFAULT_PVNO,
			  SHISHI_KDCREP_DEFAULT_PVNO_LEN);
  if (res != ASN1_SUCCESS)
    goto error;

  if (as)
    res = asn1_write_value (node, "KDC-REP.msg-type",
			    SHISHI_AS_REP_DEFAULT_MSG_TYPE,
			    SHISHI_AS_REP_DEFAULT_MSG_TYPE_LEN);
  else
    res = asn1_write_value (node, "KDC-REP.msg-type",
			    SHISHI_TGS_REP_DEFAULT_MSG_TYPE,
			    SHISHI_TGS_REP_DEFAULT_MSG_TYPE_LEN);
  if (res != ASN1_SUCCESS)
    goto error;

  return node;

error:
  shishi_error_set (handle, libtasn1_strerror (res));
  if (node != ASN1_TYPE_EMPTY)
    asn1_delete_structure (&node);
  return NULL;
}

/**
 * shishi_as_rep:
 * @handle: shishi handle as allocated by shishi_init().
 * 
 * This function creates a new AS-REP, populated with some default
 * values.
 * 
 * Return value: Returns the AS-REP or ASN1_TYPE_EMPTY on failure.
 **/
ASN1_TYPE
shishi_as_rep (Shishi * handle)
{
  return _shishi_kdcrep (handle, 1);
}

/**
 * shishi_tgs_rep:
 * @handle: shishi handle as allocated by shishi_init().
 * 
 * This function creates a new TGS-REP, populated with some default
 * values.
 * 
 * Return value: Returns the TGS-REP or ASN1_TYPE_EMPTY on failure.
 **/
ASN1_TYPE
shishi_tgs_rep (Shishi * handle)
{
  return _shishi_kdcrep (handle, 0);
}


/**
 * shishi_kdcrep_print:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle open for writing.
 * @kdcrep: KDC-REP to print.
 * 
 * Print ASCII armored DER encoding of KDC-REP to file.
 * 
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcrep_print (Shishi * handle, FILE * fh, ASN1_TYPE kdcrep)
{
  return _shishi_print_armored_data (handle, fh, kdcrep, "KDC-REP", NULL);
}

/**
 * shishi_kdcrep_save:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle open for writing.
 * @kdcrep: KDC-REP to save.
 * 
 * Print  DER encoding of KDC-REP to file.
 * 
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcrep_save (Shishi * handle, FILE * fh, ASN1_TYPE kdcrep)
{
  return _shishi_save_data (handle, fh, kdcrep, "KDC-REP");
}

/**
 * shishi_kdcrep_to_file:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcrep: KDC-REP to save.
 * @filetype: input variable specifying type of file to be written,
 *            see Shishi_filetype.
 * @filename: input variable with filename to write to.
 * 
 * Write KDC-REP to file in specified TYPE.  The file will be truncated
 * if it exists.
 * 
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcrep_to_file (Shishi * handle, ASN1_TYPE kdcrep,
		       int filetype, char *filename)
{
  FILE *fh;
  int res;

  if (!SILENT(handle))
    printf (_("Writing KDC-REP to %s...\n"), filename);

  fh = fopen (filename, "w");
  if (fh == NULL)
    return SHISHI_FOPEN_ERROR;

  if (!SILENT(handle))
    printf (_("Writing KDC-REP in %s format...\n"),
	    filetype == SHISHI_FILETYPE_TEXT ? "TEXT" : "DER");

  if (filetype == SHISHI_FILETYPE_TEXT)
    res = shishi_kdcrep_print (handle, fh, kdcrep);
  else
    res = shishi_kdcrep_save (handle, fh, kdcrep);
  if (res != SHISHI_OK)
    return res;

  res = fclose (fh);
  if (res != 0)
    return SHISHI_FCLOSE_ERROR;

  if (!SILENT(handle))
    printf (_("Writing KDC-REP to %s...done\n"), filename);

  return SHISHI_OK;
}

/**
 * shishi_kdcrep_parse:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle open for reading.
 * @kdcrep: output variable with newly allocated KDC-REP.
 * 
 * Read ASCII armored DER encoded KDC-REP from file and populate given
 * variable.
 * 
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcrep_parse (Shishi * handle, FILE * fh, ASN1_TYPE * kdcrep)
{
  return _shishi_kdcrep_input (handle, fh, kdcrep, 0);
}

/**
 * shishi_kdcrep_read:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle open for reading.
 * @kdcrep: output variable with newly allocated KDC-REP.
 * 
 * Read DER encoded KDC-REP from file and populate given variable.
 * 
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcrep_read (Shishi * handle, FILE * fh, ASN1_TYPE * kdcrep)
{
  return _shishi_kdcrep_input (handle, fh, kdcrep, 1);
}

/**
 * shishi_kdcrep_from_file:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcrep: output variable with newly allocated KDC-REP.
 * @filetype: input variable specifying type of file to be read,
 *            see Shishi_filetype.
 * @filename: input variable with filename to read from.
 * 
 * Read KDC-REP from file in specified TYPE.
 * 
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcrep_from_file (Shishi * handle, ASN1_TYPE * kdcrep,
			 int filetype, char *filename)
{
  int res;
  FILE *fh;

  if (!SILENT(handle))
    printf (_("Reading KDC-REP from %s...\n"), filename);

  fh = fopen (filename, "r");
  if (fh == NULL)
    return SHISHI_FOPEN_ERROR;

  if (!SILENT(handle))
    printf (_("Reading KDC-REP in %s format...\n"),
	    filetype == SHISHI_FILETYPE_TEXT ? "TEXT" : "DER");

  if (filetype == SHISHI_FILETYPE_TEXT)
    res = shishi_kdcrep_parse (handle, fh, kdcrep);
  else
    res = shishi_kdcrep_read (handle, fh, kdcrep);
  if (res != SHISHI_OK)
    return res;

  res = fclose (fh);
  if (res != 0)
    return SHISHI_FCLOSE_ERROR;

  if (!SILENT(handle))
    printf (_("Reading KDC-REP from %s...done\n"), filename);

  return SHISHI_OK;
}

/**
 * shishi_kdcrep_get_enc_part_etype:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcrep: KDC-REP variable to get value from.
 * @etype: output variable that holds the value.
 * 
 * Extract KDC-REP.enc-part.etype.
 * 
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcrep_get_enc_part_etype (Shishi * handle,
				  ASN1_TYPE kdcrep, int *etype)
{
  return _shishi_asn1_integer_field (handle, kdcrep, etype,
				     "KDC-REP.enc-part.etype");
}

/**
 * shishi_kdcrep_get_ticket:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcrep: KDC-REP variable to get ticket from.
 * @ticket: output variable to hold extracted ticket.
 * 
 * Extract ticket from KDC-REP.
 * 
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcrep_get_ticket (Shishi * handle,
			  ASN1_TYPE kdcrep, ASN1_TYPE * ticket)
{
  unsigned char buf[BUFSIZ];
  unsigned char format[BUFSIZ];
  int buflen;
  int res;
  int i, n;

  /* there's GOT to be an easier way to do this */

  *ticket = ASN1_TYPE_EMPTY;
  res = asn1_create_element (handle->asn1, "Kerberos5.Ticket",
			     ticket, "Ticket");
  if (res != ASN1_SUCCESS)
    {
      *ticket = ASN1_TYPE_EMPTY;
      goto error;
    }

  buflen = BUFSIZ;
  res = asn1_read_value (kdcrep, "KDC-REP.ticket.tkt-vno", buf, &buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (*ticket, "Ticket.tkt-vno", buf, buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  buflen = BUFSIZ;
  res = asn1_read_value (kdcrep, "KDC-REP.ticket.realm", buf, &buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (*ticket, "Ticket.realm", buf, buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  buflen = BUFSIZ;
  res =
    asn1_read_value (kdcrep, "KDC-REP.ticket.sname.name-type", buf, &buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (*ticket, "Ticket.sname.name-type", buf, buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  res =
    asn1_number_of_elements (kdcrep, "KDC-REP.ticket.sname.name-string", &n);
  if (res != ASN1_SUCCESS)
    goto error;

  for (i = 1; i <= n; i++)
    {
      res = asn1_write_value (*ticket, "Ticket.sname.name-string", "NEW", 1);
      if (res != ASN1_SUCCESS)
	goto error;

      sprintf (format, "KDC-REP.ticket.sname.name-string.?%d", i);
      buflen = BUFSIZ;
      res = asn1_read_value (kdcrep, format, buf, &buflen);
      if (res != ASN1_SUCCESS)
	goto error;

      sprintf (format, "Ticket.sname.name-string.?%d", i);
      res = asn1_write_value (*ticket, format, buf, buflen);
      if (res != ASN1_SUCCESS)
	goto error;
    }

  buflen = BUFSIZ;
  res =
    asn1_read_value (kdcrep, "KDC-REP.ticket.enc-part.etype", buf, &buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (*ticket, "Ticket.enc-part.etype", buf, buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  buflen = BUFSIZ;
  res =
    asn1_read_value (kdcrep, "KDC-REP.ticket.enc-part.kvno", buf, &buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (*ticket, "Ticket.enc-part.kvno", buf, buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  buflen = BUFSIZ;
  res =
    asn1_read_value (kdcrep, "KDC-REP.ticket.enc-part.cipher", buf, &buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (*ticket, "Ticket.enc-part.cipher", buf, buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  return SHISHI_OK;

error:
  shishi_error_printf (handle, "shishi_kdcrep_get_ticket() failure: %s",
		       libtasn1_strerror (res));
  if (*ticket != ASN1_TYPE_EMPTY)
    asn1_delete_structure (ticket);
  return SHISHI_ASN1_ERROR;
}

int
shishi_kdcrep_decrypt (Shishi * handle,
		       ASN1_TYPE kdcrep,
		       int keyusage,
		       int keytype,
		       char *key, 
		       int keylen, 
		       ASN1_TYPE * enckdcreppart)
{
  int res;
  int i, len;
  int buflen = BUFSIZ;
  unsigned char buf[BUFSIZ];
  unsigned char cipher[BUFSIZ];
  int realmlen = BUFSIZ;
  int cipherlen;
  int etype;

  res = shishi_kdcrep_get_enc_part_etype (handle, kdcrep, &etype);
  if (res != SHISHI_OK)
    return res;

  if (etype != keytype)
    return SHISHI_KDCREP_BAD_KEYTYPE;

  cipherlen = BUFSIZ;
  res = _shishi_asn1_field (handle, kdcrep, cipher, &cipherlen,
			    "KDC-REP.enc-part.cipher");
  if (res != SHISHI_OK)
    return res;

  res = shishi_decrypt (handle, keyusage, etype,
			key, keylen, cipher, cipherlen, buf, &buflen);
  if (res != SHISHI_OK)
    {
      if (!SILENT(handle))
	printf ("des_decrypt failed: %s\n", shishi_strerror_details (handle));
      shishi_error_printf (handle,
			   "des_decrypt fail, most likely wrong password\n");
      return res;
    }

  /* The crypto is so 1980; no length indicator. Trim off pad bytes
     until we can parse it. */
  for (i = 0; i < 8; i++)
    {
      if (DEBUG (handle))
	printf ("Trying with %d pad in enckdcrep...\n", i);

      *enckdcreppart = shishi_d2a_encasreppart (handle, &buf[0], buflen - i);
      if (*enckdcreppart != ASN1_TYPE_EMPTY)
	break;

      *enckdcreppart = shishi_d2a_enctgsreppart (handle, &buf[0], buflen - i);
      if (*enckdcreppart != ASN1_TYPE_EMPTY)
	break;
    }

  if (*enckdcreppart == ASN1_TYPE_EMPTY)
    {
      shishi_error_printf (handle, "Could not DER decode EncKDCRepPart. "
			   "Password probably correct (decrypt ok) though\n");
      return SHISHI_ASN1_ERROR;
    }

  return SHISHI_OK;
}
