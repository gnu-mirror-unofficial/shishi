/* apreq.c	AP-REQ functions
 * Copyright (C) 2002  Simon Josefsson
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

#define SHISHI_APREQ_DEFAULT_PVNO "5"
#define SHISHI_APREQ_DEFAULT_PVNO_LEN 0
#define SHISHI_APREQ_DEFAULT_MSG_TYPE      "14"	/* KRB_AP_REQ */
#define SHISHI_APREQ_DEFAULT_MSG_TYPE_LEN  0
#define SHISHI_APREQ_DEFAULT_AP_OPTIONS      "\x00\x00\x00\x00"
#define SHISHI_APREQ_DEFAULT_AP_OPTIONS_LEN  32
#define SHISHI_APREQ_DEFAULT_TICKET_TKT_VNO      "5"
#define SHISHI_APREQ_DEFAULT_TICKET_TKT_VNO_LEN  0
#define SHISHI_APREQ_DEFAULT_TICKET_REALM      ""
#define SHISHI_APREQ_DEFAULT_TICKET_REALM_LEN  0
#define SHISHI_APREQ_DEFAULT_TICKET_SNAME_NAME_TYPE "1"	/* SHISHI_NT_PRINCIPAL */
#define SHISHI_APREQ_DEFAULT_TICKET_SNAME_NAME_TYPE_LEN 0
#define SHISHI_APREQ_DEFAULT_TICKET_ENC_PART_ETYPE "0"
#define SHISHI_APREQ_DEFAULT_TICKET_ENC_PART_ETYPE_LEN 0
#define SHISHI_APREQ_DEFAULT_TICKET_ENC_PART_KVNO "0"
#define SHISHI_APREQ_DEFAULT_TICKET_ENC_PART_KVNO_LEN 0
#define SHISHI_APREQ_DEFAULT_TICKET_ENC_PART_CIPHER ""
#define SHISHI_APREQ_DEFAULT_TICKET_ENC_PART_CIPHER_LEN 0
#define SHISHI_APREQ_DEFAULT_AUTHENTICATOR_ETYPE "0"
#define SHISHI_APREQ_DEFAULT_AUTHENTICATOR_ETYPE_LEN 0
#define SHISHI_APREQ_DEFAULT_AUTHENTICATOR_KVNO "1"
#define SHISHI_APREQ_DEFAULT_AUTHENTICATOR_KVNO_LEN 0
#define SHISHI_APREQ_DEFAULT_AUTHENTICATOR_CIPHER ""
#define SHISHI_APREQ_DEFAULT_AUTHENTICATOR_CIPHER_LEN 0

/**
 * shishi_apreq:
 * @handle: shishi handle as allocated by shishi_init().
 *
 * This function creates a new AP-REQ, populated with some default
 * values.
 *
 * Return value: Returns the authenticator or ASN1_TYPE_EMPTY on
 * failure.
 **/
ASN1_TYPE
shishi_apreq (Shishi * handle)
{
  int res = ASN1_SUCCESS;
  ASN1_TYPE node = ASN1_TYPE_EMPTY;

  res =
    asn1_create_element (handle->asn1, "Kerberos5.AP-REQ", &node, "AP-REQ");
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (node, "AP-REQ.pvno",
			  SHISHI_APREQ_DEFAULT_PVNO,
			  SHISHI_APREQ_DEFAULT_PVNO_LEN);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (node, "AP-REQ.msg-type",
			  SHISHI_APREQ_DEFAULT_MSG_TYPE,
			  SHISHI_APREQ_DEFAULT_MSG_TYPE_LEN);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (node, "AP-REQ.ap-options",
			  SHISHI_APREQ_DEFAULT_AP_OPTIONS,
			  SHISHI_APREQ_DEFAULT_AP_OPTIONS_LEN);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (node, "AP-REQ.ticket.tkt-vno",
			  SHISHI_APREQ_DEFAULT_TICKET_TKT_VNO,
			  SHISHI_APREQ_DEFAULT_TICKET_TKT_VNO_LEN);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (node, "AP-REQ.ticket.realm",
			  SHISHI_APREQ_DEFAULT_TICKET_REALM,
			  SHISHI_APREQ_DEFAULT_TICKET_REALM_LEN);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (node, "AP-REQ.ticket.realm",
			  SHISHI_APREQ_DEFAULT_TICKET_REALM,
			  SHISHI_APREQ_DEFAULT_TICKET_REALM_LEN);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (node, "AP-REQ.ticket.sname.name-type",
			  SHISHI_APREQ_DEFAULT_TICKET_SNAME_NAME_TYPE,
			  SHISHI_APREQ_DEFAULT_TICKET_SNAME_NAME_TYPE_LEN);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (node, "AP-REQ.ticket.enc-part.etype",
			  SHISHI_APREQ_DEFAULT_TICKET_ENC_PART_ETYPE,
			  SHISHI_APREQ_DEFAULT_TICKET_ENC_PART_ETYPE_LEN);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (node, "AP-REQ.ticket.enc-part.kvno",
			  SHISHI_APREQ_DEFAULT_TICKET_ENC_PART_KVNO,
			  SHISHI_APREQ_DEFAULT_TICKET_ENC_PART_KVNO_LEN);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (node, "AP-REQ.ticket.enc-part.cipher",
			  SHISHI_APREQ_DEFAULT_TICKET_ENC_PART_CIPHER,
			  SHISHI_APREQ_DEFAULT_TICKET_ENC_PART_CIPHER_LEN);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (node, "AP-REQ.authenticator.etype",
			  SHISHI_APREQ_DEFAULT_AUTHENTICATOR_ETYPE,
			  SHISHI_APREQ_DEFAULT_AUTHENTICATOR_ETYPE_LEN);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (node, "AP-REQ.authenticator.kvno",
			  SHISHI_APREQ_DEFAULT_AUTHENTICATOR_KVNO,
			  SHISHI_APREQ_DEFAULT_AUTHENTICATOR_KVNO_LEN);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (node, "AP-REQ.authenticator.cipher",
			  SHISHI_APREQ_DEFAULT_AUTHENTICATOR_CIPHER,
			  SHISHI_APREQ_DEFAULT_AUTHENTICATOR_CIPHER_LEN);
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
 * shishi_apreq_print:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle open for writing.
 * @apreq: AP-REQ to print.
 *
 * Print ASCII armored DER encoding of AP-REQ to file.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_apreq_print (Shishi * handle, FILE * fh, ASN1_TYPE apreq)
{
  return _shishi_print_armored_data (handle, fh, apreq, "AP-REQ", NULL);
}

/**
 * shishi_apreq_save:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle open for writing.
 * @apreq: AP-REQ to save.
 *
 * Save DER encoding of AP-REQ to file.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_apreq_save (Shishi * handle, FILE * fh, ASN1_TYPE apreq)
{
  return _shishi_save_data (handle, fh, apreq, "AP-REQ");
}

/**
 * shishi_apreq_to_file:
 * @handle: shishi handle as allocated by shishi_init().
 * @apreq: AP-REQ to save.
 * @filetype: input variable specifying type of file to be written,
 *            see Shishi_filetype.
 * @filename: input variable with filename to write to.
 *
 * Write AP-REQ to file in specified TYPE.  The file will be
 * truncated if it exists.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_apreq_to_file (Shishi * handle, ASN1_TYPE apreq,
		      int filetype, char *filename)
{
  FILE *fh;
  int res;

  if (VERBOSE (handle))
    printf (_("Writing AP-REQ to %s...\n"), filename);

  fh = fopen (filename, "w");
  if (fh == NULL)
    return SHISHI_FOPEN_ERROR;

  if (VERBOSE (handle))
    printf (_("Writing AP-REQ in %s format...\n"),
	    filetype == SHISHI_FILETYPE_TEXT ? "TEXT" : "DER");

  if (filetype == SHISHI_FILETYPE_TEXT)
    res = shishi_apreq_print (handle, fh, apreq);
  else
    res = shishi_apreq_save (handle, fh, apreq);
  if (res != SHISHI_OK)
    return res;

  res = fclose (fh);
  if (res != 0)
    return SHISHI_FCLOSE_ERROR;

  if (VERBOSE (handle))
    printf (_("Writing AP-REQ to %s...done\n"), filename);

  return SHISHI_OK;
}

/**
 * shishi_apreq_parse:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle open for reading.
 * @apreq: output variable with newly allocated AP-REQ.
 *
 * Read ASCII armored DER encoded AP-REQ from file and populate given
 * variable.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_apreq_parse (Shishi * handle, FILE * fh, ASN1_TYPE * apreq)
{
  return _shishi_apreq_input (handle, fh, apreq, 0);
}

/**
 * shishi_apreq_read:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle open for reading.
 * @apreq: output variable with newly allocated AP-REQ.
 *
 * Read DER encoded AP-REQ from file and populate given variable.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_apreq_read (Shishi * handle, FILE * fh, ASN1_TYPE * apreq)
{
  return _shishi_apreq_input (handle, fh, apreq, 1);
}

/**
 * shishi_apreq_from_file:
 * @handle: shishi handle as allocated by shishi_init().
 * @apreq: output variable with newly allocated AP-REQ.
 * @filetype: input variable specifying type of file to be read,
 *            see Shishi_filetype.
 * @filename: input variable with filename to read from.
 *
 * Read AP-REQ from file in specified TYPE.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_apreq_from_file (Shishi * handle, ASN1_TYPE * apreq,
			int filetype, char *filename)
{
  int res;
  FILE *fh;

  if (VERBOSE (handle))
    printf (_("Reading AP-REQ from %s...\n"), filename);

  fh = fopen (filename, "r");
  if (fh == NULL)
    return SHISHI_FOPEN_ERROR;

  if (VERBOSE (handle))
    printf (_("Reading AP-REQ in %s format...\n"),
	    filetype == SHISHI_FILETYPE_TEXT ? "TEXT" : "DER");

  if (filetype == SHISHI_FILETYPE_TEXT)
    res = shishi_apreq_parse (handle, fh, apreq);
  else
    res = shishi_apreq_read (handle, fh, apreq);
  if (res != SHISHI_OK)
    return res;

  res = fclose (fh);
  if (res != 0)
    return SHISHI_FCLOSE_ERROR;

  if (VERBOSE (handle))
    printf (_("Reading AP-REQ from %s...done\n"), filename);

  return SHISHI_OK;
}

/**
 * shishi_apreq_set_authenticator:
 * @handle: shishi handle as allocated by shishi_init().
 * @apreq: AP-REQ to add authenticator field to.
 * @etype: encryption type used to encrypt authenticator.
 * @buf: input array with encrypted authenticator.
 * @buflen: size of input array with encrypted authenticator.
 *
 * Set the encrypted authenticator field in the AP-REP.  The encrypted
 * data is usually created by calling shishi_encrypt() on the DER
 * encoded authenticator.  To save time, you may want to use
 * shishi_apreq_add_authenticator() instead, which calculates the
 * encrypted data and calls this function in one step.
 *
 * Return value:
 **/
int
shishi_apreq_set_authenticator (Shishi * handle,
				ASN1_TYPE apreq,
				int etype, char *buf, int buflen)
{
  char format[BUFSIZ];
  int res = ASN1_SUCCESS;

  res = asn1_write_value (apreq, "AP-REQ.authenticator.cipher", buf, buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  sprintf (format, "%d", etype);
  res = asn1_write_value (apreq, "AP-REQ.authenticator.etype", format, 0);
  if (res != ASN1_SUCCESS)
    goto error;

  return SHISHI_OK;

error:
  shishi_error_set (handle, libtasn1_strerror (res));
  return SHISHI_ASN1_ERROR;
}

/**
 * shishi_apreq_add_authenticator:
 * @handle: shishi handle as allocated by shishi_init().
 * @apreq: AP-REQ to add authenticator field to.
 * @enckdcreppart: ticket information where the key is taken from.
 * @authenticator: authenticator as allocated by shishi_authenticator().
 *
 * Encrypts DER encoded authenticator using key from ticket and store
 * it in the AP-REQ.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_apreq_add_authenticator (Shishi * handle,
				ASN1_TYPE apreq,
				Shishi_key *key,
				int keyusage,
				ASN1_TYPE authenticator)
{
  int res = ASN1_SUCCESS;
  char errorDescription[MAX_ERROR_DESCRIPTION_SIZE];
  unsigned char buf[BUFSIZ];
  int buflen;
  unsigned char der[BUFSIZ];
  int derlen;

  res = asn1_der_coding (authenticator, "Authenticator", der, &derlen,
			 errorDescription);
  if (res != ASN1_SUCCESS)
    {
      shishi_error_printf (handle, "Could not DER encode authenticator: %s\n",
			   errorDescription);
      return !SHISHI_OK;
    }

  buflen = BUFSIZ;
  res = shishi_encrypt (handle, key, keyusage, der, derlen, buf, &buflen);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "des_encrypt fail\n");
      return res;
    }

  res = shishi_apreq_set_authenticator (handle, apreq, shishi_key_type(key),
					buf, buflen);

  return res;
}

/**
 * shishi_apreq_set_ticket:
 * @handle: shishi handle as allocated by shishi_init().
 * @apreq: AP-REQ to add ticket field to.
 * @ticket: input ticket to copy into AP-REQ ticket field.
 *
 * Copy ticket into AP-REQ.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_apreq_set_ticket (Shishi * handle, ASN1_TYPE apreq, ASN1_TYPE ticket)
{
  int res = ASN1_SUCCESS;
  ASN1_TYPE node = ASN1_TYPE_EMPTY;
  unsigned char format[BUFSIZ];
  unsigned char buf[BUFSIZ];
  int buflen;
  int i, n;

  buflen = BUFSIZ;
  res = asn1_read_value (ticket, "Ticket.tkt-vno", buf, &buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (apreq, "AP-REQ.ticket.tkt-vno", buf, buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  buflen = BUFSIZ;
  res = asn1_read_value (ticket, "Ticket.realm", buf, &buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (apreq, "AP-REQ.ticket.realm", buf, buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  buflen = BUFSIZ;
  res = asn1_read_value (ticket, "Ticket.sname.name-type", buf, &buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  res =
    asn1_write_value (apreq, "AP-REQ.ticket.sname.name-type", buf, buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_number_of_elements (ticket, "Ticket.sname.name-string", &n);
  if (res != ASN1_SUCCESS)
    goto error;

  for (i = 1; i <= n; i++)
    {
      res = asn1_write_value (apreq, "AP-REQ.ticket.sname.name-string",
			      "NEW", 1);
      if (res != ASN1_SUCCESS)
	goto error;

      sprintf (format, "Ticket.sname.name-string.?%d", i);

      buflen = BUFSIZ;
      res = asn1_read_value (ticket, format, buf, &buflen);
      if (res != ASN1_SUCCESS)
	goto error;

      sprintf (format, "AP-REQ.ticket.sname.name-string.?%d", i);

      res = asn1_write_value (apreq, format, buf, buflen);
      if (res != ASN1_SUCCESS)
	goto error;
    }

  buflen = BUFSIZ;
  res = asn1_read_value (ticket, "Ticket.enc-part.etype", buf, &buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (apreq, "AP-REQ.ticket.enc-part.etype", buf, buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  buflen = BUFSIZ;
  res = asn1_read_value (ticket, "Ticket.enc-part.kvno", buf, &buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (apreq, "AP-REQ.ticket.enc-part.kvno", buf, buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  buflen = BUFSIZ;
  res = asn1_read_value (ticket, "Ticket.enc-part.cipher", buf, &buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  res =
    asn1_write_value (apreq, "AP-REQ.ticket.enc-part.cipher", buf, buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  return SHISHI_OK;

error:
  shishi_error_set (handle, libtasn1_strerror (res));
  if (node != ASN1_TYPE_EMPTY)
    asn1_delete_structure (&node);
  return !SHISHI_OK;
}

int
shishi_apreq_options (Shishi * handle, ASN1_TYPE apreq, int *flags)
{
  int len = sizeof (*flags);
  int res;
  *flags = 0;
  res = _shishi_asn1_field (handle, apreq, (char *) flags, &len,
			    "AP-REQ.ap-options");
  return res;
}

int
shishi_apreq_use_session_key_p (Shishi * handle, ASN1_TYPE apreq)
{
  int options = 0;

  shishi_apreq_options (handle, apreq, &options);

  return options & SHISHI_APOPTIONS_USE_SESSION_KEY;
}

int
shishi_apreq_mutual_required_p (Shishi * handle, ASN1_TYPE apreq)
{
  int options = 0;

  shishi_apreq_options (handle, apreq, &options);

  return options & SHISHI_APOPTIONS_MUTUAL_REQUIRED;
}

int
shishi_apreq_options_set (Shishi * handle, ASN1_TYPE apreq, int options)
{
  int res;

  res = asn1_write_value (apreq, "AP-REQ.ap-options",
			  (char *) &options,
			  SHISHI_APREQ_DEFAULT_AP_OPTIONS_LEN);
  if (res != ASN1_SUCCESS)
    return SHISHI_ASN1_ERROR;

  return SHISHI_OK;
}

int
shishi_apreq_options_add (Shishi * handle, ASN1_TYPE apreq, int option)
{
  int options;
  int res;

  res = shishi_apreq_options (handle, apreq, &options);
  if (res != SHISHI_OK)
    return res;

  options |= option;

  res = shishi_apreq_options_set (handle, apreq, options);
  if (res != SHISHI_OK)
    return res;

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
shishi_apreq_get_authenticator_etype (Shishi * handle,
				      ASN1_TYPE apreq, int *etype)
{
  return _shishi_asn1_integer_field (handle, apreq, etype,
				     "AP-REQ.authenticator.etype");
}

/**
 * shishi_apreq_get_ticket:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcrep: AP-REQ variable to get ticket from.
 * @ticket: output variable to hold extracted ticket.
 *
 * Extract ticket from AP-REQ.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_apreq_get_ticket (Shishi * handle, ASN1_TYPE apreq, ASN1_TYPE * ticket)
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
  res = asn1_read_value (apreq, "AP-REQ.ticket.tkt-vno", buf, &buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (*ticket, "Ticket.tkt-vno", buf, buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  buflen = BUFSIZ;
  res = asn1_read_value (apreq, "AP-REQ.ticket.realm", buf, &buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (*ticket, "Ticket.realm", buf, buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  buflen = BUFSIZ;
  res =
    asn1_read_value (apreq, "AP-REQ.ticket.sname.name-type", buf, &buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (*ticket, "Ticket.sname.name-type", buf, buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  res =
    asn1_number_of_elements (apreq, "AP-REQ.ticket.sname.name-string", &n);
  if (res != ASN1_SUCCESS)
    goto error;

  for (i = 1; i <= n; i++)
    {
      res = asn1_write_value (*ticket, "Ticket.sname.name-string", "NEW", 1);
      if (res != ASN1_SUCCESS)
	goto error;

      sprintf (format, "AP-REQ.ticket.sname.name-string.?%d", i);
      buflen = BUFSIZ;
      res = asn1_read_value (apreq, format, buf, &buflen);
      if (res != ASN1_SUCCESS)
	goto error;

      sprintf (format, "Ticket.sname.name-string.?%d", i);
      res = asn1_write_value (*ticket, format, buf, buflen);
      if (res != ASN1_SUCCESS)
	goto error;
    }

  buflen = BUFSIZ;
  res = asn1_read_value (apreq, "AP-REQ.ticket.enc-part.etype", buf, &buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (*ticket, "Ticket.enc-part.etype", buf, buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  buflen = BUFSIZ;
  res = asn1_read_value (apreq, "AP-REQ.ticket.enc-part.kvno", buf, &buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (*ticket, "Ticket.enc-part.kvno", buf, buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  buflen = BUFSIZ;
  res =
    asn1_read_value (apreq, "AP-REQ.ticket.enc-part.cipher", buf, &buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (*ticket, "Ticket.enc-part.cipher", buf, buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  return SHISHI_OK;

error:
  shishi_error_printf (handle, "shishi_apreq_get_ticket() failure: %s",
		       libtasn1_strerror (res));
  if (*ticket != ASN1_TYPE_EMPTY)
    asn1_delete_structure (ticket);
  return SHISHI_ASN1_ERROR;
}

int
shishi_apreq_decrypt (Shishi * handle,
		      ASN1_TYPE apreq,
		      Shishi_key *key,
		      int keyusage,
		      ASN1_TYPE * authenticator)
{
  int res;
  int i, len;
  int buflen = BUFSIZ;
  unsigned char buf[BUFSIZ];
  unsigned char cipher[BUFSIZ];
  int realmlen = BUFSIZ;
  int cipherlen;
  int etype;

  res = shishi_apreq_get_authenticator_etype (handle, apreq, &etype);
  if (res != SHISHI_OK)
    return res;

  if (etype != shishi_key_type(key))
    return SHISHI_APREQ_BAD_KEYTYPE;

  cipherlen = BUFSIZ;
  res = _shishi_asn1_field (handle, apreq, cipher, &cipherlen,
			    "AP-REQ.authenticator.cipher");
  if (res != SHISHI_OK)
    return res;

  res = shishi_decrypt (handle, key, keyusage,
			cipher, cipherlen, buf, &buflen);

  if (res != SHISHI_OK)
    {
      if (VERBOSE (handle))
	printf ("decrypt failed: %s\n", shishi_strerror_details (handle));
      shishi_error_printf (handle,
			   "decrypt fail, most likely wrong password\n");
      return res;
    }

  /* The crypto is so 1980; no length indicator. Trim off pad bytes
     until we can parse it. */
  for (i = 0; i < 8; i++)
    {
      if (VERBOSEASN1 (handle))
	printf ("Trying with %d pad in enckdcrep...\n", i);

      *authenticator = shishi_d2a_authenticator (handle, &buf[0], buflen - i);
      if (*authenticator != ASN1_TYPE_EMPTY)
	break;
    }

  if (*authenticator == ASN1_TYPE_EMPTY)
    {
      shishi_error_printf (handle, "Could not DER decode Authenticator. "
			   "Password probably correct (decrypt ok) though\n");
      return SHISHI_ASN1_ERROR;
    }

  return SHISHI_OK;
}
