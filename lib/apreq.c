/* apreq.c --- AP-REQ functions.
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

/* Get _shishi_print_armored_data, etc. */
#include "diskio.h"

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
 * Return value: Returns the AP-REQ or NULL on failure.
 **/
Shishi_asn1
shishi_apreq (Shishi * handle)
{
  Shishi_asn1 node;
  int res;

  node = shishi_asn1_apreq (handle);
  if (!node)
    goto error;

  res = shishi_asn1_write (handle, node, "pvno",
			   SHISHI_APREQ_DEFAULT_PVNO,
			   SHISHI_APREQ_DEFAULT_PVNO_LEN);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_write (handle, node, "msg-type",
			   SHISHI_APREQ_DEFAULT_MSG_TYPE,
			   SHISHI_APREQ_DEFAULT_MSG_TYPE_LEN);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_write (handle, node, "ap-options",
			   SHISHI_APREQ_DEFAULT_AP_OPTIONS,
			   SHISHI_APREQ_DEFAULT_AP_OPTIONS_LEN);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_write (handle, node, "ticket.tkt-vno",
			   SHISHI_APREQ_DEFAULT_TICKET_TKT_VNO,
			   SHISHI_APREQ_DEFAULT_TICKET_TKT_VNO_LEN);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_write (handle, node, "ticket.realm",
			   SHISHI_APREQ_DEFAULT_TICKET_REALM,
			   SHISHI_APREQ_DEFAULT_TICKET_REALM_LEN);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_write (handle, node, "ticket.realm",
			   SHISHI_APREQ_DEFAULT_TICKET_REALM,
			   SHISHI_APREQ_DEFAULT_TICKET_REALM_LEN);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_write (handle, node, "ticket.sname.name-type",
			   SHISHI_APREQ_DEFAULT_TICKET_SNAME_NAME_TYPE,
			   SHISHI_APREQ_DEFAULT_TICKET_SNAME_NAME_TYPE_LEN);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_write (handle, node, "ticket.enc-part.etype",
			   SHISHI_APREQ_DEFAULT_TICKET_ENC_PART_ETYPE,
			   SHISHI_APREQ_DEFAULT_TICKET_ENC_PART_ETYPE_LEN);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_write (handle, node, "ticket.enc-part.kvno",
			   SHISHI_APREQ_DEFAULT_TICKET_ENC_PART_KVNO,
			   SHISHI_APREQ_DEFAULT_TICKET_ENC_PART_KVNO_LEN);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_write (handle, node, "ticket.enc-part.cipher",
			   SHISHI_APREQ_DEFAULT_TICKET_ENC_PART_CIPHER,
			   SHISHI_APREQ_DEFAULT_TICKET_ENC_PART_CIPHER_LEN);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_write (handle, node, "authenticator.etype",
			   SHISHI_APREQ_DEFAULT_AUTHENTICATOR_ETYPE,
			   SHISHI_APREQ_DEFAULT_AUTHENTICATOR_ETYPE_LEN);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_write (handle, node, "authenticator.kvno",
			   SHISHI_APREQ_DEFAULT_AUTHENTICATOR_KVNO,
			   SHISHI_APREQ_DEFAULT_AUTHENTICATOR_KVNO_LEN);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_write (handle, node, "authenticator.cipher",
			   SHISHI_APREQ_DEFAULT_AUTHENTICATOR_CIPHER,
			   SHISHI_APREQ_DEFAULT_AUTHENTICATOR_CIPHER_LEN);
  if (res != SHISHI_OK)
    goto error;

  return node;

error:
  if (node)
    shishi_asn1_done (handle, node);
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
shishi_apreq_print (Shishi * handle, FILE * fh, Shishi_asn1 apreq)
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
shishi_apreq_save (Shishi * handle, FILE * fh, Shishi_asn1 apreq)
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
shishi_apreq_to_file (Shishi * handle, Shishi_asn1 apreq,
		      int filetype, const char *filename)
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
    return SHISHI_IO_ERROR;

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
shishi_apreq_parse (Shishi * handle, FILE * fh, Shishi_asn1 * apreq)
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
shishi_apreq_read (Shishi * handle, FILE * fh, Shishi_asn1 * apreq)
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
shishi_apreq_from_file (Shishi * handle, Shishi_asn1 * apreq,
			int filetype, const char *filename)
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
    return SHISHI_IO_ERROR;

  if (VERBOSE (handle))
    printf (_("Reading AP-REQ from %s...done\n"), filename);

  return SHISHI_OK;
}

/**
 * shishi_apreq_set_authenticator:
 * @handle: shishi handle as allocated by shishi_init().
 * @apreq: AP-REQ to add authenticator field to.
 * @etype: encryption type used to encrypt authenticator.
 * @kvno: version of the key used to encrypt authenticator.
 * @buf: input array with encrypted authenticator.
 * @buflen: size of input array with encrypted authenticator.
 *
 * Set the encrypted authenticator field in the AP-REP.  The encrypted
 * data is usually created by calling shishi_encrypt() on the DER
 * encoded authenticator.  To save time, you may want to use
 * shishi_apreq_add_authenticator() instead, which calculates the
 * encrypted data and calls this function in one step.
 *
 * Return value: Returns SHISHI_OK on success.
 **/
int
shishi_apreq_set_authenticator (Shishi * handle,
				Shishi_asn1 apreq,
				int32_t etype, uint32_t kvno,
				const char *buf, size_t buflen)
{
  int res;

  res = shishi_asn1_write (handle, apreq, "authenticator.cipher",
			   buf, buflen);
  if (res != SHISHI_OK)
    return res;

  if (kvno == UINT32_MAX)
    res = shishi_asn1_write (handle, apreq, "authenticator.kvno", NULL, 0);
  else
    res = shishi_asn1_write_int32 (handle, apreq, "authenticator.kvno", kvno);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_write_int32 (handle, apreq, "authenticator.etype", etype);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_apreq_add_authenticator:
 * @handle: shishi handle as allocated by shishi_init().
 * @apreq: AP-REQ to add authenticator field to.
 * @key: key to to use for encryption.
 * @keyusage: cryptographic key usage value to use in encryption.
 * @authenticator: authenticator as allocated by shishi_authenticator().
 *
 * Encrypts DER encoded authenticator using key and store it in the
 * AP-REQ.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_apreq_add_authenticator (Shishi * handle,
				Shishi_asn1 apreq,
				Shishi_key * key,
				int keyusage, Shishi_asn1 authenticator)
{
  int res;
  char *buf;
  size_t buflen;
  char *der;
  size_t derlen;

  res = shishi_asn1_to_der (handle, authenticator, &der, &derlen);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "Could not DER encode authenticator: %s\n",
			   shishi_strerror (res));
      return res;
    }

  res = shishi_encrypt (handle, key, keyusage, der, derlen, &buf, &buflen);

  free (der);

  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "Cannot encrypt authenticator.\n");
      return res;
    }

  res = shishi_apreq_set_authenticator (handle, apreq, shishi_key_type (key),
					shishi_key_version (key),
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
shishi_apreq_set_ticket (Shishi * handle, Shishi_asn1 apreq,
			 Shishi_asn1 ticket)
{
  int res;
  char *format;
  char *buf;
  size_t buflen, i, n;

  res = shishi_asn1_read (handle, ticket, "tkt-vno", &buf, &buflen);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_write (handle, apreq, "ticket.tkt-vno", buf, buflen);
  free (buf);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_read (handle, ticket, "realm", &buf, &buflen);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_write (handle, apreq, "ticket.realm", buf, buflen);
  free (buf);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_read (handle, ticket, "sname.name-type", &buf, &buflen);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_write (handle, apreq, "ticket.sname.name-type",
			   buf, buflen);
  free (buf);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_number_of_elements (handle, ticket,
					"sname.name-string", &n);
  if (res != SHISHI_OK)
    return res;

  for (i = 1; i <= n; i++)
    {
      res = shishi_asn1_write (handle, apreq,
			       "ticket.sname.name-string", "NEW", 1);
      if (res != SHISHI_OK)
	return res;

      asprintf (&format, "sname.name-string.?%d", i);
      res = shishi_asn1_read (handle, ticket, format, &buf, &buflen);
      free (format);
      if (res != SHISHI_OK)
	return res;

      asprintf (&format, "ticket.sname.name-string.?%d", i);
      res = shishi_asn1_write (handle, apreq, format, buf, buflen);
      free (format);
      free (buf);
      if (res != SHISHI_OK)
	return res;
    }

  res = shishi_asn1_read (handle, ticket, "enc-part.etype", &buf, &buflen);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_write (handle, apreq, "ticket.enc-part.etype",
			   buf, buflen);
  free (buf);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_read (handle, ticket, "enc-part.kvno", &buf, &buflen);
  if (res != SHISHI_OK && res != SHISHI_ASN1_NO_ELEMENT)
    return res;

  if (res == SHISHI_ASN1_NO_ELEMENT)
    res = shishi_asn1_write (handle, apreq, "ticket.enc-part.kvno", NULL, 0);
  else
    {
      res = shishi_asn1_write (handle, apreq, "ticket.enc-part.kvno",
			       buf, buflen);
      free (buf);
    }
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_read (handle, ticket, "enc-part.cipher", &buf, &buflen);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_write (handle, apreq, "ticket.enc-part.cipher",
			   buf, buflen);
  free (buf);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_apreq_options:
 * @handle: shishi handle as allocated by shishi_init().
 * @apreq: AP-REQ to get options from.
 * @flags: Output integer containing options from AP-REQ.
 *
 * Extract the AP-Options from AP-REQ into output integer.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_apreq_options (Shishi * handle, Shishi_asn1 apreq, uint32_t * flags)
{
  return shishi_asn1_read_bitstring (handle, apreq, "ap-options", flags);
}

/**
 * shishi_apreq_use_session_key_p:
 * @handle: shishi handle as allocated by shishi_init().
 * @apreq: AP-REQ as allocated by shishi_apreq().
 *
 * Return non-0 iff the "Use session key" option is set in the AP-REQ.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_apreq_use_session_key_p (Shishi * handle, Shishi_asn1 apreq)
{
  uint32_t options = 0;

  shishi_apreq_options (handle, apreq, &options);

  return options & SHISHI_APOPTIONS_USE_SESSION_KEY;
}

/**
 * shishi_apreq_mutual_required_p:
 * @handle: shishi handle as allocated by shishi_init().
 * @apreq: AP-REQ as allocated by shishi_apreq().
 *
 * Return non-0 iff the "Mutual required" option is set in the AP-REQ.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_apreq_mutual_required_p (Shishi * handle, Shishi_asn1 apreq)
{
  uint32_t options = 0;

  shishi_apreq_options (handle, apreq, &options);

  return options & SHISHI_APOPTIONS_MUTUAL_REQUIRED;
}

/**
 * shishi_apreq_options_set:
 * @handle: shishi handle as allocated by shishi_init().
 * @apreq: AP-REQ as allocated by shishi_apreq().
 * @options: Options to set in AP-REQ.
 *
 * Set the AP-Options in AP-REQ to indicate integer.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_apreq_options_set (Shishi * handle, Shishi_asn1 apreq,
			  uint32_t options)
{
  int res;

  res = shishi_asn1_write_bitstring (handle, apreq, "ap-options", options);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_apreq_options_add:
 * @handle: shishi handle as allocated by shishi_init().
 * @apreq: AP-REQ as allocated by shishi_apreq().
 * @option: Options to add in AP-REQ.
 *
 * Add the AP-Options in AP-REQ.  Options not set in input parameter
 * @option are preserved in the AP-REQ.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_apreq_options_add (Shishi * handle, Shishi_asn1 apreq, uint32_t option)
{
  uint32_t options;
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
 * shishi_apreq_options_remove:
 * @handle: shishi handle as allocated by shishi_init().
 * @apreq: AP-REQ as allocated by shishi_apreq().
 * @option: Options to remove from AP-REQ.
 *
 * Remove the AP-Options from AP-REQ.  Options not set in input
 * parameter @option are preserved in the AP-REQ.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_apreq_options_remove (Shishi * handle,
			     Shishi_asn1 apreq, uint32_t option)
{
  uint32_t options;
  int res;

  res = shishi_apreq_options (handle, apreq, &options);
  if (res != SHISHI_OK)
    return res;

  options &= ~(options & option);

  res = shishi_apreq_options_set (handle, apreq, options);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_apreq_get_authenticator_etype:
 * @handle: shishi handle as allocated by shishi_init().
 * @apreq: AP-REQ variable to get value from.
 * @etype: output variable that holds the value.
 *
 * Extract AP-REQ.authenticator.etype.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_apreq_get_authenticator_etype (Shishi * handle,
				      Shishi_asn1 apreq, int32_t * etype)
{
  return shishi_asn1_read_int32 (handle, apreq, "authenticator.etype", etype);
}

/**
 * shishi_apreq_get_ticket:
 * @handle: shishi handle as allocated by shishi_init().
 * @apreq: AP-REQ variable to get ticket from.
 * @ticket: output variable to hold extracted ticket.
 *
 * Extract ticket from AP-REQ.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_apreq_get_ticket (Shishi * handle,
			 Shishi_asn1 apreq, Shishi_asn1 * ticket)
{
  char *buf;
  char *format;
  size_t buflen, i, n;
  int res;

  /* there's GOT to be an easier way to do this */

  *ticket = shishi_ticket (handle);
  if (!*ticket)
    return SHISHI_ASN1_ERROR;

  res = shishi_asn1_read (handle, apreq, "ticket.tkt-vno", &buf, &buflen);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_write (handle, *ticket, "tkt-vno", buf, buflen);
  free (buf);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_read (handle, apreq, "ticket.realm", &buf, &buflen);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_write (handle, *ticket, "realm", buf, buflen);
  free (buf);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_read (handle, apreq, "ticket.sname.name-type",
			  &buf, &buflen);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_write (handle, *ticket, "sname.name-type", buf, buflen);
  free (buf);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_number_of_elements (handle, apreq,
					"ticket.sname.name-string", &n);
  if (res != SHISHI_OK)
    goto error;

  for (i = 1; i <= n; i++)
    {
      res = shishi_asn1_write (handle, *ticket, "sname.name-string",
			       "NEW", 1);
      if (res != SHISHI_OK)
	goto error;

      asprintf (&format, "ticket.sname.name-string.?%d", i);
      res = shishi_asn1_read (handle, apreq, format, &buf, &buflen);
      free (format);
      if (res != SHISHI_OK)
	goto error;

      asprintf (&format, "sname.name-string.?%d", i);
      res = shishi_asn1_write (handle, *ticket, format, buf, buflen);
      free (format);
      free (buf);
      if (res != SHISHI_OK)
	goto error;
    }

  res = shishi_asn1_read (handle, apreq, "ticket.enc-part.etype",
			  &buf, &buflen);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_write (handle, *ticket, "enc-part.etype", buf, buflen);
  free (buf);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_read (handle, apreq, "ticket.enc-part.kvno",
			  &buf, &buflen);
  if (res != SHISHI_OK && res != SHISHI_ASN1_NO_ELEMENT)
    goto error;

  if (res == SHISHI_ASN1_NO_ELEMENT)
    res = shishi_asn1_write (handle, *ticket, "enc-part.kvno", NULL, 0);
  else
    {
      res = shishi_asn1_write (handle, *ticket, "enc-part.kvno", buf, buflen);
      free (buf);
    }
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_read (handle, apreq, "ticket.enc-part.cipher",
			  &buf, &buflen);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_write (handle, *ticket, "enc-part.cipher", buf, buflen);
  free (buf);
  if (res != SHISHI_OK)
    goto error;

  return SHISHI_OK;

error:
  shishi_asn1_done (handle, *ticket);
  return res;
}

int
shishi_apreq_decrypt (Shishi * handle,
		      Shishi_asn1 apreq,
		      Shishi_key * key,
		      int keyusage, Shishi_asn1 * authenticator)
{
  int res;
  int i;
  char *buf;
  size_t buflen;
  char *cipher;
  size_t cipherlen;
  int etype;

  res = shishi_apreq_get_authenticator_etype (handle, apreq, &etype);
  if (res != SHISHI_OK)
    return res;

  if (etype != shishi_key_type (key))
    return SHISHI_APREQ_BAD_KEYTYPE;

  res = shishi_asn1_read (handle, apreq, "authenticator.cipher",
			  &cipher, &cipherlen);
  if (res != SHISHI_OK)
    return res;

  res = shishi_decrypt (handle, key, keyusage,
			cipher, cipherlen, &buf, &buflen);
  free (cipher);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle,
			   "decrypt fail, most likely wrong password\n");
      return SHISHI_APREQ_DECRYPT_FAILED;
    }

  /* The crypto is so 1980; no length indicator. Trim off pad bytes
     until we can parse it. */
  for (i = 0; i < 8; i++)
    {
      if (VERBOSEASN1 (handle))
	printf ("Trying with %d pad in enckdcrep...\n", i);

      *authenticator = shishi_der2asn1_authenticator (handle, &buf[0],
						      buflen - i);
      if (*authenticator != NULL)
	break;
    }

  if (*authenticator == NULL)
    {
      shishi_error_printf (handle, "Could not DER decode Authenticator. "
			   "Password probably correct (decrypt ok) though\n");
      return SHISHI_ASN1_ERROR;
    }

  return SHISHI_OK;
}
