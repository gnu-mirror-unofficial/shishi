/* krberror.c	Functions related to KRB-ERROR packet.
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
 * shishi_krberror:
 * @handle: shishi handle as allocated by shishi_init().
 *
 * This function creates a new KRB-ERROR, populated with some default
 * values.
 *
 * Return value: Returns the KRB-ERROR or NULL on failure.
 **/
Shishi_asn1
shishi_krberror (Shishi * handle)
{
  Shishi_asn1 node;

  node = shishi_asn1_krberror (handle);
  if (!node)
    return NULL;

  return node;
}

/**
 * shishi_krberror_print:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle open for writing.
 * @krberror: KRB-ERROR to print.
 *
 * Print ASCII armored DER encoding of KRB-ERROR to file.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_print (Shishi * handle, FILE * fh, Shishi_asn1 krberror)
{
  return _shishi_print_armored_data (handle, fh, krberror, "KRB-ERROR", NULL);
}

/**
 * shishi_krberror_save:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle open for writing.
 * @krberror: KRB-ERROR to save.
 *
 * Save DER encoding of KRB-ERROR to file.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_save (Shishi * handle, FILE * fh, Shishi_asn1 krberror)
{
  return _shishi_save_data (handle, fh, krberror, "KRB-ERROR");
}

/**
 * shishi_krberror_to_file:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: KRB-ERROR to save.
 * @filetype: input variable specifying type of file to be written,
 *            see Shishi_filetype.
 * @filename: input variable with filename to write to.
 *
 * Write KRB-ERROR to file in specified TYPE.  The file will be
 * truncated if it exists.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_to_file (Shishi * handle, Shishi_asn1 krberror,
			 int filetype, char *filename)
{
  FILE *fh;
  int res;

  if (VERBOSE (handle))
    printf (_("Writing KRB-ERROR to %s...\n"), filename);

  fh = fopen (filename, "w");
  if (fh == NULL)
    return SHISHI_FOPEN_ERROR;

  if (VERBOSE (handle))
    printf (_("Writing KRB-ERROR in %s format...\n"),
	    filetype == SHISHI_FILETYPE_TEXT ? "TEXT" : "DER");

  if (filetype == SHISHI_FILETYPE_TEXT)
    res = shishi_krberror_print (handle, fh, krberror);
  else
    res = shishi_krberror_save (handle, fh, krberror);
  if (res != SHISHI_OK)
    return res;

  res = fclose (fh);
  if (res != 0)
    return SHISHI_FCLOSE_ERROR;

  if (VERBOSE (handle))
    printf (_("Writing KRB-ERROR to %s...done\n"), filename);

  return SHISHI_OK;
}

/**
 * shishi_krberror_parse:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle open for reading.
 * @krberror: output variable with newly allocated KRB-ERROR.
 *
 * Read ASCII armored DER encoded KRB-ERROR from file and populate given
 * variable.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_parse (Shishi * handle, FILE * fh, Shishi_asn1 * krberror)
{
  return _shishi_krberror_input (handle, fh, krberror, 0);
}

/**
 * shishi_krberror_read:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle open for reading.
 * @krberror: output variable with newly allocated KRB-ERROR.
 *
 * Read DER encoded KRB-ERROR from file and populate given variable.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_read (Shishi * handle, FILE * fh, Shishi_asn1 * krberror)
{
  return _shishi_krberror_input (handle, fh, krberror, 1);
}

/**
 * shishi_krberror_from_file:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: output variable with newly allocated KRB-ERROR.
 * @filetype: input variable specifying type of file to be read,
 *            see Shishi_filetype.
 * @filename: input variable with filename to read from.
 *
 * Read KRB-ERROR from file in specified TYPE.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_from_file (Shishi * handle, Shishi_asn1 * krberror,
			   int filetype, char *filename)
{
  int res;
  FILE *fh;

  if (VERBOSE (handle))
    printf (_("Reading KRB-ERROR from %s...\n"), filename);

  fh = fopen (filename, "r");
  if (fh == NULL)
    return SHISHI_FOPEN_ERROR;

  if (VERBOSE (handle))
    printf (_("Reading KRB-ERROR in %s format...\n"),
	    filetype == SHISHI_FILETYPE_TEXT ? "TEXT" : "DER");

  if (filetype == SHISHI_FILETYPE_TEXT)
    res = shishi_krberror_parse (handle, fh, krberror);
  else
    res = shishi_krberror_read (handle, fh, krberror);
  if (res != SHISHI_OK)
    return res;

  res = fclose (fh);
  if (res != 0)
    return SHISHI_FCLOSE_ERROR;

  if (VERBOSE (handle))
    printf (_("Reading KRB-ERROR from %s...done\n"), filename);

  return SHISHI_OK;
}

struct krb_error_msgs
{
  int errorcode;
  char *message;
};

enum krb_error_codes
{
  KDC_ERR_NONE = 0,
  KDC_ERR_NAME_EXP = 1,
  KDC_ERR_SERVICE_EXP = 2,
  KDC_ERR_BAD_PVNO = 3,
  KDC_ERR_C_OLD_MAST_KVNO = 4,
  KDC_ERR_S_OLD_MAST_KVNO = 5,
  KDC_ERR_C_PRINCIPAL_UNKNOWN = 6,
  KDC_ERR_S_PRINCIPAL_UNKNOWN = 7,
  KDC_ERR_PRINCIPAL_NOT_UNIQUE = 8,
  KDC_ERR_NULL_KEY = 9,
  KDC_ERR_CANNOT_POSTDATE = 10,
  KDC_ERR_NEVER_VALID = 11,
  KDC_ERR_POLICY = 12,
  KDC_ERR_BADOPTION = 13,
  KDC_ERR_ETYPE_NOSUPP = 14,
  KDC_ERR_SUMTYPE_NOSUPP = 15,
  KDC_ERR_PADATA_TYPE_NOSUPP = 16,
  KDC_ERR_TRTYPE_NOSUPP = 17,
  KDC_ERR_CLIENT_REVOKED = 18,
  KDC_ERR_SERVICE_REVOKED = 19,
  KDC_ERR_TGT_REVOKED = 20,
  KDC_ERR_CLIENT_NOTYET = 21,
  KDC_ERR_SERVICE_NOTYET = 22,
  KDC_ERR_KEY_EXPIRED = 23,
  KDC_ERR_PREAUTH_FAILED = 24,
  KDC_ERR_PREAUTH_REQUIRED = 25,
  KDC_ERR_SERVER_NOMATCH = 26,
  KDC_ERR_MUST_USE_USER2USER = 27,
  KDC_ERR_PATH_NOT_ACCPETED = 28,
  KDC_ERR_SVC_UNAVAILABLE = 29,
  KRB_AP_ERR_BAD_INTEGRITY = 31,
  KRB_AP_ERR_TKT_EXPIRED = 32,
  KRB_AP_ERR_TKT_NYV = 33,
  KRB_AP_ERR_REPEAT = 34,
  KRB_AP_ERR_NOT_US = 35,
  KRB_AP_ERR_BADMATCH = 36,
  KRB_AP_ERR_SKEW = 37,
  KRB_AP_ERR_BADADDR = 38,
  KRB_AP_ERR_BADVERSION = 39,
  KRB_AP_ERR_MSG_TYPE = 40,
  KRB_AP_ERR_MODIFIED = 41,
  KRB_AP_ERR_BADORDER = 42,
  KRB_AP_ERR_BADKEYVER = 44,
  KRB_AP_ERR_NOKEY = 45,
  KRB_AP_ERR_MUT_FAIL = 46,
  KRB_AP_ERR_BADDIRECTION = 47,
  KRB_AP_ERR_METHOD = 48,
  KRB_AP_ERR_BADSEQ = 49,
  KRB_AP_ERR_INAPP_CKSUM = 50,
  KRB_AP_PATH_NOT_ACCEPTED = 51,
  KRB_ERR_RESPONSE_TOO_BIG = 52,
  KRB_ERR_GENERIC = 60,
  KRB_ERR_FIELD_TOOLONG = 61,
  KDC_ERROR_CLIENT_NOT_TRUSTED = 62,
  KDC_ERROR_KDC_NOT_TRUSTED = 63,
  KDC_ERROR_INVALID_SIG = 64,
  KDC_ERR_KEY_TOO_WEAK = 65,
  KDC_ERR_CERTIFICATE_MISMATCH = 66,
  KRB_AP_ERR_NO_TGT = 67,
  KDC_ERR_WRONG_REALM = 68,
  KRB_AP_ERR_USER_TO_USER_REQUIRED = 69,
  KDC_ERR_CANT_VERIFY_CERTIFICATE = 70,
  KDC_ERR_INVALID_CERTIFICATE = 71,
  KDC_ERR_REVOKED_CERTIFICATE = 72,
  KDC_ERR_REVOCATION_STATUS_UNKNOWN = 73,
  KDC_ERR_REVOCATION_STATUS_UNAVAILABLE = 74,
  KDC_ERR_CLIENT_NAME_MISMATCH = 75,
  KDC_ERR_KDC_NAME_MISMATCH = 76,
  KDC_ERR_SIZE = 77
};

struct krb_error_msgs _shishi_krberror_messages[KDC_ERR_SIZE] = {
  {KDC_ERR_NONE, "No error"},
  {KDC_ERR_NAME_EXP, "Client's entry in database has expired"},
  {KDC_ERR_SERVICE_EXP, "Server's entry in database has expired"},
  {KDC_ERR_BAD_PVNO, "Requested protocol version number not supported"},
  {KDC_ERR_C_OLD_MAST_KVNO, "Client's key encrypted in old master key"},
  {KDC_ERR_S_OLD_MAST_KVNO, "Server's key encrypted in old master key"},
  {KDC_ERR_C_PRINCIPAL_UNKNOWN, "Client not found in Kerberos database"},
  {KDC_ERR_S_PRINCIPAL_UNKNOWN, "Server not found in Kerberos database"},
  {KDC_ERR_PRINCIPAL_NOT_UNIQUE, "Multiple principal entries in database"},
  {KDC_ERR_NULL_KEY, "The client or server has a null key"},
  {KDC_ERR_CANNOT_POSTDATE, "Ticket not eligible for postdating"},
  {KDC_ERR_NEVER_VALID, "Requested start time is later than end time"},
  {KDC_ERR_POLICY, "KDC policy rejects request"},
  {KDC_ERR_BADOPTION, "KDC cannot accommodate requested option"},
  {KDC_ERR_ETYPE_NOSUPP, "KDC has no support for encryption type"},
  {KDC_ERR_SUMTYPE_NOSUPP, "KDC has no support for checksum type"},
  {KDC_ERR_PADATA_TYPE_NOSUPP, "KDC has no support for padata type"},
  {KDC_ERR_TRTYPE_NOSUPP, "KDC has no support for transited type"},
  {KDC_ERR_CLIENT_REVOKED, "Clients credentials have been revoked"},
  {KDC_ERR_SERVICE_REVOKED, "Credentials for server have been revoked"},
  {KDC_ERR_TGT_REVOKED, "TGT has been revoked"},
  {KDC_ERR_CLIENT_NOTYET, "Client not yet valid - try again later"},
  {KDC_ERR_SERVICE_NOTYET, "Server not yet valid - try again later"},
  {KDC_ERR_KEY_EXPIRED, "Password has expired "},
  {KDC_ERR_PREAUTH_FAILED, "Pre-authentication information was invalid"},
  {KDC_ERR_PREAUTH_REQUIRED, "Additional pre-authenticationrequired [40]"},
  {KDC_ERR_SERVER_NOMATCH, "Requested server and ticket don't match"},
  {KDC_ERR_MUST_USE_USER2USER, "Server principal valid for user2user only"},
  {KDC_ERR_PATH_NOT_ACCPETED, "KDC Policy rejects transited path"},
  {KDC_ERR_SVC_UNAVAILABLE, "A service is not available"},
  {KRB_AP_ERR_BAD_INTEGRITY, "Integrity check on decrypted field failed"},
  {KRB_AP_ERR_TKT_EXPIRED, "Ticket expired"},
  {KRB_AP_ERR_TKT_NYV, "Ticket not yet valid"},
  {KRB_AP_ERR_REPEAT, "Request is a replay"},
  {KRB_AP_ERR_NOT_US, "The ticket isn't for us"},
  {KRB_AP_ERR_BADMATCH, "Ticket and authenticator don't match"},
  {KRB_AP_ERR_SKEW, "Clock skew too great"},
  {KRB_AP_ERR_BADADDR, "Incorrect net address"},
  {KRB_AP_ERR_BADVERSION, "Protocol version mismatch"},
  {KRB_AP_ERR_MSG_TYPE, "Invalid msg type"},
  {KRB_AP_ERR_MODIFIED, "Message stream modified"},
  {KRB_AP_ERR_BADORDER, "Message out of order"},
  {KRB_AP_ERR_BADKEYVER, "Specified version of key is not available"},
  {KRB_AP_ERR_NOKEY, "Service key not available"},
  {KRB_AP_ERR_MUT_FAIL, "Mutual authentication failed"},
  {KRB_AP_ERR_BADDIRECTION, "Incorrect message direction"},
  {KRB_AP_ERR_METHOD, "Alternative authentication method required"},
  {KRB_AP_ERR_BADSEQ, "Incorrect sequence number in message"},
  {KRB_AP_ERR_INAPP_CKSUM, "Inappropriate type of checksum in message"},
  {KRB_AP_PATH_NOT_ACCEPTED, "Policy rejects transited path"},
  {KRB_ERR_RESPONSE_TOO_BIG, "Response too big for UDP, retry with TCP"},
  {KRB_ERR_GENERIC, "Generic error (description in e-text)"},
  {KRB_ERR_FIELD_TOOLONG, "Field is too long for this implementation"},
  {KDC_ERROR_CLIENT_NOT_TRUSTED, "(pkinit)"},
  {KDC_ERROR_KDC_NOT_TRUSTED, "(pkinit)"},
  {KDC_ERROR_INVALID_SIG, "(pkinit)"},
  {KDC_ERR_KEY_TOO_WEAK, "(pkinit)"},
  {KDC_ERR_CERTIFICATE_MISMATCH, "(pkinit)"},
  {KRB_AP_ERR_NO_TGT, "(user-to-user)"},
  {KDC_ERR_WRONG_REALM, "(user-to-user)"},
  {KRB_AP_ERR_USER_TO_USER_REQUIRED, "(user-to-user)"},
  {KDC_ERR_CANT_VERIFY_CERTIFICATE, "(pkinit)"},
  {KDC_ERR_INVALID_CERTIFICATE, "(pkinit)"},
  {KDC_ERR_REVOKED_CERTIFICATE, "(pkinit)"},
  {KDC_ERR_REVOCATION_STATUS_UNKNOWN, "(pkinit)"},
  {KDC_ERR_REVOCATION_STATUS_UNAVAILABLE, "(pkinit)"},
  {KDC_ERR_CLIENT_NAME_MISMATCH, "(pkinit)"},
  {KDC_ERR_KDC_NAME_MISMATCH, "(pkinit)"}
};

/**
 * shishi_krberror_errorcode_message:
 * @handle: shishi handle as allocated by shishi_init().
 * @errorcode: integer KRB-ERROR error code.
 *
 * Return value: Return a string describing error code.  This function
 *               will always return a string even if the error code
 *               isn't known.
 **/
const char *
shishi_krberror_errorcode_message (Shishi * handle, int errorcode)
{
  int i;
  char *p;

  for (i = 0; i < KDC_ERR_SIZE; i++)
    {
      if (errorcode == _shishi_krberror_messages[i].errorcode)
	return _(_shishi_krberror_messages[i].message);
    }

  /* XXX memory leak */
  asprintf (&p, _("Unknown KRB-ERROR error code %d."), errorcode);
  return p;
}

/**
 * shishi_krberror_errorcode:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: KRB-ERROR structure with error code.
 * @errorcode: output integer KRB-ERROR error code.
 *
 * Extract error code from KRB-ERROR.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_errorcode (Shishi * handle,
			   Shishi_asn1 krberror, int *errorcode)
{
  return shishi_asn1_integer_field (handle, krberror, errorcode,
				    "error-code");
}

/**
 * shishi_krberror_errorcode_fast:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: KRB-ERROR structure with error code.
 *
 * Return value: Return error code (see shishi_krberror_errorcode())
 *               directly, or -1 on error.
 **/
int
shishi_krberror_errorcode_fast (Shishi * handle, Shishi_asn1 krberror)
{
  int i;

  if (shishi_krberror_errorcode (handle, krberror, &i) != SHISHI_OK)
    i = -1;

  return i;
}

/**
 * shishi_krberror_etext:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: KRB-ERROR structure with error code.
 * @etext: output array with error text.
 * @etextlen: on input, maximum size of output array with error text,
 *            on output, actual size of output array with error text.
 *
 * Extract additional error text from server (possibly empty).
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_etext (Shishi * handle, Shishi_asn1 krberror,
		       char *etext, size_t * etextlen)
{
  return shishi_asn1_optional_field (handle, krberror, etext, etextlen,
				     "e-text");
}

/**
 * shishi_krberror_message:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: KRB-ERROR structure with error code.
 *
 * Extract error code (see shishi_krberror_errorcode_fast()) and
 * return error message (see shishi_krberror_errorcode_message()).
 *
 * Return value: Return a string describing error code.  This function
 *               will always return a string even if the error code
 *               isn't known.
 **/
const char *
shishi_krberror_message (Shishi * handle, Shishi_asn1 krberror)
{
  return shishi_krberror_errorcode_message
    (handle, shishi_krberror_errorcode_fast (handle, krberror));
}

/**
 * shishi_krberror_pretty_print:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle opened for writing.
 * @krberror: KRB-ERROR structure with error code.
 *
 * Print KRB-ERROR error condition and some explanatory text to file
 * descriptor.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_pretty_print (Shishi * handle, FILE * fh,
			      Shishi_asn1 krberror)
{
  char buf[BUFSIZ];
  size_t len = BUFSIZ;
  int res;

  if (VERBOSEASN1 (handle))
    shishi_krberror_print (handle, fh, krberror);

  fprintf (fh, "Kerberos error code from server:\n%s\n",
	   shishi_krberror_message (handle, krberror));

  res = shishi_krberror_etext (handle, krberror, buf, &len);
  buf[len] = '\0';
  if (res == SHISHI_OK && len > 0)
    fprintf (fh, "Additional Kerberos error message from server:\n%s\n", buf);


  return SHISHI_OK;
}
