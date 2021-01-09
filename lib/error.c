/* error.c --- Error handling functions.
 * Copyright (C) 2002-2021 Simon Josefsson
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

struct shishi_error_msgs
{
  int errorcode;
  const char *message;
};

static const struct shishi_error_msgs _shishi_error_messages[] = {
  {SHISHI_OK,
   N_("Shishi success.")},
  {SHISHI_ASN1_ERROR,
   N_("Error in ASN.1 function. (corrupt data?)")},
  {SHISHI_FOPEN_ERROR,
   N_("Could not open file.")},
  {SHISHI_IO_ERROR,
   N_("File input/output error.")},
  {SHISHI_MALLOC_ERROR,
   N_("Memory allocation error in shishi library.")},
  {SHISHI_BASE64_ERROR,
   N_("Base64 encoding or decoding failed. Data corrupt?")},
  {SHISHI_REALM_MISMATCH,
   N_("Client realm value differ between request and reply.")},
  {SHISHI_CNAME_MISMATCH,
   N_("Client name value differ between request and reply.")},
  {SHISHI_NONCE_MISMATCH,
   N_("Replay protection value (nonce) differ between request and reply.")},
  {SHISHI_TGSREP_BAD_KEYTYPE,
   N_("Incorrect key type used in TGS reply.")},
  {SHISHI_KDCREP_BAD_KEYTYPE,
   N_("Incorrect key type used in reply from KDC.")},
  {SHISHI_APREP_BAD_KEYTYPE,
   N_("Incorrect key type used in AP reply.")},
  {SHISHI_APREP_VERIFY_FAILED,
   N_("Failed verification of AP reply.")},
  {SHISHI_APREQ_BAD_KEYTYPE,
   N_("Incorrect key type used in AP request.")},
  {SHISHI_TOO_SMALL_BUFFER,
   N_("Provided buffer was too small.")},
  {SHISHI_DERIVEDKEY_TOO_SMALL,
   N_("Derived key material is too short to be applicable.")},
  {SHISHI_KEY_TOO_LARGE,
   N_("The key is too large to be usable.")},
  {SHISHI_CRYPTO_ERROR,
   N_("Low-level cryptographic primitive failed.  This usually indicates "
      "bad password or data corruption.")},
  {SHISHI_CRYPTO_INTERNAL_ERROR,
   N_("Internal error in low-level crypto routines.")},
  {SHISHI_SOCKET_ERROR,
   N_("The system call socket() failed.  This usually indicates that "
      "your system does not support the socket type.")},
  {SHISHI_BIND_ERROR,
   N_("The system call bind() failed.  This usually indicates "
      "insufficient permissions.")},
  {SHISHI_SENDTO_ERROR,
   N_("The system call sendto() failed.")},
  {SHISHI_RECVFROM_ERROR,
   N_("Error receiving data from server.")},
  {SHISHI_CLOSE_ERROR,
   N_("The system call close() failed.")},
  {SHISHI_KDC_TIMEOUT,
   N_("Timed out talking to KDC.  This usually indicates a network "
      "or KDC address problem.")},
  {SHISHI_KDC_NOT_KNOWN_FOR_REALM,
   N_("No KDC known for given realm.")},
  {SHISHI_TTY_ERROR,
   N_("No TTY assigned to process.")},
  {SHISHI_GOT_KRBERROR,
   N_("Server replied to the request with an error message.")},
  {SHISHI_HANDLE_ERROR,
   N_("Failure to use handle.  Missing handle, or misconfigured.")},
  {SHISHI_INVALID_TKTS,
   N_("Ticket set not initialized.  This usually indicates an internal "
      "application error.")},
  {SHISHI_TICKET_BAD_KEYTYPE,
   N_("Key type used to encrypt ticket doesn't match provided key. "
      "This usually indicates an internal application error.")},
  {SHISHI_INVALID_KEY,
   N_("Reference to invalid encryption key.")},
  {SHISHI_APREQ_DECRYPT_FAILED,
   N_("Could not decrypt AP-REQ using provided key. "
      "This usually indicates an internal application error.")},
  {SHISHI_TICKET_DECRYPT_FAILED,
   N_("Could not decrypt Ticket using provided key. "
      "This usually indicates an internal application error.")},
  {SHISHI_INVALID_TICKET,
   N_("Invalid ticked passed in call.")},
  {SHISHI_OUT_OF_RANGE,
   N_("Argument lies outside of valid range.")},
  {SHISHI_ASN1_NO_ELEMENT,
   N_("The ASN.1 structure does not contain the indicated element.")},
  {SHISHI_SAFE_BAD_KEYTYPE,
   N_("Attempted access to non-existent key type.")},
  {SHISHI_SAFE_VERIFY_FAILED,
   N_("Verification failed on either side.")},
  {SHISHI_PKCS5_INVALID_PRF,
   N_("Invalid PKCS5 descriptor.")},
  {SHISHI_PKCS5_INVALID_ITERATION_COUNT,
   N_("Invalid claim of iteration count in PKCS5 descriptor.")},
  {SHISHI_PKCS5_INVALID_DERIVED_KEY_LENGTH,
   N_("Derived key length is incorrect for PKCS5 descriptor.")},
  {SHISHI_PKCS5_DERIVED_KEY_TOO_LONG,
   N_("Derived key is too long for PKCS5 descriptor.")},
  {SHISHI_INVALID_PRINCIPAL_NAME,
   N_("Principal name syntax error.")},
  {SHISHI_INVALID_ARGUMENT,
   N_("Invalid argument passed in call.  Wrong or unknown value.")},
  {SHISHI_ASN1_NO_VALUE,
   N_("The indicated ASN.1 element does not carry a value.")},
  {SHISHI_CONNECT_ERROR,
   N_("Connection attempt failed.  Try again, or check availability.")},
  {SHISHI_VERIFY_FAILED,
   N_("Verification failed on either side.")},
  {SHISHI_PRIV_BAD_KEYTYPE,
   N_("The private key uses an incompatible encryption type.")},
  {SHISHI_FILE_ERROR,
   N_("The desired file could not be accessed.  Check permissions.")},
  {SHISHI_ENCAPREPPART_BAD_KEYTYPE,
   N_("The present AP reply specifies an inpermissible key type.")},
  {SHISHI_GETTIMEOFDAY_ERROR,
   N_("A request for present time of day has failed. "
      "This is usually internal, but a valid time is imperative for us.")},
  {SHISHI_KEYTAB_ERROR,
   N_("Failed to parse keytab file.")},
  {SHISHI_CCACHE_ERROR,
   N_("Failed to parse credential cache file.")},
  {-1, NULL}
};

/**
 * shishi_strerror:
 * @err: shishi error code.
 *
 * Converts the return code in @err to a human readable string.
 *
 * Return value: Returns a pointer to a statically allocated string
 * containing a description of the error with code @err.
 * This string can be used to output a diagnostic message to the user.
 **/
const char *
shishi_strerror (int err)
{
  const char *p = _("Unknown error");
  size_t i;

  for (i = 0; _shishi_error_messages[i].errorcode != -1; i++)
    if (_shishi_error_messages[i].errorcode == err)
      {
	p = _(_shishi_error_messages[i].message);
	break;
      }

  return p;

}

/**
 * shishi_error:
 * @handle: shishi handle as allocated by shishi_init().
 *
 * Extracts detailed information on the most recently occurred
 * error condition.  Note that memory is managed by the Shishi
 * library, so the returned string must not be deallocated.
 *
 * Return value: Returns a pointer to a string describing an error.
 *   The string must not be deallocated by the caller.
 **/
const char *
shishi_error (Shishi * handle)
{
  if (handle->error)
    return handle->error;

  return _("No error");
}

/**
 * shishi_error_clear:
 * @handle: shishi handle as allocated by shishi_init().
 *
 * Clears the internal error description.  See shishi_error()
 * on how to access the error string, and shishi_error_set() as well
 * as shishi_error_printf() on how to set the error string.
 *
 * This function is mostly for Shishi's internal use, but if you develop
 * an extension of Shishi, it may be useful to support the same error
 * handling infrastructure.
 **/
void
shishi_error_clear (Shishi * handle)
{
  handle->error[0] = '\0';
}

/**
 * shishi_error_set:
 * @handle: shishi handle as allocated by shishi_init().
 * @errstr: A null-terminated character string holding a description,
 *   or %NULL to clear the internal error string.
 *
 * Sets the error description to the content of @errstr.  The
 * string is copied into the Shishi internal structure, so you can
 * deallocate any string passed to this function.
 *
 * This function is mostly for Shishi's internal use, but if you develop
 * an extension of Shishi, it may be useful to support the same error
 * handling infrastructure.
 **/
void
shishi_error_set (Shishi * handle, const char *errstr)
{
  if (errstr)
    {
      strncpy (handle->error, errstr, sizeof (handle->error) - 1);
      handle->error[sizeof (handle->error) - 1] = '\0';

      if (VERBOSENOISE (handle))
	puts (handle->error);
    }
  else
    shishi_error_clear (handle);
}

/**
 * shishi_error_printf:
 * @handle: shishi handle as allocated by shishi_init().
 * @format: printf style format string.
 * @...: printf style arguments.
 *
 * Sets the internal error description to a printf(3) formatted
 * string.  This function is mostly for Shishi's internal use, but if
 * you develop an extension of Shishi, it may be useful to support the
 * same infrastructure for error handling.
 **/
void
shishi_error_printf (Shishi * handle, const char *format, ...)
{
  va_list ap;
  char *s;

  va_start (ap, format);

  vasprintf (&s, format, ap);
  strncpy (handle->error, s, sizeof (handle->error));
  handle->error[sizeof (handle->error) - 1] = '\0';
  free (s);

  if (VERBOSE (handle))
    puts (handle->error);

  va_end (ap);
}

/**
 * shishi_error_outputtype:
 * @handle: shishi handle as allocated by shishi_init().
 *
 * Reports the current output type used in message logging.
 *
 * Return value: Returns the output type.  %SHISHI_OUTPUTTYPE_NULL
 *   means no output. %SHISHI_OUTPUTTYPE_STDERR and
 *   %SHISHI_OUTPUTTYPE_SYSLOG direct text to the console, or to the
 *   syslog system.
 **/
int
shishi_error_outputtype (Shishi * handle)
{
  return handle->outputtype;
}

/**
 * shishi_error_set_outputtype:
 * @handle: shishi handle as allocated by shishi_init().
 * @type: output type, of enum type #Shishi_outputtype.
 *
 * Sets the output type (%NULL, %stderr or %syslog) used for information
 * and warning messages.  Intended values are %SHISHI_OUTPUTTYPE_NULL,
 * for no output at all, %SHISHI_OUTPUTTYPE_STDERR for output to the
 * console, and %SHISHI_OUTPUTTYPE_SYSLOG for syslog messaging.
 * The first value covers everything different from the latter two values.
 **/
void
shishi_error_set_outputtype (Shishi * handle, int type)
{
  handle->outputtype = type;
}

/**
 * shishi_info:
 * @handle: shishi handle as allocated by shishi_init().
 * @format: printf style format string.
 * @...: printf style arguments.
 *
 * Prints an informational message, composed from the arguments,
 * to the output stream set in @handle.
 **/
void
shishi_info (Shishi * handle, const char *format, ...)
{
  va_list ap;
  char *out;
  int type;

  va_start (ap, format);
  vasprintf (&out, format, ap);

  type = shishi_error_outputtype (handle);
  switch (type)
    {
    case SHISHI_OUTPUTTYPE_SYSLOG:
      /* If we don't have syslog, log to stderr... */
#ifdef HAVE_SYSLOG
      /* Which facility is optimal?  */
      syslog (LOG_INFO, _("libshishi: info: %s"), out);
      break;
#endif
    case SHISHI_OUTPUTTYPE_STDERR:
      fprintf (stderr, _("libshishi: info: %s\n"), out);
      break;
    default:
      break;
    }

  free (out);
  va_end (ap);
}

/**
 * shishi_warn:
 * @handle: shishi handle as allocated by shishi_init().
 * @format: printf style format string.
 * @...: printf style arguments.
 *
 * Prints a warning, composed from the arguments, to the output
 * stream set in @handle.
 **/
void
shishi_warn (Shishi * handle, const char *format, ...)
{
  va_list ap;
  char *out;
  int type;

  va_start (ap, format);
  vasprintf (&out, format, ap);

  type = shishi_error_outputtype (handle);
  switch (type)
    {
    case SHISHI_OUTPUTTYPE_SYSLOG:
      /* If we don't have syslog, log to stderr... */
#ifdef HAVE_SYSLOG
      /* Which facility is optimal?  */
      syslog (LOG_WARNING, _("libshishi: warning: %s"), out);
      break;
#endif
    case SHISHI_OUTPUTTYPE_STDERR:
      fprintf (stderr, _("libshishi: warning: %s\n"), out);
      break;
    default:
      break;
    }

  free (out);
  va_end (ap);
}

/**
 * shishi_verbose:
 * @handle: shishi handle as allocated by shishi_init().
 * @format: printf style format string.
 * @...: printf style arguments.
 *
 * Prints a diagnostic message, composed from the arguments,
 * to the output stream set in @handle.  The current verbosity
 * setting determines whether the message is actually printed,
 * or is suppressed due to low significance.
 **/
void
shishi_verbose (Shishi * handle, const char *format, ...)
{
  va_list ap;
  char *out;
  int type;

  if (!VERBOSE (handle))
    return;

  va_start (ap, format);
  vasprintf (&out, format, ap);

  type = shishi_error_outputtype (handle);
  switch (type)
    {
    case SHISHI_OUTPUTTYPE_SYSLOG:
      /* If we don't have syslog, log to stderr... */
#ifdef HAVE_SYSLOG
      /* Which facility is optimal?  */
      syslog (LOG_INFO, "%s", out);
      break;
#endif
    case SHISHI_OUTPUTTYPE_STDERR:
      fprintf (stderr, "%s\n", out);
      break;
    default:
      break;
    }

  free (out);
  va_end (ap);
}
