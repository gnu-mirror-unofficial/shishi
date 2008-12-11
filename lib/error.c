/* error.c --- Error handling functions.
 * Copyright (C) 2002, 2003, 2004, 2006, 2007, 2008  Simon Josefsson
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
   N_("Shishi success")},
  {SHISHI_ASN1_ERROR,
   N_("Error in ASN.1 function (corrupt data?)")},
  {SHISHI_FOPEN_ERROR,
   N_("Could not open file")},
  {SHISHI_IO_ERROR,
   N_("File input/output error")},
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
  {SHISHI_TICKET_BAD_KEYTYPE,
   N_("Keytype used to encrypt ticket doesn't match provided key. "
      "This usually indicates an internal application error.")},
  {SHISHI_CRYPTO_INTERNAL_ERROR,
   N_("Internal error in low-level crypto routines.")},
  {SHISHI_CRYPTO_ERROR,
   N_("Low-level cryptographic primitive failed.  This usually indicates "
      "bad password or data corruption.")},
  {SHISHI_KDC_TIMEOUT,
   N_("Timedout talking to KDC. This usually indicates a network "
      "or KDC address problem.")},
  {SHISHI_KDC_NOT_KNOWN_FOR_REALM,
   N_("No KDC for realm known.")},
  {SHISHI_SOCKET_ERROR,
   N_("The system call socket() failed.  This usually indicates that "
      "your system does not support the socket type.")},
  {SHISHI_BIND_ERROR,
   N_("The system call bind() failed.  This usually indicates "
      "insufficient permissions.")},
  {SHISHI_SENDTO_ERROR,
   N_("The system call sendto() failed.")},
  {SHISHI_CLOSE_ERROR,
   N_("The system call close() failed.")},
  {SHISHI_GOT_KRBERROR,
   N_("Server replied with an error message to request.")},
  {SHISHI_INVALID_TKTS,
   N_("Ticketset not initialized.  This usually indicates an internal "
      "application error.")},
  {SHISHI_APREQ_DECRYPT_FAILED,
   N_("Could not decrypt AP-REQ using provided key. "
      "This usually indicates an internal application error.")},
  {SHISHI_TICKET_DECRYPT_FAILED,
   N_("Could not decrypt Ticket using provided key. "
      "This usually indicates an internal application error.")},
  {SHISHI_KEYTAB_ERROR,
   N_("Failed to parse keytab file")},
  {SHISHI_CCACHE_ERROR,
   N_("Failed to parse credential cache file")},
  {-1, NULL}
};

/**
 * shishi_strerror:
 * @err: shishi error code.
 *
 * Convert return code to human readable string.
 *
 * Return value: Returns a pointer to a statically allocated string
 * containing a description of the error with the error value @err.
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
 * Extract detailed error information string.  Note that the memory is
 * managed by the Shishi library, so you must not deallocate the
 * string.
 *
 * Return value: Returns pointer to error information string, that must
 *   not be deallocate by caller.
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
 * Clear the detailed error information string.  See shishi_error()
 * for how to access the error string, and shishi_error_set() and
 * shishi_error_printf() for how to set the error string.  This
 * function is mostly for Shishi internal use, but if you develop an
 * extension of Shishi, it may be useful to use the same error
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
 * @errstr: Zero terminated character array containing error description,
 *   or NULL to clear the error description string.
 *
 * Set the detailed error information string to specified string.  The
 * string is copied into the Shishi internal structure, so you can
 * deallocate the string passed to this function after the call.  This
 * function is mostly for Shishi internal use, but if you develop an
 * extension of Shishi, it may be useful to use the same error
 * handling infrastructure.
 **/
void
shishi_error_set (Shishi * handle, const char *errstr)
{
  if (errstr)
    {
      strncpy (handle->error, errstr, sizeof (handle->error));

      if (VERBOSE (handle))
	puts (handle->error);
    }
  else
    shishi_error_clear (handle);
}

/**
 * shishi_error_printf:
 * @handle: shishi handle as allocated by shishi_init().
 * @format: printf style format string.
 * @...: print style arguments.
 *
 * Set the detailed error information string to a printf formatted
 * string.  This function is mostly for Shishi internal use, but if
 * you develop an extension of Shishi, it may be useful to use the
 * same error handling infrastructure.
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
 * Get the current output type for logging messages.
 *
 * Return value: Return output type (NULL, stderr or syslog) for
 *   informational and warning messages.
 **/
int
shishi_error_outputtype (Shishi * handle)
{
  return handle->outputtype;
}

/**
 * shishi_error_set_outputtype:
 * @handle: shishi handle as allocated by shishi_init().
 * @type: output type.
 *
 * Set output type (NULL, stderr or syslog) for informational
 * and warning messages.
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
 * @...: print style arguments.
 *
 * Print informational message to output as defined in handle.
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
      syslog (LOG_ERR, _("libshishi: info: %s"), out);
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
 * @...: print style arguments.
 *
 * Print a warning to output as defined in handle.
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
      syslog (LOG_ERR, _("libshishi: warning: %s"), out);
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
 * @...: print style arguments.
 *
 * Print a diagnostic message to output as defined in handle.
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
      syslog (LOG_DEBUG, "%s", out);
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
