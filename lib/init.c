/* init.c	initialization functions
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
#include <gcrypt.h>

#define WARNSTR "libshishi: warning: "

#if ENABLE_NLS
char *
_shishi_gettext (const char *str)
{
  return dgettext (PACKAGE, str);
}

static void
_shishi_gettext_init (void)
{
  bindtextdomain (PACKAGE, LOCALEDIR);
#ifdef HAVE_BIND_TEXTDOMAIN_CODESET
  bind_textdomain_codeset (PACKAGE, "UTF-8");
#endif
  textdomain (PACKAGE);
}
#endif /* ENABLE_NLS */

extern const ASN1_ARRAY_TYPE shishi_asn1_tab[];

static ASN1_TYPE
read_asn1 (void)
{
  ASN1_TYPE definitions = ASN1_TYPE_EMPTY;
  int asn1_result = ASN1_SUCCESS;
  char errorDescription[MAX_ERROR_DESCRIPTION_SIZE];

  asn1_result = asn1_array2tree (shishi_asn1_tab,
				 &definitions, errorDescription);
  if (asn1_result != ASN1_SUCCESS)
    {
      fprintf (stderr, "libshishi: error: %s\n", errorDescription);
      fprintf (stderr, "libshishi: error: %s\n",
	       libtasn1_strerror (asn1_result));
      return ASN1_TYPE_EMPTY;
    }

  return definitions;
}

/**
 * shishi_init:
 *
 * Initializes the Shishi library.  If this function fails, it may print
 * diagnostic errors to stderr.
 *
 * Return Value: Returns Shishi library handle, or %NULL on error.
 **/
Shishi *
shishi (void)
{
  Shishi *handle;
  char *tmp;

  handle = (Shishi *) malloc (sizeof (*handle));
  if (handle == NULL)
    {
      fprintf(stderr, "libshishi: error: %s\n",
	      shishi_strerror (SHISHI_MALLOC_ERROR));
      return NULL;
    }
  memset ((void *) handle, 0, sizeof (*handle));

#if 0
  res = gcry_control (GCRYCTL_INIT_SECMEM, 512, 0);
  if (res != GCRYERR_SUCCESS)
    {
      fprintf(stderr, "libshishi: error: %s\n",
	      shishi_strerror (SHISHI_GCRYPT_ERROR));
      return NULL;
    }
#else
  gcry_control (GCRYCTL_DISABLE_SECMEM, NULL, 0);
#endif

  handle->asn1 = read_asn1 ();
  if (handle->asn1 == ASN1_TYPE_EMPTY)
    {
      fprintf(stderr, "libshishi: error: %s\n",
	      shishi_strerror (SHISHI_ASN1_ERROR));
      return NULL;
    }

  handle->kdctimeout = 5;
  handle->kdcretries = 3;

  handle->nclientkdcetypes = 1;
  handle->clientkdcetypes = malloc (sizeof (*handle->clientkdcetypes) *
				    handle->nclientkdcetypes);
  if (handle->clientkdcetypes == NULL)
    {
      fprintf(stderr, "libshishi: error: %s\n",
	      shishi_strerror (SHISHI_MALLOC_ERROR));
      return NULL;
    }
  handle->clientkdcetypes[0] = SHISHI_AES256_CTS_HMAC_SHA1_96;

  tmp = shishi_realm_default_guess ();
  shishi_realm_default_set (handle, tmp);
  free (tmp);

  tmp = shishi_principal_default_guess ();
  if (tmp != NULL)
    {
      shishi_principal_default_set (handle, tmp);
      free (tmp);
    }

  return handle;
}

static int
_shishi_init_read (Shishi * handle,
		   const char *ticketsetfile,
		   const char *systemcfgfile,
		   const char *usercfgfile)
{
  int rc = SHISHI_OK;

  if (!ticketsetfile)
    ticketsetfile = shishi_ticketset_default_file (handle);

  if (!systemcfgfile)
    systemcfgfile = shishi_cfg_default_systemfile (handle);

  if (!usercfgfile)
    usercfgfile = shishi_cfg_default_userfile (handle);

  if (!handle->ticketset)
    rc = shishi_ticketset (handle, &handle->ticketset);
  if (rc != SHISHI_OK)
    return rc;

  if (*ticketsetfile)
    rc = shishi_ticketset_from_file (handle->ticketset, ticketsetfile);
  if (rc == SHISHI_FOPEN_ERROR)
    fprintf (stderr, WARNSTR "%s: %s\n", ticketsetfile, strerror(errno));
  if (rc != SHISHI_OK && rc != SHISHI_FOPEN_ERROR)
    return rc;

  if (*systemcfgfile)
    rc = shishi_cfg_from_file (handle, systemcfgfile);
  if (rc == SHISHI_FOPEN_ERROR)
    fprintf (stderr, WARNSTR "%s: %s\n", systemcfgfile, strerror(errno));
  if (rc != SHISHI_OK && rc != SHISHI_FOPEN_ERROR)
    return rc;

  if (*usercfgfile)
    rc = shishi_cfg_from_file (handle, usercfgfile);
  if (rc == SHISHI_FOPEN_ERROR)
    fprintf (stderr, WARNSTR "%s: %s\n", usercfgfile, strerror(errno));
  if (rc != SHISHI_OK && rc != SHISHI_FOPEN_ERROR)
    return rc;

  if (VERBOSE (handle))
    shishi_cfg_print (handle, stdout);

  return SHISHI_OK;
}

/**
 * shishi_init:
 * @handle: pointer to handle to be created.
 *
 * Create a Shishi library handle and read the system configuration
 * file, user configuration file and user tickets from the defaul
 * paths.  The paths to the system configuration file is decided at
 * compile time, and is $sysconfdir/shishi.conf.  The user
 * configuration file is $HOME/.shishi/config, and the user ticket
 * file is $HOME/.shishi/ticket.  The handle is allocated regardless
 * of return values, except for SHISHI_HANDLE_ERROR which indicates a
 * problem allocating the handle.  (The other error conditions comes
 * from reading the files.)
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_init (Shishi ** handle)
{
  if (!handle || !(*handle = shishi ()))
    return SHISHI_HANDLE_ERROR;

  return _shishi_init_read (*handle, shishi_ticketset_default_file (*handle),
			    shishi_cfg_default_systemfile (*handle),
			    shishi_cfg_default_userfile (*handle));
}

/**
 * shishi_init_with_paths:
 * @handle: pointer to handle to be created.
 * @ticketsetfile: Filename of ticket file, or NULL.
 * @systemcfgfile: Filename of system configuration, or NULL.
 * @usercfgfile: Filename of user configuration, or NULL.
 *
 * Like shishi_init() but use explicit paths.  Like shishi_init(), the
 * handle is allocated regardless of return values, except for
 * SHISHI_HANDLE_ERROR which indicates a problem allocating the
 * handle.  (The other error conditions comes from reading the files.)
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_init_with_paths (Shishi ** handle,
			const char *ticketsetfile,
			const char *systemcfgfile,
			const char *usercfgfile)
{
  if (!handle || !(*handle = shishi ()))
    return SHISHI_HANDLE_ERROR;

  shishi_ticketset_default_file_set (*handle, ticketsetfile);

  return _shishi_init_read (*handle, ticketsetfile,
			    systemcfgfile, usercfgfile);
}

void
shishi_warn (Shishi * handle, const char *fmt, ...)
{
  va_list ap;
  va_start (ap, fmt);
  if (VERBOSE (handle))
    {
      fprintf (stderr, WARNSTR);
      vfprintf (stderr, fmt, ap);
      fprintf (stderr, "\n");
    }
  va_end (ap);
}
