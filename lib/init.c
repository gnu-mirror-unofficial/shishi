/* init.c	initialization functions
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
#include <gcrypt.h>

#if ENABLE_NLS
char *
_shishi_gettext (const char *str)
{
  return dgettext (PACKAGE, str);
}

void
_shishi_gettext_init ()
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
read_asn1 ()
{
  ASN1_TYPE definitions = ASN1_TYPE_EMPTY;
  int asn1_result = ASN1_SUCCESS;
  char errorDescription[MAX_ERROR_DESCRIPTION_SIZE];

  asn1_result = asn1_array2tree (shishi_asn1_tab,
				 &definitions, errorDescription);

  if (asn1_result != ASN1_SUCCESS)
    {
      printf ("Internal error reading ASN.1 definition.\n");
      printf ("Error: %s\n", errorDescription);
      printf ("libasn1 ERROR: %s\n", libtasn1_strerror (asn1_result));
      exit (1);
    }

  return definitions;
}

/**
 * shishi_init:
 *
 * Initializes the shishi library.
 * 
 * Return Value: Returns Shishi library handle, or %NULL on error.
 **/
Shishi *
shishi (void)
{
  Shishi *handle;
  char *value;
  char *tmp;
  int res;

  handle = (Shishi *) malloc (sizeof (*handle));
  if (handle == NULL)
    return NULL;

  res = gcry_control (GCRYCTL_INIT_SECMEM, 512, 0);
  if (res != GCRYERR_SUCCESS)
    return NULL;

  memset ((void *) handle, 0, sizeof (*handle));

  handle->asn1 = read_asn1 ();

  handle->shortnonceworkaround = 1;

  handle->kdctimeout = 5;
  handle->kdcretries = 3;

  handle->clientkdcetypes = malloc(sizeof(*handle->clientkdcetypes)*2);
  handle->clientkdcetypes[0] = SHISHI_DES3_CBC_HMAC_SHA1_KD;
  handle->clientkdcetypes[1] = SHISHI_DES_CBC_MD5;
  handle->nclientkdcetypes = 2;

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

int
_shishi_init_read (Shishi *handle,
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
    rc = shishi_ticketset_init (handle, &handle->ticketset);
  if (rc != SHISHI_OK)
    return rc;

  if (*ticketsetfile)
    rc = shishi_ticketset_from_file (handle, handle->ticketset, ticketsetfile);
  if (rc != SHISHI_OK && rc != SHISHI_FOPEN_ERROR)
    return rc;

  if (*systemcfgfile)
    rc = shishi_cfg_from_file (handle, systemcfgfile);
  if (rc != SHISHI_OK && rc != SHISHI_FOPEN_ERROR)
    return rc;

  if (*usercfgfile)
    rc = shishi_cfg_from_file (handle, usercfgfile);
  if (rc != SHISHI_OK && rc != SHISHI_FOPEN_ERROR)
    return rc;

  if (DEBUG(handle))
    shishi_cfg_print (handle, stdout);

  return SHISHI_OK;
}

int
shishi_init_with_paths (Shishi **handle,
			const char *ticketsetfile,
			const char *systemcfgfile, 
			const char *usercfgfile)
{
  if (!handle || !(*handle = shishi()))
    return SHISHI_HANDLE_ERROR;

  return _shishi_init_read (*handle, ticketsetfile, 
			    systemcfgfile, usercfgfile);
}

int
shishi_init (Shishi **handle)
{
  if (!handle || !(*handle = shishi()))
    return SHISHI_HANDLE_ERROR;

  return _shishi_init_read (*handle, shishi_ticketset_default_file (*handle),
			    shishi_cfg_default_systemfile (*handle),
			    shishi_cfg_default_userfile (*handle));
}

/* XXX remove these: */

ASN1_TYPE
shishi_last_authenticator (Shishi * handle)
{
  return handle->lastauthenticator;
}

ASN1_TYPE
shishi_last_apreq (Shishi * handle)
{
  return handle->lastapreq;
}

ASN1_TYPE
shishi_last_aprep (Shishi * handle)
{
  return handle->lastaprep;
}

ASN1_TYPE
shishi_last_encapreppart (Shishi * handle)
{
  return handle->lastencapreppart;
}

void
shishi_warn(Shishi * handle, char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  if (!SILENT(handle))
    {
      fprintf(stderr, "libshishi: warning: ");
      vfprintf(stderr, fmt, ap);
      fprintf(stderr, "\n");
    }
  va_end(ap);
}
