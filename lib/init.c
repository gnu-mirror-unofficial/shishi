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
shishi_init ()
{
  Shishi *handle;
  char *value;
  char *tmp;
  int res;

  handle = (Shishi *) malloc (sizeof (*handle));
  if (handle == NULL)
    return NULL;

  memset ((void *) handle, 0, sizeof (*handle));

  handle->asn1 = read_asn1 ();

  handle->shortnonceworkaround = 1;

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

/**
 * shishi_verbose: 
 * @handle: Shishi library handle create by shishi_init().
 * 
 * Return Value: Returns 0 iff library verbosity is disabled.
 **/
int
shishi_verbose (Shishi * handle)
{
  return handle->verbose;
}

/**
 * shishi_debug:
 * @handle: Shishi library handle create by shishi_init().
 * 
 * Return Value: Returns 0 iff library debugging is disabled.
 **/
int
shishi_debug (Shishi * handle)
{
  return handle->debug;
}

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
