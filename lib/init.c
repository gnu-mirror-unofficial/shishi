/* init.c	initialization functions
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
 * shishi:
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

  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);

  handle = (Shishi *) xmalloc (sizeof (*handle));
  memset ((void *) handle, 0, sizeof (*handle));

  if (shishi_crypto_init () != SHISHI_OK)
    {
      shishi_warn (handle, "Cannot initialize crypto library");
      return NULL;
    }

  handle->asn1 = _shishi_asn1_read ();
  if (handle->asn1 == NULL)
    {
      shishi_warn (handle, "%s", shishi_strerror (SHISHI_ASN1_ERROR));
      return NULL;
    }

  handle->kdctimeout = 5;
  handle->kdcretries = 3;

  handle->ticketlife = TICKETLIFE;
  handle->renewlife = RENEWLIFE;

  handle->nclientkdcetypes = 1;
  handle->clientkdcetypes = xmalloc (sizeof (*handle->clientkdcetypes) *
				     handle->nclientkdcetypes);
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

/**
 * shishi_done:
 * @handle: shishi handle as allocated by shishi_init().
 *
 * Deallocates the shishi library handle.  The handle must not be used
 * in any calls to shishi functions after this.  If there is a default
 * tkts, it is written to the default tkts file (call
 * shishi_tkts_default_file_set() to change the default tkts
 * file). If you do not wish to write the default tkts file,
 * close the default tkts with shishi_tkts_done(handle,
 * NULL) before calling this function.
 **/
void
shishi_done (Shishi * handle)
{
  if (handle->tkts)
    {
      shishi_tkts_to_file (handle->tkts, shishi_tkts_default_file (handle));

      shishi_tkts_done (&handle->tkts);
    }

  /*  if (handle->default_realm)
     free (handle->default_realm); */
  if (handle->usercfgfile)
    free (handle->usercfgfile);
  if (handle->tktsdefaultfile)
    free (handle->tktsdefaultfile);
  if (handle->hostkeysdefaultfile)
    free (handle->hostkeysdefaultfile);
  if (handle->clientkdcetypes)
    free (handle->clientkdcetypes);

  if (handle->asn1)
    shishi_asn1_done (handle, handle->asn1);

  free (handle);
}

static void
_shishi_maybe_install_usercfg (Shishi * handle)
{
  const char *usercfg = shishi_cfg_default_userfile (handle);
  const char *userdir = shishi_cfg_default_userdirectory (handle);
  struct stat buf;
  FILE *fh;
  FILE *src, *dst;
  int rc;
  int c;

  fh = fopen (usercfg, "r");
  if (fh)
    {
      fclose (fh);
      return;
    }

  rc = stat (userdir, &buf);
  if (rc == -1 && errno == ENOENT)
    {
      rc = mkdir (userdir, S_IRUSR | S_IWUSR | S_IXUSR);
      if (rc != 0)
	shishi_info (handle, "mkdir %s: %s", userdir, strerror (errno));
    }
  else if (rc != 0)
    shishi_info (handle, "stat %s: %s", userdir, strerror (errno));

  src = fopen (SKELCFGFILE, "r");
  if (!src)
    {
      shishi_info (handle, "open %s: %s", SKELCFGFILE, strerror (errno));
      return;
    }

  dst = fopen (usercfg, "w");
  if (!dst)
    {
      fclose (src);
      shishi_info (handle, "open %s: %s", usercfg, strerror (errno));
      return;
    }

  while ((c = getc (src)) != EOF)
    putc (c, dst);

  fclose (dst);
  fclose (src);

  shishi_info (handle, "created `%s'", usercfg);
}

static int
_shishi_init_read (Shishi * handle,
		   const char *tktsfile,
		   const char *systemcfgfile, const char *usercfgfile)
{
  int rc = SHISHI_OK;

  _shishi_maybe_install_usercfg (handle);

  if (!tktsfile)
    tktsfile = shishi_tkts_default_file (handle);

  if (!systemcfgfile)
    systemcfgfile = shishi_cfg_default_systemfile (handle);

  if (!usercfgfile)
    usercfgfile = shishi_cfg_default_userfile (handle);

  if (!handle->tkts)
    rc = shishi_tkts (handle, &handle->tkts);
  if (rc != SHISHI_OK)
    return rc;

  if (*tktsfile)
    rc = shishi_tkts_from_file (handle->tkts, tktsfile);
  if (rc == SHISHI_FOPEN_ERROR)
    shishi_warn (handle, "%s: %s", tktsfile, strerror (errno));
  if (rc != SHISHI_OK && rc != SHISHI_FOPEN_ERROR)
    return rc;

  if (*systemcfgfile)
    rc = shishi_cfg_from_file (handle, systemcfgfile);
  if (rc == SHISHI_FOPEN_ERROR)
    shishi_warn (handle, "%s: %s", systemcfgfile, strerror (errno));
  if (rc != SHISHI_OK && rc != SHISHI_FOPEN_ERROR)
    return rc;

  if (*usercfgfile)
    rc = shishi_cfg_from_file (handle, usercfgfile);
  if (rc == SHISHI_FOPEN_ERROR)
    shishi_warn (handle, "%s: %s", usercfgfile, strerror (errno));
  if (rc != SHISHI_OK && rc != SHISHI_FOPEN_ERROR)
    return rc;

  if (VERBOSENOICE (handle))
    shishi_cfg_print (handle, stderr);

  return SHISHI_OK;
}

/**
 * shishi_init:
 * @handle: pointer to handle to be created.
 *
 * Create a Shishi library handle and read the system configuration
 * file, user configuration file and user tickets from the default
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

  return _shishi_init_read (*handle, shishi_tkts_default_file (*handle),
			    shishi_cfg_default_systemfile (*handle),
			    shishi_cfg_default_userfile (*handle));
}

/**
 * shishi_init_with_paths:
 * @handle: pointer to handle to be created.
 * @tktsfile: Filename of ticket file, or NULL.
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
			const char *tktsfile,
			const char *systemcfgfile, const char *usercfgfile)
{
  if (!handle || !(*handle = shishi ()))
    return SHISHI_HANDLE_ERROR;

  shishi_tkts_default_file_set (*handle, tktsfile);

  return _shishi_init_read (*handle, tktsfile, systemcfgfile, usercfgfile);
}

/**
 * shishi_init_server:
 * @handle: pointer to handle to be created.
 *
 * Like shishi_init() but only read the system configuration file.
 * Like shishi_init(), the handle is allocated regardless of return
 * values, except for SHISHI_HANDLE_ERROR which indicates a problem
 * allocating the handle.  (The other error conditions comes from
 * reading the configuration file.)
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_init_server (Shishi ** handle)
{
  int rc;

  if (!handle || !(*handle = shishi ()))
    return SHISHI_HANDLE_ERROR;

  rc =
    shishi_cfg_from_file (*handle, shishi_cfg_default_systemfile (*handle));
  if (rc == SHISHI_FOPEN_ERROR)
    shishi_warn (*handle, "%s: %s", shishi_cfg_default_systemfile (*handle),
		 strerror (errno));
  if (rc != SHISHI_OK && rc != SHISHI_FOPEN_ERROR)
    return rc;

  return SHISHI_OK;
}

/**
 * shishi_init_server_with_paths:
 * @handle: pointer to handle to be created.
 * @systemcfgfile: Filename of system configuration, or NULL.
 *
 * Like shishi_init() but only read the system configuration file from
 * specified location.  Like shishi_init(), the handle is allocated
 * regardless of return values, except for SHISHI_HANDLE_ERROR which
 * indicates a problem allocating the handle.  (The other error
 * conditions comes from reading the configuration file.)
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_init_server_with_paths (Shishi ** handle, const char *systemcfgfile)
{
  int rc;

  if (!handle || !(*handle = shishi ()))
    return SHISHI_HANDLE_ERROR;

  if (!systemcfgfile)
    systemcfgfile = shishi_cfg_default_systemfile (*handle);

  rc = shishi_cfg_from_file (*handle, systemcfgfile);
  if (rc == SHISHI_FOPEN_ERROR)
    shishi_warn (*handle, "%s: %s", systemcfgfile, strerror (errno));
  if (rc != SHISHI_OK && rc != SHISHI_FOPEN_ERROR)
    return rc;

  return SHISHI_OK;
}
