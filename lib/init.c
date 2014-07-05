/* init.c --- Initialization functions.
 * Copyright (C) 2002-2013 Simon Josefsson
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

/* Get gl_sockets_startup. */
#include "sockets.h"

/* Get _shishi_tls_init. */
#include "starttls.h"

/* Get _shishi_crypto_init. */
#include "low-crypto.h"

/* Get _shishi_asn1_init. */
#include "asn1.h"

static Shishi *
init_handle (int outputtype)
{
  Shishi *handle;
  int rc;

  handle = xcalloc (1, sizeof (*handle));

  shishi_error_set_outputtype (handle, outputtype);

  if (!shishi_check_version (SHISHI_VERSION))
    {
      shishi_warn (handle, "Library and header version missmatch (%s vs %s).",
		   shishi_check_version (NULL), SHISHI_VERSION);
      free (handle);
      return NULL;
    }

  rc = gl_sockets_startup (SOCKETS_2_1);
  if (rc)
    {
      shishi_warn (handle, "Failed to initialized Windows sockets (%d)", rc);
      free (handle);
      return NULL;
    }

  rc = _shishi_crypto_init (handle);
  if (rc != SHISHI_OK)
    {
      shishi_warn (handle, "Cannot initialize crypto library");
      free (handle);
      return NULL;
    }

#ifdef USE_STARTTLS
  rc = _shishi_tls_init (handle);
  if (rc != SHISHI_OK)
    {
      shishi_warn (handle, "Cannot initialize TLS library");
      free (handle);
      return NULL;
    }
#endif

  rc = _shishi_asn1_init (handle);
  if (rc != SHISHI_OK)
    {
      shishi_warn (handle, "%s", shishi_strerror (SHISHI_ASN1_ERROR));
      free (handle);
      return NULL;
    }

  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);

  handle->kdctimeout = 5;
  handle->kdcretries = 3;

  handle->ticketlife = TICKETLIFE;
  handle->renewlife = RENEWLIFE;

  handle->nclientkdcetypes = 1;
  handle->clientkdcetypes = xmalloc (sizeof (*handle->clientkdcetypes) *
				     handle->nclientkdcetypes);
  handle->clientkdcetypes[0] = SHISHI_AES256_CTS_HMAC_SHA1_96;

  handle->nauthorizationtypes = 1;
  handle->authorizationtypes = xmalloc (sizeof (*handle->authorizationtypes) *
					handle->nauthorizationtypes);
  handle->authorizationtypes[0] = SHISHI_AUTHORIZATION_BASIC;

  return handle;
}

/**
 * shishi:
 *
 * Initializes the Shishi library, and primes logging so that future
 * warnings and informational messages are printed on %stderr.
 * If this function fails, it may send its own diagnostic errors
 * to %stderr.
 *
 * Return value: Returns a Shishi library handle, or %NULL on error.
 **/
Shishi *
shishi (void)
{
  return init_handle (SHISHI_OUTPUTTYPE_STDERR);
}

/**
 * shishi_server:
 *
 * Initializes the Shishi library, and primes logging so that future
 * warnings and informational messages are sent to the syslog system.
 * If this function fails, it may print diagnostic errors in the syslog.
 *
 * Return value: Returns a Shishi library handle, or %NULL on error.
 **/
Shishi *
shishi_server (void)
{
  return init_handle (SHISHI_OUTPUTTYPE_SYSLOG);
}

/**
 * shishi_done:
 * @handle: Shishi handle as allocated by shishi_init().
 *
 * Deallocates the Shishi library handle.  The handle must not be used
 * in any call to a shishi function after an execution of shishi_done().
 *
 * If there is a default #tkts, it is written to the default tkts file.
 * If you do not wish to write the default tkts file, close the
 * default file before calling this function.  It is closed with a
 * simple #shishi_tkts_done(@handle, %NULL).  For related information,
 * see shishi_tkts_default_file_set().
 **/
void
shishi_done (Shishi * handle)
{
  int rc;

  if (handle->tkts)
    {
      shishi_tkts_to_file (handle->tkts, shishi_tkts_default_file (handle));
      shishi_tkts_done (&handle->tkts);
    }

  shishi_principal_default_set (handle, NULL);
  shishi_tkts_default_file_set (handle, NULL);

#ifdef USE_STARTTLS
  rc = _shishi_tls_done (handle);
  if (rc != SHISHI_OK)
    shishi_warn (handle, "Cannot deinitialize TLS library");
#endif

  if (handle->realminfos)
    {
      size_t i, j;

      for (i = 0; i < handle->nrealminfos; i++)
	{
	  /* XXX free each address */

	  free (handle->realminfos[i].kdcaddresses);
	  free (handle->realminfos[i].name);

	  for (j = 0; j < handle->realminfos[i].nserverwildcards; j++)
	    free (handle->realminfos[i].serverwildcards[j]);
	}
    }

  free (handle->default_realm);
  free (handle->usercfgfile);
  free (handle->hostkeysdefaultfile);
  free (handle->clientkdcetypes);
  free (handle->authorizationtypes);
  free (handle->stringprocess);
  free (handle->userdirectory);

  if (handle->asn1)
    shishi_asn1_done (handle, handle->asn1);

  free (handle);
}

static void
maybe_install_usercfg (Shishi * handle)
{
  const char *usercfg = shishi_cfg_default_userfile (handle);
  const char *userdir = shishi_cfg_default_userdirectory (handle);
  struct stat buf;
  FILE *fh;
  FILE *src, *dst;
  int rc;
  int c;

  /* Don't create anything if non-standard home is used. */
  if (getenv ("SHISHI_HOME"))
    return;

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
	shishi_warn (handle, "`%s': %s", userdir, strerror (errno));
    }
  else if (rc != 0)
    shishi_warn (handle, "`%s': %s", userdir, strerror (errno));

  src = fopen (SKELCFGFILE, "r");
  if (!src)
    {
      shishi_warn (handle, "`%s': %s", SKELCFGFILE, strerror (errno));
      return;
    }

  dst = fopen (usercfg, "w");
  if (!dst)
    {
      fclose (src);
      shishi_warn (handle, "`%s': %s", usercfg, strerror (errno));
      return;
    }

  while ((c = getc (src)) != EOF)
    putc (c, dst);

  fclose (dst);
  fclose (src);

  shishi_info (handle, "created `%s'", usercfg);
}

static int
init_read (Shishi * handle,
	   const char *tktsfile,
	   const char *systemcfgfile, const char *usercfgfile)
{
  int rc = SHISHI_OK;

  /* XXX Is this the correct place for this? */
  maybe_install_usercfg (handle);

  if (!systemcfgfile)
    systemcfgfile = shishi_cfg_default_systemfile (handle);

  if (*systemcfgfile)
    rc = shishi_cfg_from_file (handle, systemcfgfile);
  if (rc == SHISHI_FOPEN_ERROR)
    shishi_warn (handle, "%s: %s", systemcfgfile, strerror (errno));
  if (rc != SHISHI_OK && rc != SHISHI_FOPEN_ERROR)
    return rc;

  if (!usercfgfile)
    usercfgfile = shishi_cfg_default_userfile (handle);

  if (*usercfgfile)
    rc = shishi_cfg_from_file (handle, usercfgfile);
  if (rc == SHISHI_FOPEN_ERROR)
    shishi_warn (handle, "%s: %s", usercfgfile, strerror (errno));
  if (rc != SHISHI_OK && rc != SHISHI_FOPEN_ERROR)
    return rc;

  if (!tktsfile)
    tktsfile = shishi_tkts_default_file (handle);

  if (!handle->tkts)
    rc = shishi_tkts (handle, &handle->tkts);
  if (rc != SHISHI_OK)
    return rc;

  if (*tktsfile)
    rc = shishi_tkts_from_file (handle->tkts, tktsfile);
  if (rc == SHISHI_FOPEN_ERROR)
    shishi_verbose (handle, "%s: %s", tktsfile, strerror (errno));
  if (rc != SHISHI_OK && rc != SHISHI_FOPEN_ERROR)
    return rc;

  if (VERBOSENOISE (handle))
    shishi_cfg_print (handle, stderr);

  return SHISHI_OK;
}

/**
 * shishi_init:
 * @handle: Pointer to a Shishi handle created by this call.
 *
 * Creates a Shishi library handle, using shishi(), and reads the system
 * configuration file, user configuration file and user tickets from
 * their default locations.  The paths to the system configuration
 * file is decided at compile time, and is $sysconfdir/shishi.conf.
 * The user configuration file is $HOME/.shishi/config, and the user
 * ticket file is $HOME/.shishi/ticket.
 *
 * The handle is allocated regardless of return value.  The single
 * exception being %SHISHI_HANDLE_ERROR, which indicates a problem
 * in allocating the handle.  Other error conditions could arise
 * while reading files.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_init (Shishi ** handle)
{
  if (!handle || !(*handle = shishi ()))
    return SHISHI_HANDLE_ERROR;

  return init_read (*handle, shishi_tkts_default_file (*handle),
		    shishi_cfg_default_systemfile (*handle),
		    shishi_cfg_default_userfile (*handle));
}

/**
 * shishi_init_with_paths:
 * @handle: Pointer to a Shishi handle created by this call .
 * @tktsfile: Filename of ticket file, or %NULL.
 * @systemcfgfile: Filename of system configuration, or %NULL.
 * @usercfgfile: Filename of user configuration, or %NULL.
 *
 * Creates a Shishi library handle, using shishi(), and reads the system
 * configuration file, user configuration file, and user tickets at
 * the specified locations.  If any of @usercfgfile or @systemcfgfile
 * is %NULL, the file is read from its default location, which for
 * the system configuration is decided at compile time, and is
 * $sysconfdir/shishi.conf, and for the user configuration it is
 * $HOME/.shishi/config.  If the ticket file name is %NULL, a ticket
 * file is not read at all.
 *
 * The handle is allocated regardless of return value.  The single
 * exception being %SHISHI_HANDLE_ERROR, which indicates a problem
 * in allocating the handle.  Other error conditions could arise
 * while reading files.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_init_with_paths (Shishi ** handle,
			const char *tktsfile,
			const char *systemcfgfile, const char *usercfgfile)
{
  if (!handle || !(*handle = shishi ()))
    return SHISHI_HANDLE_ERROR;

  shishi_tkts_default_file_set (*handle, tktsfile);

  return init_read (*handle, tktsfile, systemcfgfile, usercfgfile);
}

/**
 * shishi_init_server:
 * @handle: Pointer to a Shishi handle created by this call .
 *
 * Creates a Shishi library handle, using shishi_server(), and reads
 * the system configuration file.  The path to the system configuration
 * file is decided at compile time, and is $sysconfdir/shishi.conf.
 *
 * The handle is allocated regardless of return value.  The single
 * exception being %SHISHI_HANDLE_ERROR, which indicates a problem
 * in allocating the handle.  Other error conditions could arise
 * while reading the file.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_init_server (Shishi ** handle)
{
  int rc;

  if (!handle || !(*handle = shishi_server ()))
    return SHISHI_HANDLE_ERROR;

  rc = shishi_cfg_from_file (*handle,
			     shishi_cfg_default_systemfile (*handle));
  if (rc == SHISHI_FOPEN_ERROR)
    shishi_warn (*handle, "%s: %s", shishi_cfg_default_systemfile (*handle),
		 strerror (errno));
  if (rc != SHISHI_OK && rc != SHISHI_FOPEN_ERROR)
    return rc;

  return SHISHI_OK;
}

/**
 * shishi_init_server_with_paths:
 * @handle: Pointer to a Shishi handle created by this call .
 * @systemcfgfile: Filename of system configuration, or %NULL.
 *
 * Creates a Shishi library handle, using shishi_server(), and reads
 * the system configuration file from the specified location.  The path
 * to the system configuration file is decided at compile time, and is
 * $sysconfdir/shishi.conf.
 *
 * The handle is allocated regardless of return value.  The single
 * exception being %SHISHI_HANDLE_ERROR, which indicates a problem
 * in allocating the handle.  Other error conditions could arise
 * while reading the file.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_init_server_with_paths (Shishi ** handle, const char *systemcfgfile)
{
  int rc;

  if (!handle || !(*handle = shishi_server ()))
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
