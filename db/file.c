/* file.c --- File based Kerberos database.
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

/*
 * Theory of operation:
 *
 * Data is stored in the standard file system, so it is subject to
 * normal access permission infrastructure, e.g. POSIX ACL or normal
 * Unix file permissions.  A definition of the file database looks
 * like:
 *
 * file LOCATION OPTIONS
 *
 * Where LOCATION is a path name, e.g. /var/shisa.  No OPTIONS are
 * currently implemented.
 *
 * Realms are directories in LOCATION.  Principals are directories in
 * realm directories.  Characters outside A-Za-z0-9_- are escaped
 * using the URL encoding, e.g. example/host%2fwww denote the
 * "host/www" principal in the "example" realm.
 *
 * Example file tree:
 *
 * LOCATION/EXAMPLE.ORG
 * LOCATION/EXAMPLE.ORG/krbtgt%2fEXAMPLE.ORG
 * LOCATION/EXAMPLE.ORG/host%2fkerberos.example.org
 * LOCATION/EXAMPLE.NET
 * LOCATION/EXAMPLE.NET/krbtgt%2fEXAMPLE.NET
 *
 */

/* XXX fix race conditions. */

#include "internal.h"

/* Get ssize_t. */
#if HAVE_UNISTD_H
# include <unistd.h>
#endif

#include "fileutil.h"

struct Shisa_file
{
  char *path;
  int readonly;
  int allowcreate;
};
typedef struct Shisa_file Shisa_file;

enum
  {
    READ_ONLY_OPTION = 0,
    ALLOW_CREATE_OPTION = 1,
    THE_END
  };

static char *const _shisa_file_opts[] = {
  /* [READ_ONLY_OPTION] =        */ "read-only",
  /* [ALLOW_CREATE_OPTION] =     */ "allow-create",
  /* [THE_END] =                 */ NULL
};

int
shisa_file_cfg (Shisa *dbh,
		Shisa_file *info,
		const char *option)
{
  char *opt = option ? xstrdup (option) : NULL;
  char *p = opt;
  char *value;
  int rc;

  while (p != NULL && *p != '\0')
    {
      switch (getsubopt (&p, _shisa_file_opts, &value))
	{
	case READ_ONLY_OPTION:
	  info->readonly = 1;
	  break;

	case ALLOW_CREATE_OPTION:
	  info->allowcreate = 1;
	  break;

	default:
	  shisa_info (dbh, "Unknown file database option: `%s'.", value);
	  return SHISA_CFG_SYNTAX_ERROR;
	  break;
	}
    }

  if (opt)
    free (opt);

  return SHISA_OK;
}

int
shisa_file_init (Shisa *dbh,
		 const char *location,
		 const char *options,
		 void **state)
{
  Shisa_file *info;
  int rc;

  if (!_shisa_isdir (location))
    return SHISA_OPEN_ERROR;

  *state = info = xcalloc (1, sizeof (*info));

  rc = shisa_file_cfg (dbh, info, options);
  if (rc != SHISA_OK)
    return rc;

  info->path = xstrdup (location);

  return SHISA_OK;
}

int
shisa_file_enumerate_realms (Shisa *dbh,
			     void *state,
			     char ***realms,
			     size_t *nrealms)
{
  Shisa_file *info = state;

  if (_shisa_lsdir (info->path, realms, nrealms) != 0)
    return SHISA_ENUMERATE_REALM_ERROR;

  return SHISA_OK;
}

int
shisa_file_enumerate_principals (Shisa *dbh,
				 void *state,
				 const char *realm,
				 char ***principals,
				 size_t *nprincipals)
{
  Shisa_file *info = state;

  if (!_shisa_isdir2 (info->path, realm))
    return SHISA_NO_REALM;

  if (_shisa_lsdir2 (info->path, realm, principals, nprincipals) != 0)
    return SHISA_ENUMERATE_PRINCIPAL_ERROR;

  return SHISA_OK;
}

int
shisa_file_principal_find (Shisa * dbh,
			   void *state,
			   const char *realm,
			   const char *principal,
			   Shisa_principal *ph)
{
  Shisa_file *info = state;

  if (!_shisa_isdir3 (info->path, realm, principal))
    return SHISA_NO_PRINCIPAL;

  ph->notusedbefore =
    _shisa_mtime4 (info->path, realm, principal, "validfrom.stamp");
  ph->isdisabled =
    _shisa_isfile4 (info->path, realm, principal, "disabled.flag");
  ph->kvno = _shisa_uint32link4 (info->path, realm, principal, "latest.key");
  ph->lastinitialtgt =
    _shisa_mtime4 (info->path, realm, principal, "lastinitaltgt.stamp");
  ph->lastinitialrequest =
    _shisa_mtime4 (info->path, realm, principal, "lastinitial.stamp");
  ph->lasttgt = _shisa_mtime4 (info->path, realm, principal, "lasttgt.stamp");
  ph->lastrenewal =
    _shisa_mtime4 (info->path, realm, principal, "lastrenewal.stamp");
  ph->passwordexpire =
    _shisa_mtime4 (info->path, realm, principal, "passwordexpire.stamp");
  ph->accountexpire =
    _shisa_mtime4 (info->path, realm, principal, "accountexpire.stamp");

  return SHISA_OK;
}

int
shisa_file_principal_update (Shisa * dbh,
			     void *state,
			     const char *realm,
			     const char *principal,
			     const Shisa_principal * ph)
{
  Shisa_file *info = state;

  return SHISA_OK;
}

static int
realm_add (Shisa * dbh, void *state, const char *realm)
{
  Shisa_file *info = state;

  if (_shisa_isdir2 (info->path, realm))
    return SHISA_ADD_REALM_EXISTS;

  if (_shisa_mkdir2 (info->path, realm) != 0)
    return SHISA_ADD_REALM_ERROR;

  return SHISA_OK;

}

static int
principal_add (Shisa * dbh,
	       void *state,
	       const char *realm,
	       const char *principal,
	       const Shisa_principal * ph,
	       const Shisa_key * key)
{
  Shisa_file *info = state;

  if (!_shisa_isdir2 (info->path, realm))
    return SHISA_NO_REALM;

  if (_shisa_isdir3 (info->path, realm, principal))
    return SHISA_ADD_PRINCIPAL_EXISTS;

  if (_shisa_mkdir3 (info->path, realm, principal) != 0)
    return SHISA_ADD_PRINCIPAL_ERROR;

  if (ph)
    shisa_file_principal_update (dbh, state, realm, principal, ph);

  if (key)
    shisa_file_key_add (dbh, state, realm, principal, ph->kvno, key);

  return SHISA_OK;
}

int
shisa_file_principal_add (Shisa * dbh,
			  void *state,
			  const char *realm,
			  const char *principal,
			  const Shisa_principal * ph,
			  const Shisa_key * key)
{
  int rc;

  if (principal == NULL)
    rc = realm_add (dbh, state, realm);
  else
    rc = principal_add (dbh, state, realm, principal, ph, key);

  return rc;
}

static int
realm_remove (Shisa * dbh, void *state, const char *realm)
{
  Shisa_file *info = state;
  size_t nprincipals = 0;
  int rc;

  if (!_shisa_isdir2 (info->path, realm))
    return SHISA_NO_REALM;

  rc = shisa_file_enumerate_principals (dbh, state, realm, NULL, &nprincipals);
  if (rc != SHISA_OK)
    return rc;

  if (nprincipals > 0)
    return SHISA_REMOVE_REALM_NONEMPTY;

  if (_shisa_rmdir2 (info->path, realm) != 0)
    return SHISA_REMOVE_REALM_ERROR;

  return SHISA_OK;
}

static int
remove_keys (Shisa * dbh,
	     void *state,
	     const char *realm,
	     const char *principal)
{
  Shisa_file *info = state;
  char **files;
  size_t nfiles;
  size_t i;
  int rc;

  files = NULL;
  nfiles = 0;

  rc = _shisa_ls4 (info->path, realm, principal, "keys", &files, &nfiles);
  if (rc != SHISA_OK)
    return rc;

  for (i = 0; i < nfiles; i++)
    {
      rc = _shisa_rm5 (info->path, realm, principal, "keys", files[i]);
      free (files[i]);
    }
  free (files);

  rc = _shisa_rmdir4 (info->path, realm, principal, "keys");
  if (rc != SHISA_OK)
    return rc;

  return SHISA_OK;
}

static int
remove_info (Shisa * dbh,
	     void *state,
	     const char *realm,
	     const char *principal)
{
  Shisa_file *info = state;
  char **files;
  size_t nfiles;
  size_t i;
  int rc;

  files = NULL;
  nfiles = 0;

  rc = _shisa_ls3 (info->path, realm, principal, &files, &nfiles);
  if (rc != SHISA_OK)
    return rc;

  for (i = 0; i < nfiles; i++)
    {
      rc = _shisa_rm4 (info->path, realm, principal, files[i]);
      free (files[i]);
    }
  free (files);

  return SHISA_OK;
}

static int
principal_remove (Shisa * dbh,
		  void *state,
		  const char *realm,
		  const char *principal)
{
  Shisa_file *info = state;
  size_t nprincipals = 0;
  int rc;

  if (!_shisa_isdir2 (info->path, realm))
    return SHISA_NO_REALM;

  if (!_shisa_isdir3 (info->path, realm, principal))
    return SHISA_NO_PRINCIPAL;

  rc = remove_keys (dbh, state, realm, principal);
  if (rc != SHISA_OK)
    return rc;

  if (_shisa_rmdir3 (info->path, realm, principal) != 0)
    return SHISA_REMOVE_PRINCIPAL_ERROR;

  return SHISA_OK;
}

int
shisa_file_principal_remove (Shisa * dbh,
			     void *state,
			     const char *realm,
			     const char *principal)
{
  int rc;

  if (principal == NULL)
    rc = realm_remove (dbh, state, realm);
  else
    rc = principal_remove (dbh, state, realm, principal);

  return rc;
}

int
read_key (Shisa * dbh,
	  Shisa_file *info,
	  const char *realm,
	  const char *principal,
	  const char *keyfile,
	  Shisa_key **key)
{
  Shisa_key tmpkey;
  FILE *fh;
  char *file;
  char *line;
  size_t linelen;
  unsigned passwdlen;
  ssize_t len;
  int rc;

  asprintf (&file, "keys/%s", keyfile);
  fh = _shisa_fopen4 (info->path, realm, principal, file, "r");
  free (file);
  if (!fh)
    return SHISA_NO_KEY;

  memset (&tmpkey, 0, sizeof (tmpkey));

  if (fscanf (fh, "%u %u %u %u %u\n", &tmpkey.etype, &tmpkey.keylen,
	      &tmpkey.saltlen, &tmpkey.str2keyparamlen, &passwdlen) != 5)
    return SHISA_NO_KEY;

  if (tmpkey.keylen > 0)
    {
      tmpkey.key = xmalloc (tmpkey.keylen + 1);
      if (fread (tmpkey.key, 1, tmpkey.keylen, fh) != tmpkey.keylen)
	return SHISA_NO_KEY;
      tmpkey.key[tmpkey.keylen] = '\0';
    }

  if (tmpkey.saltlen > 0)
    {
      tmpkey.salt = xmalloc (tmpkey.saltlen + 1);
      if (fread (tmpkey.salt, 1, tmpkey.saltlen, fh) != tmpkey.saltlen)
	return SHISA_NO_KEY;
      tmpkey.salt[tmpkey.saltlen] = '\0';
    }

  if (tmpkey.str2keyparamlen > 0)
    {
      tmpkey.str2keyparam = xmalloc (tmpkey.str2keyparamlen + 1);
      if (fread (tmpkey.str2keyparam, 1, tmpkey.str2keyparamlen, fh) !=
	  tmpkey.str2keyparamlen)
	return SHISA_NO_KEY;
      tmpkey.str2keyparam[tmpkey.str2keyparamlen] = '\0';
    }

  if (passwdlen > 0)
    {
      tmpkey.password = xmalloc (passwdlen + 1);
      if (fread (tmpkey.password, 1, passwdlen, fh) != passwdlen)
	return SHISA_NO_KEY;
      tmpkey.password[passwdlen] = '\0';
    }

  rc = fclose (fh);
  if (rc != 0)
    {
      perror(keyfile);
      return SHISA_NO_KEY;
    }

  *key = xmalloc (sizeof (**key));
  memcpy (*key, &tmpkey, sizeof (tmpkey));

  return SHISA_OK;
}

int
shisa_file_enumerate_keys (Shisa * dbh,
			   void *state,
			   const char *realm,
			   const char *principal,
			   Shisa_key ***keys,
			   size_t *nkeys)
{
  Shisa_file *info = state;
  char **files;
  size_t nfiles;
  size_t i;
  int rc;

  files = NULL;
  nfiles = 0;

  rc = _shisa_ls4 (info->path, realm, principal, "keys", &files, &nfiles);
  if (rc != SHISA_OK)
    return rc;

  *nkeys = nfiles;
  if (keys)
    *keys = xmalloc (nfiles * sizeof (**keys));
  for (i = 0; i < nfiles; i++)
    {
      if (keys && rc == SHISA_OK)
	{
	  rc = read_key (dbh, info, realm, principal, files[i], &(*keys)[i]);
	  if (rc != SHISA_OK)
	    /* XXX mem leak. */
	    (*keys)[i] = NULL;
	}
      free (files[i]);
    }
  free (files);

  return SHISA_OK;
}

int
shisa_file_key_add (Shisa * dbh,
		    void *state,
		    const char *realm,
		    const char *principal,
		    uint32_t kvno,
		    const Shisa_key * key)
{
  Shisa_file *info = state;
  size_t passwdlen = key && key->password ? strlen(key->password) : 0;
  char *file;
  FILE *fh;

  if (!key)
    return SHISA_NO_KEY;

  if (!_shisa_isdir4 (info->path, realm, principal, "keys") &&
      _shisa_mkdir4 (info->path, realm, principal, "keys"))
    return SHISA_NO_KEY;

  asprintf (&file, "keys/%d.key", kvno);
  fh = _shisa_fopen4 (info->path, realm, principal, file, "w");
  free (file);
  if (!fh)
    {
      perror (file);
      return SHISA_NO_KEY;
    }

  fprintf (fh, "%u %u %u %u %u\n", key->etype, key->keylen,
	   key->saltlen, key->str2keyparamlen, passwdlen);
  if (key->keylen > 0)
    fwrite (key->key, 1, key->keylen, fh);
  if (key->saltlen > 0)
    fwrite (key->salt, 1, key->saltlen, fh);
  if (key->str2keyparamlen > 0)
    fwrite (key->str2keyparam, 1, key->str2keyparamlen, fh);
  if (passwdlen > 0)
    fwrite (key->password, 1, passwdlen, fh);

  fclose (fh);

  return SHISA_OK;
}

void
shisa_file_done (Shisa *dbh, void *state)
{
  Shisa_file *info = state;

  if (info)
    {
      if (info->path)
	free (info->path);
      free (info);
    }
}
