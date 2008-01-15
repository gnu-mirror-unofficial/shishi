/* fileutil.c --- Utility functions used by file.c.
 * Copyright (C) 2002, 2003, 2004, 2007, 2008  Simon Josefsson
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Shishi; if not, see http://www.gnu.org/licenses or write
 * to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
 * Floor, Boston, MA 02110-1301, USA
 *
 */

#include "info.h"

/* For stat. */
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* For readdir. */
#include <dirent.h>

#include <errno.h>
#ifndef errno
extern int errno;
#endif

#include "areadlink.h"

/* Get specification. */
#include "fileutil.h"

#define ishex(c) ((c >= '0' || c <= '9') || (c >= 'a' || c <= 'f'))
#define tohex(c1,c2) (((c1 - '0' > 9 ? c1 - 'a' + 10 : c1 - '0') << 4) | \
		      (c2 - '0' > 9 ? c2 - 'a' + 10 : c2 - '0'))

static char *
unescape_filename (const char *path)
{
  char *out = strdup (path);
  char *p = out;

  while (*path)
    {
      if (path[0] == '%' &&
	  path[1] && ishex (path[1]) && path[2] && ishex (path[2]))
	{
	  *p++ = tohex (path[1], path[2]);
	  path += 3;
	}
      else
	*p++ = *path++;
    }
  *p = '\0';

  return out;
}

static char *
escape_filename (const char *path)
{
  char *out = malloc (strlen (path) * 3 + 1);
  char *p = out;

  while (*path)
    {
      if ((path[0] >= 'a' && path[0] <= 'z') ||
	  (path[0] >= 'A' && path[0] <= 'Z') ||
	  (path[0] >= '0' && path[0] <= '9') ||
	  path[0] == '-' || path[0] == '.')
	*p++ = *path++;
      else
	{
	  int i;
	  *p++ = '%';
	  i = (*path & 0xF0) >> 4;
	  *p++ = i > 10 ? 'a' + i - 10 : '0' + i;
	  i = (*path & 0x0f);
	  *p++ = i > 10 ? 'a' + i - 10 : '0' + i;
	  path++;
	}
    }
  *p = '\0';

  return out;
}

int
_shisa_isdir (const char *path)
{
  struct stat buf;
  int rc;

  rc = stat (path, &buf);
  if (rc != 0 || !S_ISDIR (buf.st_mode))
    return 0;

  return 1;
}

static int
isdir2 (const char *path1, const char *path2)
{
  char *tmp;
  int rc;

  asprintf (&tmp, "%s/%s", path1, path2);

  rc = _shisa_isdir (tmp);

  free (tmp);

  return rc;
}


int
_shisa_isdir2 (const char *path1, const char *realm)
{
  char *saferealm = escape_filename (realm);
  char *tmp;
  int rc;

  asprintf (&tmp, "%s/%s", path1, saferealm);
  free (saferealm);

  rc = _shisa_isdir (tmp);

  free (tmp);

  return rc;
}

int
_shisa_isdir3 (const char *path1, const char *realm, const char *principal)
{
  char *saferealm = escape_filename (realm);
  char *safeprincipal = escape_filename (principal);
  char *tmp;
  int rc;

  asprintf (&tmp, "%s/%s/%s", path1, saferealm, safeprincipal);
  free (saferealm);
  free (safeprincipal);

  rc = _shisa_isdir (tmp);

  free (tmp);

  return rc;
}

int
_shisa_isdir4 (const char *path1, const char *realm,
	       const char *principal, const char *path4)
{
  char *saferealm = escape_filename (realm);
  char *safeprincipal = escape_filename (principal);
  char *tmp;
  int rc;

  asprintf (&tmp, "%s/%s/%s/%s", path1, saferealm, safeprincipal, path4);
  free (saferealm);
  free (safeprincipal);

  rc = _shisa_isdir (tmp);

  free (tmp);

  return rc;
}

int
_shisa_mkdir (const char *file)
{
  int rc;

  rc = mkdir (file, S_IRUSR | S_IWUSR | S_IXUSR);
  if (rc != 0)
    {
      perror (file);
      return -1;
    }

  return 0;
}

int
_shisa_mkdir2 (const char *path1, const char *realm)
{
  char *saferealm = escape_filename (realm);
  char *tmp;
  int rc;

  asprintf (&tmp, "%s/%s", path1, saferealm);
  free (saferealm);

  rc = _shisa_mkdir (tmp);

  free (tmp);

  return rc;
}

int
_shisa_mkdir3 (const char *path1, const char *realm, const char *principal)
{
  char *saferealm = escape_filename (realm);
  char *safeprincipal = escape_filename (principal);
  char *tmp;
  int rc;

  asprintf (&tmp, "%s/%s/%s", path1, saferealm, safeprincipal);
  free (saferealm);
  free (safeprincipal);

  rc = _shisa_mkdir (tmp);

  free (tmp);

  return rc;
}

int
_shisa_mkdir4 (const char *path1, const char *realm,
	       const char *principal, const char *path4)
{
  char *saferealm = escape_filename (realm);
  char *safeprincipal = escape_filename (principal);
  char *tmp;
  int rc;

  asprintf (&tmp, "%s/%s/%s/%s", path1, saferealm, safeprincipal, path4);
  free (saferealm);
  free (safeprincipal);

  rc = _shisa_mkdir (tmp);

  free (tmp);

  return rc;
}

int
_shisa_rmdir (const char *file)
{
  int rc;

  rc = rmdir (file);
  if (rc != 0)
    {
      perror (file);
      return -1;
    }

  return 0;
}

int
_shisa_rmdir2 (const char *path1, const char *realm)
{
  char *saferealm = escape_filename (realm);
  char *tmp;
  int rc;

  asprintf (&tmp, "%s/%s", path1, saferealm);
  free (saferealm);

  rc = _shisa_rmdir (tmp);

  free (tmp);

  return rc;
}

int
_shisa_rmdir3 (const char *path1, const char *realm, const char *principal)
{
  char *saferealm = escape_filename (realm);
  char *safeprincipal = escape_filename (principal);
  char *tmp;
  int rc;

  asprintf (&tmp, "%s/%s/%s", path1, saferealm, safeprincipal);
  free (saferealm);
  free (safeprincipal);

  rc = _shisa_rmdir (tmp);

  free (tmp);

  return rc;
}

int
_shisa_rmdir4 (const char *path1, const char *realm,
	       const char *principal, const char *path4)
{
  char *saferealm = escape_filename (realm);
  char *safeprincipal = escape_filename (principal);
  char *tmp;
  int rc;

  asprintf (&tmp, "%s/%s/%s/%s", path1, saferealm, safeprincipal, path4);
  free (saferealm);
  free (safeprincipal);

  rc = _shisa_rmdir (tmp);

  free (tmp);

  return rc;
}

static time_t
mtime (const char *file)
{
  struct stat buf;
  int rc;

  rc = stat (file, &buf);
  if (rc != 0 || !S_ISREG (buf.st_mode))
    return (time_t) - 1;

  return buf.st_atime;
}

int
_shisa_mtime4 (const char *path1,
	       const char *realm, const char *principal, const char *path4)
{
  char *saferealm = escape_filename (realm);
  char *safeprincipal = escape_filename (principal);
  char *tmp;
  int rc;

  asprintf (&tmp, "%s/%s/%s/%s", path1, saferealm, safeprincipal, path4);
  free (saferealm);
  free (safeprincipal);

  rc = mtime (tmp);

  free (tmp);

  return rc;
}

static int
isfile (const char *path)
{
  struct stat buf;
  int rc;

  rc = stat (path, &buf);
  if (rc != 0 || !S_ISREG (buf.st_mode))
    return 0;

  return 1;
}

int
_shisa_isfile4 (const char *path1,
		const char *realm, const char *principal, const char *path4)
{
  char *saferealm = escape_filename (realm);
  char *safeprincipal = escape_filename (principal);
  char *tmp;
  int rc;

  asprintf (&tmp, "%s/%s/%s/%s", path1, saferealm, safeprincipal, path4);
  free (saferealm);
  free (safeprincipal);

  rc = isfile (tmp);

  free (tmp);

  return rc;
}

static uint32_t
uint32link (const char *file)
{
  char *linkname;
  long n;

  linkname = areadlink (file);
  if (linkname == NULL)
    return 0;

  n = atol (linkname);

  free (linkname);

  return n;
}

int
_shisa_uint32link4 (const char *path1,
		    const char *realm,
		    const char *principal, const char *path4)
{
  char *saferealm = escape_filename (realm);
  char *safeprincipal = escape_filename (principal);
  char *tmp;
  int rc;

  asprintf (&tmp, "%s/%s/%s/%s", path1, saferealm, safeprincipal, path4);
  free (saferealm);
  free (safeprincipal);

  rc = uint32link (tmp);

  free (tmp);

  return rc;
}

static int
ls_1 (const char *path, int onlydir, char ***files, size_t * nfiles,
      DIR * dir)
{
  struct dirent *de;

  while (errno = 0, (de = readdir (dir)) != NULL)
    {
      if (strcmp (de->d_name, ".") == 0 || strcmp (de->d_name, "..") == 0)
	continue;
      if (!onlydir || isdir2 (path, de->d_name))
	{
	  if (files)
	    {
	      *files = xrealloc (*files, (*nfiles + 1) * sizeof (**files));
	      (*files)[(*nfiles)] = unescape_filename (de->d_name);
	    }
	  (*nfiles)++;
	}
    }

  if (errno != 0)
    {
      size_t i;

      perror (path);

      if (files)
	{
	  for (i = 0; i < *nfiles; i++)
	    free (**files);
	  if (*nfiles > 0)
	    free (*files);
	}

      return -1;
    }

  return 0;
}

static int
ls (const char *path, int onlydir, char ***files, size_t * nfiles)
{
  DIR *dir;
  int rc;

  dir = opendir (path);
  if (dir == NULL)
    {
      perror (path);
      return -1;
    }

  if (ls_1 (path, onlydir, files, nfiles, dir) != 0)
    {
      rc = closedir (dir);
      if (rc != 0)
	perror (path);
      return -1;
    }

  rc = closedir (dir);
  if (rc != 0)
    {
      size_t i;

      perror (path);

      if (files)
	{
	  for (i = 0; i < *nfiles; i++)
	    free (**files);
	  if (*nfiles > 0)
	    free (*files);
	}

      return -1;
    }

  return 0;
}

int
_shisa_ls (const char *path, char ***files, size_t * nfiles)
{
  return ls (path, 0, files, nfiles);
}

int
_shisa_ls2 (const char *path, const char *realm,
	    char ***files, size_t * nfiles)
{
  char *saferealm = escape_filename (realm);
  char *tmp;
  int rc;

  asprintf (&tmp, "%s/%s", path, saferealm);
  free (saferealm);

  rc = _shisa_ls (tmp, files, nfiles);

  free (tmp);

  return rc;
}

int
_shisa_ls3 (const char *path, const char *realm,
	    const char *principal, char ***files, size_t * nfiles)
{
  char *saferealm = escape_filename (realm);
  char *safeprincipal = escape_filename (principal);
  char *tmp;
  int rc;

  asprintf (&tmp, "%s/%s/%s", path, saferealm, safeprincipal);
  free (saferealm);
  free (safeprincipal);

  rc = _shisa_ls (tmp, files, nfiles);

  free (tmp);

  return rc;
}

int
_shisa_ls4 (const char *path, const char *realm,
	    const char *principal, const char *path4,
	    char ***files, size_t * nfiles)
{
  char *saferealm = escape_filename (realm);
  char *safeprincipal = escape_filename (principal);
  char *tmp;
  int rc;

  asprintf (&tmp, "%s/%s/%s/%s", path, saferealm, safeprincipal, path4);
  free (saferealm);
  free (safeprincipal);

  rc = _shisa_ls (tmp, files, nfiles);

  free (tmp);

  return rc;
}

int
_shisa_lsdir (const char *path, char ***files, size_t * nfiles)
{
  return ls (path, 1, files, nfiles);
}

int
_shisa_lsdir2 (const char *path, const char *realm,
	       char ***files, size_t * nfiles)
{
  char *saferealm = escape_filename (realm);
  char *tmp;
  int rc;

  asprintf (&tmp, "%s/%s", path, saferealm);
  free (saferealm);

  rc = _shisa_lsdir (tmp, files, nfiles);

  free (tmp);

  return rc;
}

static int
rm (const char *path)
{
  int rc;

  rc = unlink (path);
  if (rc != 0)
    {
      perror (path);
      return -1;
    }

  return 0;
}

int
_shisa_rm4 (const char *path1, const char *realm,
	    const char *principal, const char *path4)
{
  char *saferealm = escape_filename (realm);
  char *safeprincipal = escape_filename (principal);
  char *tmp;
  int rc;

  asprintf (&tmp, "%s/%s/%s/%s", path1, saferealm, safeprincipal, path4);
  free (saferealm);
  free (safeprincipal);

  rc = rm (tmp);

  free (tmp);

  return rc;
}

int
_shisa_rm5 (const char *path1, const char *realm, const char *principal,
	    const char *path4, const char *path5)
{
  char *saferealm = escape_filename (realm);
  char *safeprincipal = escape_filename (principal);
  char *tmp;
  int rc;

  asprintf (&tmp, "%s/%s/%s/%s/%s", path1, saferealm, safeprincipal,
	    path4, path5);
  free (saferealm);
  free (safeprincipal);

  rc = rm (tmp);

  free (tmp);

  return rc;
}

FILE *
_shisa_fopen4 (const char *path1, const char *realm,
	       const char *principal, const char *path4, const char *mode)
{
  char *saferealm = escape_filename (realm);
  char *safeprincipal = escape_filename (principal);
  char *tmp;
  FILE *fh;

  asprintf (&tmp, "%s/%s/%s/%s", path1, saferealm, safeprincipal, path4);
  free (saferealm);
  free (safeprincipal);

  fh = fopen (tmp, mode);

  free (tmp);

  return fh;
}
