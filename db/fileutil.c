/* fileutil.c --- Utility functions used by file.c.
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

#include "xreadlink.h"

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

int
_shisa_isdir2 (const char *path1, const char *path2)
{
  char *tmp;
  int rc;

  asprintf (&tmp, "%s/%s", path1, path2);

  rc = _shisa_isdir (tmp);

  free (tmp);

  return rc;
}

int
_shisa_isdir3 (const char *path1, const char *path2, const char *path3)
{
  char *tmp;
  int rc;

  asprintf (&tmp, "%s/%s/%s", path1, path2, path3);

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
_shisa_mkdir2 (const char *path1, const char *path2)
{
  char *tmp;
  int rc;

  asprintf (&tmp, "%s/%s", path1, path2);

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
_shisa_rmdir2 (const char *path1, const char *path2)
{
  char *tmp;
  int rc;

  asprintf (&tmp, "%s/%s", path1, path2);

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
  if (rc != 0 || !S_ISREG(buf.st_mode))
    return (time_t) -1;

  return buf.st_atime;
}

int
_shisa_mtime4 (const char *path1,
	       const char *path2,
	       const char *path3,
	       const char *path4)
{
  char *tmp;
  int rc;

  asprintf (&tmp, "%s/%s/%s/%s", path1, path2, path3, path4);

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
		const char *path2,
		const char *path3,
		const char *path4)
{
  char *tmp;
  int rc;

  asprintf (&tmp, "%s/%s/%s/%s", path1, path2, path3, path4);

  rc = isfile (tmp);

  free (tmp);

  return rc;
}

static uint32_t
uint32link (const char *file)
{
  char *link;
  uint32_t num;
  char *endptr;

  link = xreadlink (file);
  if (link == NULL)
    return 0;

  return atol (link);
}

int
_shisa_uint32link4 (const char *path1,
		    const char *path2,
		    const char *path3,
		    const char *path4)
{
  char *tmp;
  int rc;

  asprintf (&tmp, "%s/%s/%s/%s", path1, path2, path3, path4);

  rc = uint32link (tmp);

  free (tmp);

  return rc;
}

static char *
unescape_filename (const char *path)
{
  /* XXX fix. */
  return xstrdup (path);
}

static int
_shisa_ls_1 (const char *path, char ***files, size_t *nfiles, DIR *dir)
{
  struct dirent *de;
  int rc;

  while (errno = 0, (de = readdir (dir)) != NULL)
    {
      if (strcmp (de->d_name, ".") == 0 || strcmp (de->d_name, "..") == 0)
	continue;
      if (_shisa_isdir2 (path, de->d_name))
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

      perror(path);

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
_shisa_ls (const char *path, char ***files, size_t *nfiles)
{
  struct dirent *de;
  DIR *dir;
  int rc, tmprc;

  dir = opendir (path);
  if (dir == NULL)
    {
      perror(path);
      return -1;
    }

  if (_shisa_ls_1 (path, files, nfiles, dir) != 0)
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

      perror(path);

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
_shisa_ls2 (const char *path1, const char *path2,
	    char ***files, size_t *nfiles)
{
  char *tmp;
  int rc;

  asprintf (&tmp, "%s/%s", path1, path2);

  rc = _shisa_ls (tmp, files, nfiles);

  free (tmp);

  return rc;
}
