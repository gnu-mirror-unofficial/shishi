/* info.h --- Internal header file for shisa library.
 * Copyright (C) 2002, 2003, 2004, 2007  Simon Josefsson
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

#ifndef _INFO_H
#define _INFO_H

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>

#include "gettext.h"
#define _(String) dgettext (PACKAGE, String)
#define gettext_noop(String) String
#define N_(String) gettext_noop (String)

/* Get xmalloc. */
#include "xalloc.h"

/* Get prototypes. */
#include "shisa.h"

typedef int (*_Shisa_db_init) (Shisa * dbh,
			       const char *location,
			       const char *options, void **state);
typedef void (*_Shisa_db_done) (Shisa * dbh, void *state);

typedef int (*_Shisa_db_enumerate_realms) (Shisa * dbh,
					   void *state,
					   char ***realms, size_t * nrealms);
typedef int (*_Shisa_db_enumerate_principals) (Shisa * dbh,
					       void *state,
					       const char *realm,
					       char ***principals,
					       size_t * nprincipals);

typedef int (*_Shisa_db_principal_find) (Shisa * dbh,
					 void *state,
					 const char *realm,
					 const char *principal,
					 Shisa_principal * ph);
typedef int (*_Shisa_db_principal_update) (Shisa * dbh,
					   void *state,
					   const char *realm,
					   const char *principal,
					   const Shisa_principal * ph);
typedef int (*_Shisa_db_principal_add) (Shisa * dbh,
					void *state,
					const char *realm,
					const char *principal,
					const Shisa_principal * ph,
					const Shisa_key * key);
typedef int (*_Shisa_db_principal_remove) (Shisa * dbh,
					   void *state,
					   const char *realm,
					   const char *principal);

typedef int (*_Shisa_db_keys_find) (Shisa * dbh,
				    void *state,
				    const char *realm,
				    const char *principal,
				    const Shisa_key * hint,
				    Shisa_key *** keys, size_t * nkeys);
typedef int (*_Shisa_db_key_add) (Shisa * dbh,
				  void *state,
				  const char *realm,
				  const char *principal,
				  const Shisa_key * key);
typedef int (*_Shisa_db_key_update) (Shisa * dbh,
				     void *state,
				     const char *realm,
				     const char *principal,
				     const Shisa_key * oldkey,
				     const Shisa_key * newkey);
typedef int (*_Shisa_db_key_remove) (Shisa * dbh,
				     void *state,
				     const char *realm,
				     const char *principal,
				     const Shisa_key * key);

struct _Shisa_backend
{
  const char *name;
  _Shisa_db_init init;
  _Shisa_db_done done;
  _Shisa_db_enumerate_realms enumerate_realms;
  _Shisa_db_enumerate_principals enumerate_principals;
  _Shisa_db_principal_find principal_find;
  _Shisa_db_principal_update principal_update;
  _Shisa_db_principal_add principal_add;
  _Shisa_db_principal_remove principal_remove;
  _Shisa_db_keys_find keys_find;
  _Shisa_db_key_add key_add;
  _Shisa_db_key_update key_update;
  _Shisa_db_key_remove key_remove;
};
typedef struct _Shisa_backend _Shisa_backend;

struct _Shisa_db
{
  _Shisa_backend *backend;
  void *state;
};
typedef struct _Shisa_db _Shisa_db;

struct Shisa
{
  _Shisa_db *dbs;
  size_t ndbs;
};

/* Return structure with function pointers implementing a Shisa
   backend, given a name (e.g., "file"). */
extern _Shisa_backend *_shisa_find_backend (const char *name);

#endif /* _INFO_H */
