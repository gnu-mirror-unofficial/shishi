/* internal.h --- Internal header file for shisa library.
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

#ifndef _INTERNAL_H
#define _INTERNAL_H

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

#include "xalloc.h"

#include "shisa.h"

typedef int (*_Shisa_db_init) (Shisa *dbh,
			       const char *location,
			       const char *options,
			       void **state);
typedef int (*_Shisa_db_enumerate_realms) (Shisa *dbh,
					   void *state,
					   char ***realms,
					   size_t *nrealms);
typedef int (*_Shisa_db_enumerate_principals) (Shisa *dbh,
					       void *state,
					       const char *realm,
					       char ***principals,
					       size_t *nprincipals);
typedef int (*_Shisa_db_principal_find) (Shisa * dbh,
					 void *state,
					 const char *realm,
					 const char *principal,
					 Shisa_principal *ph);
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
typedef int (*_Shisa_db_enumerate_keys) (Shisa * dbh,
					 void *state,
					 const char *realm,
					 const char *principal,
					 Shisa_key ***keys,
					 size_t *nkeys);
typedef int (*_Shisa_db_key_add) (Shisa * dbh,
				  void *state,
				  const char *realm,
				  const char *principal,
				  uint32_t kvno,
				  const Shisa_key * key);
typedef void (*_Shisa_db_done) (Shisa *dbh, void *state);

struct _Shisa_backend
{
  char *name;
  _Shisa_db_init init;
  _Shisa_db_enumerate_realms enumerate_realms;
  _Shisa_db_enumerate_principals enumerate_principals;
  _Shisa_db_principal_find principal_find;
  _Shisa_db_principal_update principal_update;
  _Shisa_db_principal_add principal_add;
  _Shisa_db_principal_remove principal_remove;
  _Shisa_db_enumerate_keys enumerate_keys;
  _Shisa_db_key_add key_add;
  _Shisa_db_done done;
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

extern int getsubopt (char **optionp, char *const *tokens, char **valuep);

/* db.c */
extern _Shisa_backend *_shisa_find_backend (const char *name);

/* file.c */
extern int shisa_file_init (Shisa *dbh,
			    const char *location,
			    const char *options,
			    void **state);
extern int shisa_file_enumerate_realms (Shisa *dbh,
					void *state,
					char ***realms,
					size_t *nrealms);
extern int shisa_file_enumerate_principals (Shisa *dbh,
					    void *state,
					    const char *realm,
					    char ***principals,
					    size_t *nprincipals);
extern int shisa_file_principal_find (Shisa * dbh,
				      void *state,
				      const char *realm,
				      const char *principal,
				      Shisa_principal *ph);
extern int shisa_file_principal_update (Shisa * dbh,
					void *state,
					const char *realm,
					const char *principal,
					const Shisa_principal * ph);
extern int shisa_file_principal_add (Shisa * dbh,
				     void *state,
				     const char *realm,
				     const char *principal,
				     const Shisa_principal * ph,
				     const Shisa_key * key);
extern int shisa_file_principal_remove (Shisa * dbh,
					void *state,
					const char *realm,
					const char *principal);
extern int shisa_file_enumerate_keys (Shisa * dbh,
				      void *state,
				      const char *realm,
				      const char *principal,
				      Shisa_key ***keys,
				      size_t *nkeys);
extern int shisa_file_key_add (Shisa * dbh,
			       void *state,
			       const char *realm,
			       const char *principal,
			       uint32_t kvno,
			       const Shisa_key * key);
extern void shisa_file_done (Shisa *dbh, void *state);

#endif /* _INTERNAL_H */
