/* shisa.h --- Header file for concurrent write-safe Kerberos database library.
 * Copyright (C) 2003  Simon Josefsson
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

#ifndef SHISA_H
#define SHISA_H

#include <stddef.h>		/* size_t */
#include <time.h>		/* time_t */
#include <shishi-int.h>		/* int32_t, uint32_t */

/* Error codes */
enum Shisa_rc
{
  SHISA_OK = 0,
  /* init.c */
  SHISA_INIT_ERROR = 1,
  /* cfg.c */
  SHISA_CFG_NO_FILE = 2,
  SHISA_CFG_IO_ERROR = 3,
  SHISA_CFG_SYNTAX_ERROR = 4,
  /* db.c: file.c */
  SHISA_OPEN_ERROR = 5,
  SHISA_ENUMERATE_REALM_ERROR = 6,
  SHISA_ENUMERATE_PRINCIPAL_ERROR = 7,
  SHISA_NO_REALM = 8,
  SHISA_NO_PRINCIPAL = 9,
  SHISA_NO_KEY = 10,
  SHISA_FIND_ERROR = 11,
  SHISA_ADD_REALM_EXISTS = 12,
  SHISA_ADD_REALM_ERROR = 13,
  SHISA_REMOVE_REALM_NONEMPTY = 14,
  SHISA_REMOVE_REALM_ERROR = 15,
  SHISA_ADD_PRINCIPAL_EXISTS = 16,
  SHISA_ADD_PRINCIPAL_ERROR = 17,
  SHISA_REMOVE_PRINCIPAL_NONEMPTY = 18,
  SHISA_REMOVE_PRINCIPAL_ERROR = 19
};
typedef enum Shisa_rc Shisa_rc;

typedef struct Shisa Shisa;

struct Shisa_principal
{
  int isdisabled;
  uint32_t kvno;
  time_t notusedbefore;
  time_t lastinitialtgt;	/* time of last initial request for a TGT */
  time_t lastinitialrequest;	/* time of last initial request */
  time_t lasttgt;		/* time of issue for the newest TGT used */
  time_t lastrenewal;		/* time of the last renewal */
  time_t passwordexpire;	/* time when the password will expire */
  time_t accountexpire;		/* time when the account will expire. */
};
typedef struct Shisa_principal Shisa_principal;

struct Shisa_key
{
  int32_t etype;
  char *key;
  size_t keylen;
  char *salt;
  size_t saltlen;
  char *str2keyparam;
  size_t str2keyparamlen;
  char *password;
};
typedef struct Shisa_key Shisa_key;

/* init.c */
extern Shisa *shisa (void);
extern void shisa_done (Shisa * dbh);
extern int shisa_init (Shisa ** dbh);
extern int shisa_init_with_paths (Shisa ** dbh, const char *file);

/* cfg.c */
extern int shisa_cfg (Shisa * dbh, char *option);
extern int shisa_cfg_db (Shisa * dbh, char *value);
extern int shisa_cfg_from_file (Shisa * dbh, const char *cfg);
extern const char *shisa_cfg_default_systemfile (Shisa * dbh);

/* core.c. */
extern int shisa_enumerate_realms (Shisa * dbh,
				   char ***realms, size_t * nrealms);
extern int shisa_enumerate_principals (Shisa * dbh,
				       const char *realm,
				       char ***principals,
				       size_t * nprincipals);

extern int shisa_principal_find (Shisa * dbh,
				 const char *realm,
				 const char *principal, Shisa_principal * ph);
extern int shisa_principal_update (Shisa * dbh,
				   const char *realm,
				   const char *principal,
				   const Shisa_principal * ph);
extern int shisa_principal_add (Shisa * dbh,
				const char *realm,
				const char *principal,
				const Shisa_principal * ph,
				const Shisa_key * key);
extern int shisa_principal_remove (Shisa * dbh,
				   const char *realm, const char *principal);

extern int shisa_enumerate_keys (Shisa * dbh,
				 const char *realm,
				 const char *principal,
				 Shisa_key *** keys, size_t * nkeys);
extern int shisa_key_add (Shisa * dbh,
			  const char *realm,
			  const char *principal,
			  uint32_t kvno, const Shisa_key * key);
extern void shisa_key_free (Shisa * dbh, Shisa_key * key);

/* error.c */
extern const char *shisa_strerror (int err);
extern void shisa_info (Shisa * dbh, const char *format, ...);

/* tool.c */
extern int shisa_valid_principal_find (Shisa * dbh,
				       const char *client,
				       const char *realm,
				       time_t t, Shisa_principal * ph);
extern int shisa_valid_key_find (Shisa * dbh,
				 const Shisa_principal * ph,
				 time_t t, Shisa_key ** key);

#endif /* SHISA_H */
