/* shisa.h --- Header file for Shishi database library.
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
#include <shishi-int.h>		/* uint32_t */

/* Error codes */
enum Shisa_rc
{
  SHISA_OK = 0,
  SHISA_INIT_ERROR,
  SHISA_CFG_NO_FILE,
  SHISA_CFG_IO_ERROR,
  SHISA_CFG_SYNTAX_ERROR,
  SHISA_DB_OPEN_ERROR
};
typedef enum Shisa_rc Shisa_rc;

typedef struct Shisa		Shisa;

struct Shisa_principal
{
  const char *name;
  const char *realm;
  time_t notusedbefore;
  time_t notusedafter;
  int isdisabled;
  int32_t kvno;
};
typedef struct Shisa_principal Shisa_principal;

struct Shisa_key
{
  int32_t etype;
  const char *value;
  size_t valuelen;
  const char *saltvalue;
  size_t saltvaluelen;
  const char *str2keyparam;
  size_t str2keyparamlen;
  const char *password;
  time_t notusedafter;
  time_t notusedbefore;
  int isdisabled;
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

/* Core API. */
extern int shisa_enumerate_realms (Shisa *dbh,
				   char ***realms,
				   size_t *nrealms);
extern int shisa_enumerate_principals (Shisa *dbh,
				       const char *realm,
				       char ***principals,
				       size_t *nprincipals);

extern int shisa_principal_find (Shisa * dbh,
				 const char *client,
				 const char *realm,
				 Shisa_principal **ph);
extern int shisa_principal_free (Shisa_principal *ph);
extern int shisa_principal_set (Shisa * dbh, const Shisa_principal * ph);
extern int shisa_principal_add (Shisa * dbh, const Shisa_principal * ph,
				const Shisa_key *key);
extern int shisa_principal_remove (Shisa * dbh, const Shisa_principal * ph);

extern int shisa_key_find (Shisa * dbh, const Shisa_principal * ph,
			  Shisa_key **key);
extern int shisa_key_free (Shisa_key **key);
extern int shisa_key_set (Shisa * dbh, const Shisa_principal * ph,
			  const Shisa_key *key);
extern int shisa_key_add (Shisa * dbh, const Shisa_principal * ph,
			  const Shisa_key *key);
extern int shisa_key_remove (Shisa * dbh, const Shisa_principal * ph,
			     const Shisa_key *key);

/* Utility API. */
extern int shisa_addpasswd (Shisa * dbh, Shisa_principal * ph,
			    const char *passwd);

#endif /* SHISA_H */
