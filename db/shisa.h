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
  SHISA_CFG_ERROR,
  SHISA_FOPEN_ERROR,
  SHISA_IO_ERROR,
  SHISA_HANDLE_ERROR
};
typedef enum Shisa_rc Shisa_rc;

typedef struct Shisa		Shisa;
typedef struct Shisa_principal	Shisa_principal;
typedef struct Shisa_key	Shisa_key;

struct Shisa_principal_info
{
  const char *name;
  const char *realm;
  time_t notusedbefore;
  time_t notusedafter;
  int isdisabled;
  int32_t kvno;
};
typedef struct Shisa_principal_info Shisa_principal_info;

struct Shisa_key_info
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
typedef struct Shisa_key_info Shisa_key_info;

/* init.c */
extern Shisa *shisa (void);
extern void shisa_done (Shisa * dbh);
extern int shisa_init (Shisa ** dbh);
extern int shisa_init_with_paths (Shisa ** dbh, const char *file);

/* cfg.c */
extern int shisa_cfg (Shisa * dbh, char *option);
extern int shisa_cfg_db (Shisa * dbh, char *value);
extern int shisa_cfg_from_file (Shisa * dbh, const char *cfg);
extern void shisa_cfg_print (Shisa * dbh, FILE * fh);
extern const char *shisa_cfg_default_systemfile (Shisa * dbh);

/* */
extern int shisa_enumerate_principals (Shisa *dbh,
				       char ***principals,
				       size_t *nprincipals);

/* Core API. */
extern int shisa_principal_create (Shisa * dbh,
				   const char *name,
				   const char *realm,
				   Shisa_principal **ph);
extern int shisa_principal_find (Shisa * dbh,
				 const char *name,
				 const char *realm,
				 Shisa_principal **ph);
extern int shisa_principal_info_get (Shisa_principal * ph,
				     Shisa_principal_info *info);
extern int shisa_principal_info_free (Shisa_principal * ph,
				      const Shisa_principal_info *info);
extern int shisa_principal_info_set (Shisa_principal * ph,
				     const Shisa_principal_info *info);
extern int shisa_principal_key_get (Shisa_principal * ph,
				    Shisa_key_info **keyinfo);
extern int shisa_principal_key_get_version (Shisa_principal * ph,
					    uint32_t kvno,
					    Shisa_key_info **keyinfo);
extern int shisa_principal_key_add (Shisa_principal * ph,
				    const Shisa_key_info *keyinfo);

/* Utility API. */
extern Shisa_principal *shisa_principal (Shisa * dbh,
					 const char *realm,
					 const char *principal);
extern int shisa_setpasswd (Shisa_principal * principal, const char *passwd);

#endif /* SHISA_H */
