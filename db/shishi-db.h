/* shishi-db.h	Header file for Shishi database library.
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

#ifndef SHISHI_DB_H
#define SHISHI_DB_H

#include <shishi.h>

typedef struct Shishi_db	   Shishi_db;

/* Initialize Shishi database system. */
extern Shishi_db *
shishi_db (void);



/*** REALM API ***/

typedef struct Shishi_db_realm     Shishi_db_realm;

struct Shishi_db_realm_info
{
  const char *name;
};
typedef struct Shishi_db_realm_info Shishi_db_realm_info;

/* Find realm in database. */
extern Shishi_db_realm *
shishi_db_realm_find (Shishi_db * dbh, const char *realm);

/* Get information about realm. */
extern int
shishi_db_realm_info (Shishi_db_realm * dbr, Shishi_db_realm_info **info);

/* XXX realm_info_set? */

/* XXX add/remove principal in realm? */



/*** PRINCIPAL API ***/

typedef struct Shishi_db_principal Shishi_db_principal;

struct Shishi_db_principal_info
{
  const char *name;
  time_t notusedbefore;
  time_t notusedafter;
  int isdisabled;
};
typedef struct Shishi_db_principal_info Shishi_db_principal_info;

/* Find principal in realm. */
extern Shishi_db_principal *
shishi_db_principal_find (Shishi_db_realm * realm, const char *cname[]);

/* Get information about principal. */
extern int
shishi_db_principal_info (Shishi_db_principal * principal,
			  Shishi_db_principal_info **info);

/* Set information in principal handle. */
extern int
shishi_db_principal_info_set (Shishi_db_principal * principal,
			      Shishi_db_principal_info *info);



/*** KEYSET API ***/

typedef struct Shishi_db_keyset    Shishi_db_keyset;

struct Shishi_db_keyset_info
{
  int32_t kvno;
};
typedef struct Shishi_db_keyset_info Shishi_db_keyset_info;

/* "Find" keyset handle. */
extern Shishi_db_keyset *
shishi_db_keyset_find (Shishi_db_principal * principal);

/* Get information about keyset. */
extern int
shishi_db_keyset_info (Shishi_db_keyset * keyset,
		       Shishi_db_keyset_info **info);

/* Set information in keyset handle. */
extern int
shishi_db_keyset_info_set (Shishi_db_keyset * keyset,
			   Shishi_db_keyset_info *info);

/* XXX Add/remove key in keyset? */



/*** KEY API ***/

typedef struct Shishi_db_key       Shishi_db_key;

struct Shishi_db_key_info
{
  int32_t etype;
  const char *value;
  size_t valuelen;
  const char *saltvalue;
  size_t saltvaluelen;
  const char *str2keyparam;
  size_t str2keyparamlen;
  time_t notusedafter;
  time_t notusedbefore;
  int isdisabled;
};
typedef struct Shishi_db_key_info Shishi_db_key_info;

/* Find key handle. */
extern Shishi_db_key *
shishi_db_key_find (Shishi_db_keyset * keyset, int32_t etype /* XXX +salt? */);

/* Get information about key. */
extern int
shishi_db_key_info (Shishi_db_key * key,
		    Shishi_db_key_info **info);

/* Set information in key handle. */
extern int
shishi_db_key_info_set (Shishi_db_key * key,
			Shishi_db_key_info *info);



/*** UTILITY API ***/

extern Shishi_db_principal *
shishi_db_search_principal (Shishi_db * dbh,
			    const char *realm, const char *client);

extern int
shishi_db_principal_setpasswd (Shishi_db_principal * principal,
			       const char *passwd);

extern int
shishi_db_key_convert (Shishi * handle, Shishi_db_key_info * key,
		       Shishi_key **key);

#endif /* SHISHI_DB_H */
