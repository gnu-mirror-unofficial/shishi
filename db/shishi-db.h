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

/* XXX perhaps move this into a separate standalone project? */

typedef struct Shishi_db	   Shishi_db;

typedef struct Shishi_db_realm     Shishi_db_realm;
typedef struct Shishi_db_principal Shishi_db_principal;
typedef struct Shishi_db_keyset    Shishi_db_keyset;
typedef struct Shishi_db_key       Shishi_db_key;

/* Initialize Shishi database system. */
extern Shishi_db *
shishi_db (void);

/*** CORE DATABASE PRIMITIVES. ***/

/* Get realm handle. */
extern Shishi_db_realm *
shishi_db_realm (Shishi_db * dbh, const char *realm);

/* Extract information from realm handle. */
extern int
shishi_db_realm_name (Shishi_db * dbh, char **realm);

/* XXX add/remove principal in realm? */

/* Get principal handle. */
extern Shishi_db_principal *
shishi_db_realm_principal (Shishi_db_realm * realm, const char *cname[]);

/* Extract information from principal handle. */
extern int
shishi_db_principal_name (Shishi_db_principal * principal, char **cname[]);
extern int
shishi_db_principal_notusedbefore (Shishi_db_principal * principal, time_t *t);
extern int
shishi_db_principal_notusedafter (Shishi_db_principal * principal, time_t *t);
extern int
shishi_db_principal_isdisabled (Shishi_db_principal * principal, int *t);

/* Set information in principal handle. */
extern int
shishi_db_principal_notusedbefore_set (Shishi_db_principal * principal,
				       time_t t);
extern int
shishi_db_principal_notusedafter_set (Shishi_db_principal * principal,
				      time_t t);
extern int
shishi_db_principal_isdisabled_set (Shishi_db_principal * principal, int t);

/* Get keyset handle. */
extern Shishi_db_keyset *
shishi_db_principal_keyset (Shishi_db_principal * principal);

/* Extract information from keyset handle. */
extern int
shishi_db_keyset_kvno (Shishi_db_keyset * keyset, uint32_t *kvno);

/* Set information in keyset handle. */
extern int
shishi_db_keyset_kvno_set (Shishi_db_keyset * keyset, uint32_t kvno);

/* Get key handle. */
extern Shishi_db_key *
shishi_db_keyset_key (Shishi_db_keyset * keyset, int32_t etype);

/* XXX Add/remove key in keyset? */

/* Extract information from key handle. */
extern int
shishi_db_key_etype (Shishi_db_key * key, int32_t *etype);
extern int
shishi_db_key_value (Shishi_db_key * key, char **data, size_t *len);
extern int
shishi_db_key_saltvalue (Shishi_db_key * key, char **data, size_t *len);
extern int
shishi_db_key_str2keyparam (Shishi_db_key * key, char **data, size_t *len);
extern int
shishi_db_key_notusedafter (Shishi_db_key * key, time_t *t);
extern int
shishi_db_key_notusedbefore (Shishi_db_key * key, time_t *t);
extern int
shishi_db_key_isdisabled (Shishi_db_key * key, int *t);

/* Set information in key handle. */
extern int
shishi_db_key_etype_set (Shishi_db_key * key, int32_t etype);
extern int
shishi_db_key_value_set (Shishi_db_key * key, char *data, size_t len);
extern int
shishi_db_key_saltvalue_set (Shishi_db_key * key, char *data, size_t len);
extern int
shishi_db_key_str2keyparam_set (Shishi_db_key * key, char *data, size_t len);
extern int
shishi_db_key_notusedafter_set (Shishi_db_key * key, time_t t);
extern int
shishi_db_key_notusedbefore_set (Shishi_db_key * key, time_t t);
extern int
shishi_db_key_isdisabled_set (Shishi_db_key * key, int t);

/*** UTILITY API ***/

/* XXX depend on shishi.h? might be nice not to. */
#include <shishi.h>

extern Shishi_db_principal *
shishi_db_realm_principal2 (Shishi_db_realm * realm, const char *client);

extern int
shishi_db_principal_name2 (Shishi_db_principal * principal, char **client);

extern int
shishi_db_principal_setpasswd (Shishi_db_principal * principal, char *passwd);

extern int
shishi_db_principal_disabled_p (Shishi_db_principal * principal);

extern int
shishi_db_key_disabled_p (Shishi_db_key * key);

extern int
shishi_db_key_extract (Shishi * handle, Shishi_db_key * key, Shishi_key **key);

#endif /* SHISHI_DB_H */
