/* db.c		abstract interface to a kerberos database backend
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

#include <shishi-kdc.h>

struct Shishi_db
{
  Shishi * handle;
};


Shishi_db *
shishi_db (void)
{
  Shishi_db *dbh;

  dbh = xcalloc (1, sizeof (*dbh));

  dbh->handle = shishi();

  return dbh;
}

struct Shishi_db_realm
{
  Shishi_db * dbh;
  const char *realm;
};


Shishi_db *
shishi_db_realm_find (Shishi_db * dbh, const char *realm)
{
  Shishi_db_realm *dbr;

  dbr = xcalloc (1, sizeof (*dbr));

  dbr->dbh = dbh;
  dbr->realm = xstrdup (realm);

  return dbr;
}

int
shishi_db_realm_info (Shishi_db_realm * dbr, Shishi_db_realm_info **info)
{
  Shishi_db_realm_info *dbri;

  dbri = xcalloc (1, sizeof (*dbri));

  dbri->name = dbr->realm;

  *info = dbri;

  return dbri;
}

struct Shishi_db_principal
{
  Shishi_db * dbh;
  
};

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
