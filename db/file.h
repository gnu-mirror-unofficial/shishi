/* file.h --- Prototypes for file based Shisa database.
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

/*************************************************** Initializor/destructor. */

/* Initialize file backend, i.e., parse options and check if file root
   exists and allocate backend handle. */
extern int
shisa_file_init (Shisa * dbh,
		 const char *location, const char *options, void **state);

/* Destroy backend handle. */
extern void shisa_file_done (Shisa * dbh, void *state);

/************************************************************** Enumerators. */

/* Return a list of all realm names in backend, as zero-terminated
   UTF-8 strings.  The caller must deallocate the strings. */
extern int
shisa_file_enumerate_realms (Shisa * dbh,
			     void *state, char ***realms, size_t * nrealms);

/* Return a list of all principals in realm in backend, as
   zero-terminated UTF-8 strings.  The caller must deallocate the
   strings. */
extern int
shisa_file_enumerate_principals (Shisa * dbh,
				 void *state,
				 const char *realm,
				 char ***principals, size_t * nprincipals);

/**************************************** Functions operating on principals. */

/* Return information about specified PRINCIPAL@REALM.  Can also be
   used check existence of principal entry, with a NULL PH. */
extern int
shisa_file_principal_find (Shisa * dbh,
			   void *state,
			   const char *realm,
			   const char *principal, Shisa_principal * ph);

/* Add new PRINCIPAL@REALM with specified information and key.  If
   PRINCIPAL is NULL, then add realm REALM. */
extern int
shisa_file_principal_add (Shisa * dbh,
			  void *state,
			  const char *realm,
			  const char *principal,
			  const Shisa_principal * ph, const Shisa_key * key);

/* Modify information for specified PRINCIPAL@REALM.  */
extern int
shisa_file_principal_update (Shisa * dbh,
			     void *state,
			     const char *realm,
			     const char *principal,
			     const Shisa_principal * ph);

/* Remove PRINCIPAL@REALM, or REALM if PRINCIPAL is NULL.  Realms must
   be empty for them to be successfully removed.  */
extern int
shisa_file_principal_remove (Shisa * dbh,
			     void *state,
			     const char *realm, const char *principal);


/********************************************** Functions operating on keys. */

/* Get all keys matching HINT for specified PRINCIPAL@REALM.  The
   caller must deallocate the returned keys.  If HINT is NULL, then
   all keys are returned. */
extern int
shisa_file_keys_find (Shisa * dbh,
		      void *state,
		      const char *realm,
		      const char *principal,
		      const Shisa_key * hint,
		      Shisa_key *** keys, size_t * nkeys);

/* Add key for PRINCIPAL@REALM. */
extern int
shisa_file_key_add (Shisa * dbh,
		    void *state,
		    const char *realm,
		    const char *principal, const Shisa_key * key);

/* Update a key for PRINCIPAL@REALM.  The OLDKEY must uniquely
   determine the key to update, i.e., shishi_keys_find using OLDKEY as
   HINT must return exactly 1 key.  */
extern int
shisa_file_key_update (Shisa * dbh,
		       void *state,
		       const char *realm,
		       const char *principal,
		       const Shisa_key * oldkey, const Shisa_key * newkey);

/* Remove a key for PRINCIPAL@REALM.  The KEY must uniquely determine
   the key to remove, i.e., shishi_keys_find using KEY as HINT must
   return exactly 1 key.  */
extern int
shisa_file_key_remove (Shisa * dbh,
		       void *state,
		       const char *realm,
		       const char *principal, const Shisa_key * key);
