/* ccache.c --- Credential Cache compatibility ticket set handling.
 * Copyright (C) 2002, 2003, 2004, 2006, 2007, 2008, 2009  Simon Josefsson
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Shishi; if not, see http://www.gnu.org/licenses or write
 * to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
 * Floor, Boston, MA 02110-1301, USA
 *
 */

#include "internal.h"
#include "ccache.h"

#include "utils.h"

/**
 * shishi_tkts_default_ccache_guess:
 * @handle: Shishi library handle create by shishi_init().
 *
 * Guesses the default ccache ticket filename; it is the contents of
 * the environment variable KRB5CCNAME or /tmp/krb5cc_UID where UID is
 * the user's identity in decimal, as returned by getuid().
 *
 * Return value: Returns default ccache filename as a string that has
 *   to be deallocated with free() by the caller.
 **/
char *
shishi_tkts_default_ccache_guess (Shishi * handle)
{
  char *envfile;

  envfile = getenv ("KRB5CCNAME");
  if (envfile)
    return xstrdup (envfile);

#if HAVE_GETUID
  return xasprintf("/tmp/krb5cc_%lu", (unsigned long) getuid ());
#else
  return xasprintf("/tmp/krb5cc_0");
#endif
}

/**
 * shishi_tkts_default_ccache:
 * @handle: Shishi library handle create by shishi_init().
 *
 * Get filename of default ccache filename.
 *
 * Return value: Returns the default ccache filename used in the
 *   library.  The string is not a copy, so don't modify or deallocate
 *   it.
 **/
const char *
shishi_tkts_default_ccache (Shishi * handle)
{
  if (!handle->ccachedefault)
    {
      char *p;

      p = shishi_tkts_default_ccache_guess (handle);
      shishi_tkts_default_ccache_set (handle, p);
      free (p);
    }

  return handle->ccachedefault;
}

/**
 * shishi_tkts_default_ccache_set:
 * @handle: Shishi library handle create by shishi_init().
 * @ccache: string with new default ccache filename, or
 *                 NULL to reset to default.
 *
 * Set the default ccache filename used in the library.  The string is
 * copied into the library, so you can dispose of the variable
 * immediately after calling this function.
 **/
void
shishi_tkts_default_ccache_set (Shishi * handle, const char *ccache)
{
  if (handle->ccachedefault)
    free (handle->ccachedefault);
  if (ccache)
    handle->ccachedefault = xstrdup (ccache);
  else
    handle->ccachedefault = NULL;
}

/**
 * shishi_tkts_add_ccache_mem:
 * @handle: shishi handle as allocated by shishi_init().
 * @data: constant memory buffer with ccache of @len size.
 * @len: size of memory buffer with ccache data.
 * @tkts: allocated key set to store tickets in.
 *
 * Read tickets from a ccache data structure, and add them to the
 * ticket set.
 *
 * The ccache format is proprietary, and this function support (at
 * least) the 0x0504 format.  See the section The Credential Cache
 * Binary File Format in the Shishi manual for a description of the
 * file format.
 *
 * Returns: Returns %SHISHI_CCACHE_ERROR if the data does not
 *   represent a valid ccache structure, and %SHISHI_OK on success.
 **/
int
shishi_tkts_add_ccache_mem (Shishi * handle,
			    const char *data, size_t len,
			    Shishi_tkts *tkts)
{
  int rc = SHISHI_OK;
  struct ccache ccache;

  if (VERBOSENOISE (handle))
    {
      printf ("ccache len %d (0x%x)\n", len, len);
      _shishi_hexprint (data, len);
    }

  rc = ccache_parse (data, len, &ccache);
  if (rc < 0)
    return SHISHI_CCACHE_ERROR;

  if (VERBOSENOISE (handle))
    ccache_print (&ccache);

  while (ccache.credentialslen)
    {
      struct ccache_credential cred;
      Shishi_tkt *tkt;
      Shishi_asn1 ticket;
      size_t n;

      rc = ccache_parse_credential (ccache.credentials,
				    ccache.credentialslen, &cred, &n);
      if (rc < 0)
	return SHISHI_CCACHE_ERROR;

      if (VERBOSENOISE (handle))
	ccache_print_credential (&cred);

      /* Sanity check credential first. */

      if (shishi_cipher_keylen (cred.key.keytype) != cred.key.keylen)
	continue;

      ticket = shishi_der2asn1_ticket (handle, cred.ticket.data,
				       cred.ticket.length);
      if (!ticket)
	continue;

      /* Let's create a new ticket... */

      rc = shishi_tkt (handle, &tkt);
      if (rc != SHISHI_OK)
	return rc;

      shishi_tkt_ticket_set (tkt, ticket);

      {
	const char *cname[CCACHE_MAX_COMPONENTS + 1];
	size_t i;

	for (i = 0; i < cred.client.num_components
	       && i < CCACHE_MAX_COMPONENTS; i++)
	  cname[i] = cred.client.components[i].data;
	cname[i] = NULL;

	rc = shishi_kdcrep_crealm_set (handle,
				       shishi_tkt_kdcrep (tkt),
				       cred.client.realm.data);
	if (rc != SHISHI_OK)
	  return rc;

	rc = shishi_kdcrep_cname_set (handle,
				      shishi_tkt_kdcrep (tkt),
				      cred.client.name_type,
				      cname);
	if (rc != SHISHI_OK)
	  return rc;
      }

      {
	char *sname[CCACHE_MAX_COMPONENTS + 1];
	size_t i;

	for (i = 0; i < cred.server.num_components
	       && i < CCACHE_MAX_COMPONENTS; i++)
	  sname[i] = cred.server.components[i].data;
	sname[i] = NULL;

	rc = shishi_enckdcreppart_srealm_set (handle,
					      shishi_tkt_enckdcreppart (tkt),
					      cred.server.realm.data);
	if (rc != SHISHI_OK)
	  return rc;

	rc = shishi_enckdcreppart_sname_set (handle,
					     shishi_tkt_enckdcreppart (tkt),
					     cred.server.name_type,
					     sname);
	if (rc != SHISHI_OK)
	  return rc;
      }

      rc = shishi_tkt_flags_set (tkt, cred.tktflags);
      if (rc != SHISHI_OK)
	return rc;

      rc = shishi_enckdcreppart_authtime_set
	(handle,
	 shishi_tkt_enckdcreppart (tkt),
	 shishi_generalize_time (handle, cred.authtime));
      if (rc != SHISHI_OK)
	return rc;

      rc = shishi_enckdcreppart_starttime_set
	(handle,
	 shishi_tkt_enckdcreppart (tkt),
	 cred.starttime ? shishi_generalize_time (handle, cred.starttime)
	 : NULL);
      if (rc != SHISHI_OK)
	return rc;

      rc = shishi_enckdcreppart_endtime_set
	(handle,
	 shishi_tkt_enckdcreppart (tkt),
	 shishi_generalize_time (handle, cred.endtime));
      if (rc != SHISHI_OK)
	return rc;

      rc = shishi_enckdcreppart_renew_till_set
	(handle,
	 shishi_tkt_enckdcreppart (tkt),
	 cred.renew_till ? shishi_generalize_time (handle, cred.renew_till)
	 : NULL);
      if (rc != SHISHI_OK)
	return rc;

      {
	uint32_t nonce = 0;
	rc = shishi_enckdcreppart_nonce_set (handle,
					     shishi_tkt_enckdcreppart (tkt),
					     nonce);
	if (rc != SHISHI_OK)
	  return rc;
      }

      rc = shishi_kdcrep_set_ticket (handle, shishi_tkt_kdcrep (tkt),
				     shishi_tkt_ticket (tkt));
      if (rc != SHISHI_OK)
	return rc;

      rc = shishi_kdcrep_set_enc_part (handle, shishi_tkt_kdcrep (tkt),
				       0, 0, "", 0);
      if (rc != SHISHI_OK)
	return rc;

      /* Add key. */

      {
	Shishi_key *key;

	rc = shishi_key (handle, &key);
	if (rc != SHISHI_OK)
	  return rc;

	shishi_key_type_set (key, cred.key.keytype);
	shishi_key_value_set (key, cred.key.keyvalue);
	rc = shishi_tkt_key_set (tkt, key);
	if (rc != SHISHI_OK)
	  return rc;

	shishi_key_done (key);
      }

      /* Add new ticket to the set... */

      rc = shishi_tkts_add (tkts, tkt);
      if (rc != SHISHI_OK)
	return rc;

      ccache.credentials += n;
      ccache.credentialslen -= n;
    }

#if 0
  {
    char *data;
    size_t len;
    rc = shishi_tkts_to_ccache_mem (handle, tkts, &data, &len);
    printf ("gaah res %d\n", rc);
  }
#endif

  return rc;
}

/**
 * shishi_tkts_add_ccache_file:
 * @handle: shishi handle as allocated by shishi_init().
 * @filename: name of file to read.
 * @tkts: allocated ticket set to store tickets in.
 *
 * Read tickets from a ccache data structure, and add them to the
 * ticket set.
 *
 * The ccache format is proprietary, and this function support (at
 * least) the 0x0504 format.  See the section The Credential Cache
 * Binary File Format in the Shishi manual for a description of the
 * file format.
 *
 * Returns: Returns %SHISHI_IO_ERROR if the file cannot be read,
 *   %SHISHI_CCACHE_ERROR if the data cannot be parsed as a valid ccache
 *   structure, and %SHISHI_OK on success.
 **/
int
shishi_tkts_add_ccache_file (Shishi * handle,
			     const char *filename,
			     Shishi_tkts *tkts)
{
  size_t len;
  char *ccache = read_binary_file (filename, &len);
  int rc;

  if (!ccache)
    return SHISHI_IO_ERROR;

  rc = shishi_tkts_add_ccache_mem (handle, ccache, len, tkts);

  free (ccache);

  return rc;
}

/**
 * shishi_tkts_from_ccache_mem:
 * @handle: shishi handle as allocated by shishi_init().
 * @data: constant memory buffer with ccache of @len size.
 * @len: size of memory buffer with ccache data.
 * @outtkts: pointer to ticket set that will be allocated and populated,
 *   must be deallocated by caller on succes.
 *
 * Read tickets from a ccache data structure, and add them to the
 * ticket set.
 *
 * The ccache format is proprietary, and this function support (at
 * least) the 0x0504 format.  See the section The Credential Cache
 * Binary File Format in the Shishi manual for a description of the
 * file format.
 *
 * Returns: Returns %SHISHI_CCACHE_ERROR if the data does not
 *   represent a valid ccache structure, and %SHISHI_OK on success.
 **/
int
shishi_tkts_from_ccache_mem (Shishi * handle,
			     const char *data, size_t len,
			     Shishi_tkts **outtkts)
{
  int rc;

  rc = shishi_tkts (handle, outtkts);
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_tkts_add_ccache_mem (handle, data, len, *outtkts);
  if (rc != SHISHI_OK)
    {
      shishi_tkts_done (outtkts);
      return rc;
    }

  return SHISHI_OK;
}

/**
 * shishi_tkts_from_ccache_file:
 * @handle: shishi handle as allocated by shishi_init().
 * @filename: name of file to read.
 * @outtkts: pointer to ticket set that will be allocated and populated,
 *   must be deallocated by caller on succes.
 *
 * Read tickets from a ccache data structure, and add them to the
 * ticket set.
 *
 * The ccache format is proprietary, and this function support (at
 * least) the 0x0504 format.  See the section The Credential Cache
 * Binary File Format in the Shishi manual for a description of the
 * file format.
 *
 * Returns: Returns %SHISHI_IO_ERROR if the file cannot be read,
 *   %SHISHI_CCACHE_ERROR if the data cannot be parsed as a valid ccache
 *   structure, and %SHISHI_OK on success.
 **/
int
shishi_tkts_from_ccache_file (Shishi * handle,
			      const char *filename,
			      Shishi_tkts **outtkts)
{
  int rc;

  rc = shishi_tkts (handle, outtkts);
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_tkts_add_ccache_file (handle, filename, *outtkts);
  if (rc != SHISHI_OK)
    {
      shishi_tkts_done (outtkts);
      return rc;
    }

  return SHISHI_OK;
}

extern int
shishi_tkt_to_ccache_mem (Shishi *handle, Shishi_tkt *tkt,
			  char **data, size_t *len);

int
shishi_tkt_to_ccache_mem (Shishi *handle,
			  Shishi_tkt *tkt,
			  char **data, size_t *len)
{
#if 0
  struct ccache_credential cred;
  char tmp[1024];
  size_t i;
  int rc;

  memset (&cred, 0, sizeof (cred));

  rc = shishi_asn1_to_der (handle, shishi_tkt_ticket (tkt),
			   &cred.ticket.data, &cred.ticket.length);
  if (rc != SHISHI_OK)
    return rc;

  /* Sanity check credential first. */

  if (shishi_key_length (shishi_tkt_key (tkt)) > CCACHE_MAX_KEYLEN)
    return SHISHI_CCACHE_ERROR;

  rc = shishi_asn1_read (handle, shishi_tkt_kdcrep (tkt), "crealm",
			 &cred.client.realm.data,
			 &cred.client.realm.length);
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_asn1_read (handle, shishi_tkt_enckdcreppart (tkt), "srealm",
			 &cred.server.realm.data,
			 &cred.server.realm.length);
  if (rc != SHISHI_OK)
    return rc;

  return SHISHI_OK;

#if 0
  {
	char *cname[CCACHE_MAX_COMPONENTS + 1];
	size_t i;

	for (i = 0; i < cred.client.num_components
	       && i < CCACHE_MAX_COMPONENTS; i++)
	  cname[i] = cred.client.components[i].data;
	cname[i] = NULL;

	rc = shishi_kdcrep_crealm_set (handle,
				       shishi_tkt_kdcrep (tkt),
				       cred.client.realm.data);
	if (rc != SHISHI_OK)
	  return rc;

	rc = shishi_kdcrep_cname_set (handle,
				      shishi_tkt_kdcrep (tkt),
				      cred.client.name_type,
				      cname);
	if (rc != SHISHI_OK)
	  return rc;
      }

      {
	char *sname[CCACHE_MAX_COMPONENTS + 1];
	size_t i;

	for (i = 0; i < cred.server.num_components
	       && i < CCACHE_MAX_COMPONENTS; i++)
	  sname[i] = cred.server.components[i].data;
	sname[i] = NULL;

	rc = shishi_enckdcreppart_srealm_set (handle,
					      shishi_tkt_enckdcreppart (tkt),
					      cred.server.realm.data);
	if (rc != SHISHI_OK)
	  return rc;

	rc = shishi_enckdcreppart_sname_set (handle,
					     shishi_tkt_enckdcreppart (tkt),
					     cred.server.name_type,
					     sname);
	if (rc != SHISHI_OK)
	  return rc;
      }
#endif

      rc = shishi_tkt_flags (tkt, &cred.tktflags);
      if (rc != SHISHI_OK)
	return rc;

      {
	time_t t;
	rc = shishi_ctime (handle, shishi_tkt_enckdcreppart (tkt),
			   "authtime", &t);
	if (rc != SHISHI_OK)
	  return rc;
	cred.authtime = t;
      }

      {
	time_t t;
	rc = shishi_ctime (handle, shishi_tkt_enckdcreppart (tkt),
			   "starttime", &t);
	if (rc == SHISHI_ASN1_NO_ELEMENT)
	  cred.starttime = 0;
	else if (rc != SHISHI_OK)
	  return rc;
	cred.starttime = t;
      }

      {
	time_t t;
	rc = shishi_ctime (handle, shishi_tkt_enckdcreppart (tkt),
			 "endtime", &t);
	if (rc != SHISHI_OK)
	  return rc;
	cred.endtime = t;
      }

      {
	time_t t;
	rc = shishi_ctime (handle, shishi_tkt_enckdcreppart (tkt),
			   "renew-till", &t);
	if (rc == SHISHI_ASN1_NO_ELEMENT)
	  cred.renew_till = 0;
	else if (rc != SHISHI_OK)
	  return rc;
	cred.renew_till = t;
      }

      cred.key.keylen = shishi_key_length (shishi_tkt_key (tkt));
      cred.key.keytype = shishi_key_type (shishi_tkt_key (tkt));
      memcpy (cred.key.storage, shishi_key_value (shishi_tkt_key (tkt)),
	      shishi_key_length (shishi_tkt_key (tkt)));
      cred.key.keyvalue = &cred.key.storage[0];

      i = 1024;
      rc = ccache_pack_credential (&cred, tmp, &i);
      printf ("rc %d len %d\n", rc, i);

      {
	struct ccache_credential foo;
	size_t n;

	rc = ccache_parse_credential (tmp, i, &foo, &n);
	if (rc < 0)
	  return SHISHI_CCACHE_ERROR;

	printf ("packed:");
	ccache_print_credential (&foo);
      }
      _shishi_escapeprint (tmp, i);
#endif

      return SHISHI_CCACHE_ERROR;
}

extern int
shishi_tkts_to_ccache_mem (Shishi *handle, Shishi_tkts *tkts,
			   char **data, size_t *len);

int
shishi_tkts_to_ccache_mem (Shishi *handle,
			   Shishi_tkts *tkts,
			   char **data, size_t *len)
{
  return SHISHI_CCACHE_ERROR;

#if 0
  struct ccache info;
  int rc = SHISHI_OK;
  size_t i;

  for (i = 0; i < shishi_tkts_size (tkts); i++)
    {
      Shishi_tkt *tkt = shishi_tkts_nth (tkts, i);
      struct ccache_credential cred;

      printf ("ccache %d\n", i);

      if (!tkt)
	return SHISHI_INVALID_TKTS;

      rc = shishi_tkt_to_ccache_mem (handle, tkt, data, len);
      printf ("f %d\n", rc);
    }

  memset (&info, 0, sizeof (info));

  rc = ccache_pack (&info, *data, *len);
  printf ("pack res %d len %d\n", rc, *len);

  return rc;
#endif
}
