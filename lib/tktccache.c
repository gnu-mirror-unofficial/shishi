/* ccache.c --- Credential Cache compatibility ticket set handling.
 * Copyright (C) 2002, 2003, 2004, 2006  Simon Josefsson
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 *
 */

#include "internal.h"
#include "ccache.h"

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

  return rc;
}

/**
 * shishi_tkts_add_ccache_file:
 * @handle: shishi handle as allocated by shishi_init().
 * @filename: name of file to read.
 * @keys: allocated ticket set to store tickets in.
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
  char *ccache = read_file (filename, &len);
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
 * @outkeys: pointer to ticket set that will be allocated and populated,
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
 * @outkeys: pointer to ticket set that will be allocated and populated,
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
