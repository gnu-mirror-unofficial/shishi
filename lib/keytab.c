/* keys.c --- Functions for reading /etc/krb5.keytab style key files.
 * Copyright (C) 2002-2013 Simon Josefsson
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

/* Get _shishi_hexprint, etc. */
#include "utils.h"

/**
 * shishi_keys_add_keytab_mem:
 * @handle: shishi handle as allocated by shishi_init().
 * @data: constant memory buffer with keytab of @len size.
 * @len: size of memory buffer with keytab data.
 * @keys: allocated key set to store keys in.
 *
 * Read keys from a MIT keytab data structure, and add them to the key
 * set.
 *
 * The format of keytab's is proprietary, and this function support
 * the 0x0501 and 0x0502 formats.  See the section The MIT Kerberos
 * Keytab Binary File Format in the Shishi manual for a description of
 * the reverse-engineered format.
 *
 * Returns: Returns %SHISHI_KEYTAB_ERROR if the data does not
 *   represent a valid keytab structure, and %SHISHI_OK on success.
 **/
int
shishi_keys_add_keytab_mem (Shishi * handle,
			    const char *data, size_t len, Shishi_keys * keys)
{
  int rc;
  uint16_t file_format_version;
  size_t entrystartpos;
  uint16_t num_components;	/* sub 1 if version 0x501 */
  size_t i;
  Shishi_key *key;

  if (VERBOSENOISE (handle))
    {
      printf ("keytab len %d (0x%x)\n", len, len);
      _shishi_hexprint (data, len);
    }

  /* Check file format. */
  file_format_version = (data[0] << 8) | data[1];

  if (VERBOSENOISE (handle))
    printf ("keytab file_format_version %04X\n", file_format_version);

  if (file_format_version != 0x0501 && file_format_version != 0x0502)
    return SHISHI_KEYTAB_ERROR;

  /* Check file integrity first, to avoid error-checking below. */
  entrystartpos = 2;
  while (entrystartpos < len)
    {
      int32_t size = data[entrystartpos] << 24 | data[entrystartpos + 1] << 16
	| data[entrystartpos + 2] << 8 | data[entrystartpos + 3];
      entrystartpos += 4;

      if (VERBOSENOISE (handle))
	{
	  printf ("keytab size %d (%x)\n", size, size);
	  printf ("keytab pos %d < %d\n", entrystartpos + size, len);
	}

      if (entrystartpos + size > len)
	return SHISHI_KEYTAB_ERROR;

      /* Go to next entry... */
      entrystartpos += size;
    }
  if (entrystartpos != len)
    return SHISHI_KEYTAB_ERROR;

  rc = shishi_key (handle, &key);
  if (rc != SHISHI_OK)
    return rc;

  entrystartpos = 2;
  while (entrystartpos < len)
    {
      size_t pos = entrystartpos;
      uint16_t size = data[pos] << 24 | data[pos + 1] << 16
	| data[pos + 2] << 8 | data[pos + 3];
      pos += 4;

      if (VERBOSENOISE (handle))
	printf ("keytab size %d (%x)\n", size, size);

      /* Num_components */
      num_components = data[pos] << 8 | data[pos + 1];
      pos += 2;

      if (file_format_version == 0x0501)
	num_components--;

      /* Realm */
      {
	uint16_t realmlen = data[pos] << 8 | data[pos + 1];
	char *realm = xstrndup (&data[pos + 2], realmlen);;

	pos += 2 + realmlen;

	shishi_key_realm_set (key, realm);
	free (realm);
      }

      /* Principal components. */
      {
	char *name = NULL;
	size_t namelen = 0;

	for (i = 0; i < num_components; i++)
	  {
	    size_t l;

	    l = data[pos] << 8 | data[pos + 1];
	    pos += 2;

	    name = xrealloc (name, namelen + l + 1);
	    memcpy (name + namelen, &data[pos], l);
	    name[namelen + l] = '/';

	    namelen += l + 1;
	    pos += l;

	  }
	name[namelen - 1] = '\0';
	shishi_key_principal_set (key, name);
	free (name);
      }

      /* Name_type */
      {
	uint32_t name_type	/* not present if version 0x501 */
	  = data[pos] << 24 | data[pos + 1] << 16
	  | data[pos + 2] << 8 | data[pos + 3];
	pos += 4;

	if (VERBOSENOISE (handle))
	  printf ("keytab nametype %d (0x%08x)\n", name_type, name_type);
      }

      /* Timestamp */
      {
	uint32_t timestamp =
	  ((data[pos] << 24) & 0xFF000000)
	  | ((data[pos + 1] << 16) & 0xFF0000)
	  | ((data[pos + 2] << 8) & 0xFF00) | ((data[pos + 3] & 0xFF));
	time_t t = timestamp;
	pos += 4;

	if (VERBOSENOISE (handle))
	  printf ("keytab timestamp %s (0x%08x)\n",
		  shishi_generalize_time (handle, timestamp), timestamp);

	shishi_key_timestamp_set (key, t);
      }

      /* keyvno8 */
      {
	uint8_t vno8 = data[pos++];

	if (VERBOSENOISE (handle))
	  printf ("keytab kvno8 %d (0x%02x)\n", vno8, vno8);

	shishi_key_version_set (key, vno8);
      }

      /* key, keytype */
      {
	uint32_t keytype = data[pos] << 8 | data[pos + 1];
	pos += 2;

	if (VERBOSENOISE (handle))
	  printf ("keytab keytype %d (0x%x)\n", keytype, keytype);

	shishi_key_type_set (key, keytype);
      }

      /* key, length and data */
      {
	uint16_t keylen = data[pos] << 8 | data[pos + 1];
	pos += 2;

	if (VERBOSENOISE (handle))
	  printf ("keytab keylen %d (0x%x) eq? %d\n", keylen, keylen,
		  shishi_key_length (key));

	if (VERBOSENOISE (handle))
	  _shishi_hexprint (data + pos, keylen);

	shishi_key_value_set (key, data + pos);
	pos += keylen;
      }

      if (pos - entrystartpos < (size_t) size + 4)
	{
	  uint32_t vno		/* only present if >= 4 bytes left in entry */
	    = data[pos] << 24 | data[pos + 1] << 16
	    | data[pos + 2] << 8 | data[pos + 3];
	  pos += 4;

	  if (VERBOSENOISE (handle))
	    printf ("keytab kvno %d (0x%08x)\n", vno, vno);

	  shishi_key_version_set (key, vno);
	}

      if (VERBOSECRYPTONOISE (handle))
	shishi_key_print (handle, stdout, key);

      rc = shishi_keys_add (keys, key);
      if (rc != SHISHI_OK)
	goto done;

      /* Go to next entry... */
      entrystartpos += size + 4;
    }

  rc = SHISHI_OK;

done:
  shishi_key_done (key);

  return rc;
}

/**
 * shishi_keys_add_keytab_file:
 * @handle: shishi handle as allocated by shishi_init().
 * @filename: name of file to read.
 * @keys: allocated key set to store keys in.
 *
 * Read keys from a MIT keytab data structure from a file, and add the
 * keys to the key set.
 *
 * The format of keytab's is proprietary, and this function support
 * the 0x0501 and 0x0502 formats.  See the section The MIT Kerberos
 * Keytab Binary File Format in the Shishi manual for a description of
 * the reverse-engineered format.
 *
 * Returns: Returns %SHISHI_IO_ERROR if the file cannot be read,
 *   %SHISHI_KEYTAB_ERROR if the data cannot be parsed as a valid keytab
 *   structure, and %SHISHI_OK on success.
 **/
int
shishi_keys_add_keytab_file (Shishi * handle,
			     const char *filename, Shishi_keys * keys)
{
  size_t len;
  char *keytab = read_binary_file (filename, &len);
  int rc;

  if (!keytab)
    return SHISHI_IO_ERROR;

  rc = shishi_keys_add_keytab_mem (handle, keytab, len, keys);

  free (keytab);

  return rc;
}

/**
 * shishi_keys_from_keytab_mem:
 * @handle: shishi handle as allocated by shishi_init().
 * @data: constant memory buffer with keytab of @len size.
 * @len: size of memory buffer with keytab data.
 * @outkeys: pointer to key set that will be allocated and populated,
 *   must be deallocated by caller on succes.
 *
 * Create a new key set populated with keys from a MIT keytab data
 * structure read from a memory block.
 *
 * The format of keytab's is proprietary, and this function support
 * the 0x0501 and 0x0502 formats.  See the section The MIT Kerberos
 * Keytab Binary File Format in the Shishi manual for a description of
 * the reverse-engineered format.
 *
 * Returns: Returns %SHISHI_KEYTAB_ERROR if the data does not
 *   represent a valid keytab structure, and %SHISHI_OK on success.
 **/
int
shishi_keys_from_keytab_mem (Shishi * handle,
			     const char *data, size_t len,
			     Shishi_keys ** outkeys)
{
  int rc;

  rc = shishi_keys (handle, outkeys);
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_keys_add_keytab_mem (handle, data, len, *outkeys);
  if (rc != SHISHI_OK)
    {
      shishi_keys_done (outkeys);
      return rc;
    }

  return SHISHI_OK;
}

/**
 * shishi_keys_from_keytab_file:
 * @handle: shishi handle as allocated by shishi_init().
 * @filename: name of file to read.
 * @outkeys: pointer to key set that will be allocated and populated,
 *   must be deallocated by caller on succes.
 *
 * Create a new key set populated with keys from a MIT keytab data
 * structure read from a file.
 *
 * The format of keytab's is proprietary, and this function support
 * the 0x0501 and 0x0502 formats.  See the section The MIT Kerberos
 * Keytab Binary File Format in the Shishi manual for a description of
 * the reverse-engineered format.
 *
 * Returns: Returns %SHISHI_IO_ERROR if the file cannot be read,
 *   %SHISHI_KEYTAB_ERROR if the data cannot be parsed as a valid keytab
 *   structure, and %SHISHI_OK on success.
 **/
int
shishi_keys_from_keytab_file (Shishi * handle,
			      const char *filename, Shishi_keys ** outkeys)
{
  int rc;

  rc = shishi_keys (handle, outkeys);
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_keys_add_keytab_file (handle, filename, *outkeys);
  if (rc != SHISHI_OK)
    {
      shishi_keys_done (outkeys);
      return rc;
    }

  return SHISHI_OK;
}

static int
key_to_keytab_entry (Shishi * handle,
		     const Shishi_key * key, char **out, size_t * len)
{
  uint16_t num_components = 0;
  const char *realm = shishi_key_realm (key);
  size_t realmlen = strlen (realm);
  const char *principal = shishi_key_principal (key);
  uint32_t name_type = SHISHI_NT_PRINCIPAL;
  time_t timestamp = shishi_key_timestamp (key);
  uint32_t version = shishi_key_version (key);
  uint16_t key_type = shishi_key_type (key);
  size_t key_length = shishi_key_length (key);
  const char *key_value = shishi_key_value (key);
  char *tmpname;
  const char **namebuf;
  char *tokptr = NULL;
  char *p;
  size_t i;

  if (realmlen > UINT16_MAX)
    return SHISHI_KEYTAB_ERROR;

  if (key_length > UINT16_MAX)
    return SHISHI_KEYTAB_ERROR;

  /* Reserve room for size, num_components, realm.length, realm,
     name_type, timestamp, vno8, keyblock.type, keyblock.data.length,
     keyblock.data, and version. */
  *len = 4 + 2 + 2 + realmlen + 4 + 4 + 1 + 2 + 2 + key_length + 4;

  tmpname = xstrdup (principal);
  namebuf = xmalloc (sizeof (*namebuf));
  for (num_components = 0; (namebuf[num_components] =
			    strtok_r (num_components == 0 ? tmpname
				      : NULL, "/", &tokptr));
       num_components++)
    {
      size_t length = strlen (namebuf[num_components]);

      if (length > UINT16_MAX)
	return SHISHI_KEYTAB_ERROR;
      *len += 2 + length;

      namebuf = xrealloc (namebuf, (num_components + 2) * sizeof (*namebuf));
    }

  *out = xmalloc (*len);
  p = *out;

  /* Write size. */
  p[0] = ((*len - 4) >> 24) & 0xFF;
  p[1] = ((*len - 4) >> 16) & 0xFF;
  p[2] = ((*len - 4) >> 8) & 0xFF;
  p[3] = (*len - 4) & 0xFF;
  p += 4;

  /* Write num_components. */
  p[0] = (num_components >> 8) & 0xFF;
  p[1] = num_components & 0xFF;
  p += 2;

  /* Write realm.length and realm.data. */
  p[0] = (realmlen >> 8) & 0xFF;
  p[1] = realmlen & 0xFF;
  p += 2;
  memcpy (p, realm, realmlen);
  p += realmlen;

  for (i = 0; i < num_components; i++)
    {
      uint16_t length = strlen (namebuf[i]);
      p[0] = (length >> 8) & 0xFF;
      p[1] = length & 0xFF;
      p += 2;
      memcpy (p, namebuf[i], length);
      p += length;
    }

  /* Name type */
  p[0] = (name_type >> 24) & 0xFF;
  p[1] = (name_type >> 16) & 0xFF;
  p[2] = (name_type >> 8) & 0xFF;
  p[3] = name_type & 0xFF;
  p += 4;

  /* Timestamp */
  p[0] = (timestamp >> 24) & 0xFF;
  p[1] = (timestamp >> 16) & 0xFF;
  p[2] = (timestamp >> 8) & 0xFF;
  p[3] = timestamp & 0xFF;
  p += 4;

  /* Version */
  if (version < 256)
    p[0] = version & 0xFF;
  else
    p[0] = 0;			/* use vno */
  p += 1;

  /* Key */
  p[0] = (key_type >> 8) & 0xFF;
  p[1] = key_type & 0xFF;
  p += 2;

  p[0] = (key_length >> 8) & 0xFF;
  p[1] = key_length & 0xFF;
  p += 2;
  memcpy (p, key_value, key_length);
  p += key_length;

  /* Version */
  p[0] = (version >> 24) & 0xFF;
  p[1] = (version >> 16) & 0xFF;
  p[2] = (version >> 8) & 0xFF;
  p[3] = version & 0xFF;

  free (tmpname);
  free (namebuf);

  return SHISHI_OK;
}

/**
 * shishi_keys_to_keytab_mem:
 * @handle: shishi handle as allocated by shishi_init().
 * @keys: key set to convert to keytab format.
 * @out: constant memory buffer with keytab of @len size.
 * @len: size of memory buffer with keytab data.
 *
 * Write keys to a MIT keytab data structure.
 *
 * The format of keytab's is proprietary, and this function writes the
 * 0x0502 format.  See the section The MIT Kerberos Keytab Binary File
 * Format in the Shishi manual for a description of the
 * reverse-engineered format.
 *
 * Returns: On success %SHISHI_OK is returned, otherwise an error
 *   code.
 *
 * Since: 0.0.42
 **/
int
shishi_keys_to_keytab_mem (Shishi * handle,
			   Shishi_keys * keys, char **out, size_t * len)
{
  int rc;
  const Shishi_key *key;
  int keyno = 0;

  *out = xmalloc (2);
  *len = 2;

  /* Write file format version. */
  (*out)[0] = '\x05';
  (*out)[1] = '\x02';

  while ((key = shishi_keys_nth (keys, keyno++)) != NULL)
    {
      char *tmp = NULL;
      size_t tmplen = 0;

      rc = key_to_keytab_entry (handle, key, &tmp, &tmplen);
      if (rc != SHISHI_OK)
	{
	  free (*out);
	  return rc;
	}

      *out = xrealloc (*out, *len + tmplen);
      memcpy (*out + *len, tmp, tmplen);
      *len += tmplen;
      free (tmp);
    }

  if (VERBOSENOISE (handle))
    {
      printf ("keys_to_keytab len %d (0x%x)\n", *len, *len);
      _shishi_hexprint (*out, *len);
    }

  return rc;
}

static int
write_binary_file (const char *filename, const char *data, size_t length)
{
  FILE *fh;
  size_t written;

  fh = fopen (filename, "wb");
  if (!fh)
    return SHISHI_FOPEN_ERROR;

  written = fwrite (data, 1, length, fh);
  if (written != length)
    return SHISHI_IO_ERROR;

  return SHISHI_OK;
}

/**
 * shishi_keys_to_keytab_file:
 * @handle: shishi handle as allocated by shishi_init().
 * @keys: keyset to write.
 * @filename: name of file to write.
 *
 * Write keys to a MIT keytab data structure.
 *
 * The format of keytab's is proprietary, and this function writes the
 * 0x0502 format.  See the section The MIT Kerberos Keytab Binary File
 * Format in the Shishi manual for a description of the
 * reverse-engineered format.
 *
 * Returns: %SHISHI_FOPEN_ERROR if there is a problem opening
 *   @filename for writing, %SHISHI_IO_ERROR if there is problem
 *   writing the file, and %SHISHI_OK on success.
 *
 * Since: 0.0.42
 **/
int
shishi_keys_to_keytab_file (Shishi * handle,
			    Shishi_keys * keys, const char *filename)
{
  int rc;
  char *data;
  size_t len;

  rc = shishi_keys_to_keytab_mem (handle, keys, &data, &len);
  if (rc != SHISHI_OK)
    return rc;

  rc = write_binary_file (filename, data, len);
  if (rc != SHISHI_OK)
    return rc;

  return SHISHI_OK;
}
