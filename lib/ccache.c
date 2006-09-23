/* ccache.c --- Read MIT style Kerberos Credential Cache file.
 * Copyright (C) 2006  Simon Josefsson
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

#include "ccache.h"
#include <stdio.h>

/* See ccache.txt for a description of the file format. */

static int
get_uint8 (const void **data, size_t * len, uint8_t * i)
{
  const char *p = *data;
  if (*len < 1)
    return -1;
  *i = p[0];
  *data += 1;
  *len -= 1;
  return 0;
}

static int
get_uint16 (const void **data, size_t * len, uint16_t * i)
{
  const char *p = *data;
  if (*len < 2)
    return -1;
  *i = p[0] << 8 | p[1];
  *data += 2;
  *len -= 2;
  return 0;
}

static int
get_uint32 (const void **data, size_t * len, uint32_t * i)
{
  const char *p = *data;
  if (*len < 4)
    return -1;
  *i = ((p[0] << 24) & 0xFF000000)
    | ((p[1] << 16) & 0xFF0000) | ((p[2] << 8) & 0xFF00) | (p[3] & 0xFF);
  *data += 4;
  *len -= 4;
  return 0;
}

static int
parse_principal (const void **data, size_t * len,
		 struct ccache_principal *out)
{
  size_t n;
  int rc;

  rc = get_uint32 (data, len, &out->name_type);
  if (rc < 0)
    return rc;

  rc = get_uint32 (data, len, &out->num_components);
  if (rc < 0)
    return rc;

  if (out->num_components >= CCACHE_MAX_COMPONENTS)
    return -1;

  rc = get_uint32 (data, len, &out->realm.length);
  if (rc < 0)
    return rc;

  if (*len < out->realm.length)
    return -1;
  out->realm.data = *data;
  *data += out->realm.length;
  *len -= out->realm.length;

  for (n = 0; n < out->num_components; n++)
    {
      rc = get_uint32 (data, len, &out->components[n].length);
      if (rc < 0)
	return rc;

      if (*len < out->components[n].length)
	return -1;
      out->components[n].data = *data;
      *data += out->components[n].length;
      *len -= out->components[n].length;
    }

  return 0;
}

static int
skip_address (const void **data, size_t * len)
{
  uint16_t addrtype;
  uint32_t addrlen;
  int rc;

  rc = get_uint16 (data, len, &addrtype);
  if (rc < 0)
    return rc;

  rc = get_uint32 (data, len, &addrlen);
  if (rc < 0)
    return rc;

  if (*len < addrlen)
    return -1;
  *data += addrlen;
  *len -= addrlen;

  return 0;
}

static int
skip_authdata (const void **data, size_t * len)
{
  uint16_t authdatatype;
  uint32_t authdatalen;
  int rc;

  rc = get_uint16 (data, len, &authdatatype);
  if (rc < 0)
    return rc;

  rc = get_uint32 (data, len, &authdatalen);
  if (rc < 0)
    return rc;

  if (*len < authdatalen)
    return -1;
  *data += authdatalen;
  *len -= authdatalen;

  return 0;
}

static int
parse_credential (const void **data, size_t * len,
		  struct ccache_credential *out)
{
  struct ccache_principal princ;
  uint32_t num_address;
  uint32_t num_authdata;
  int rc;

  rc = parse_principal (data, len, &out->client);
  if (rc < 0)
    return rc;

  rc = parse_principal (data, len, &out->server);
  if (rc < 0)
    return rc;

  rc = get_uint16 (data, len, &out->key.keytype);
  if (rc < 0)
    return rc;

  rc = get_uint16 (data, len, &out->key.etype);
  if (rc < 0)
    return rc;

  rc = get_uint16 (data, len, &out->key.keylen);
  if (rc < 0)
    return rc;

  if (*len < out->key.keylen)
    return -1;

  out->key.keyvalue = *data;

  *data += out->key.keylen;
  *len -= out->key.keylen;

  rc = get_uint32 (data, len, &out->authtime);
  if (rc < 0)
    return rc;

  rc = get_uint32 (data, len, &out->starttime);
  if (rc < 0)
    return rc;

  rc = get_uint32 (data, len, &out->endtime);
  if (rc < 0)
    return rc;

  rc = get_uint32 (data, len, &out->renew_till);
  if (rc < 0)
    return rc;

  rc = get_uint8 (data, len, &out->is_skey);
  if (rc < 0)
    return rc;

  rc = get_uint32 (data, len, &out->tktflags);
  if (rc < 0)
    return rc;

  rc = get_uint32 (data, len, &num_address);
  if (rc < 0)
    return rc;

  for (; num_address; num_address--)
    {
      /* XXX Don't just skip data. */
      rc = skip_address (data, len);
      if (rc < 0)
	return rc;
    }

  rc = get_uint32 (data, len, &num_authdata);
  if (rc < 0)
    return rc;

  for (; num_authdata; num_authdata--)
    {
      /* XXX Don't just skip data. */
      rc = skip_authdata (data, len);
      if (rc < 0)
	return rc;
    }

  rc = get_uint32 (data, len, &out->ticket.length);
  if (rc < 0)
    return rc;

  if (*len < out->ticket.length)
    return -1;
  out->ticket.data = *data;
  *data += out->ticket.length;
  *len -= out->ticket.length;

  rc = get_uint32 (data, len, &out->second_ticket.length);
  if (rc < 0)
    return rc;

  if (*len < out->second_ticket.length)
    return -1;
  out->second_ticket.data = *data;
  *data += out->second_ticket.length;
  *len -= out->second_ticket.length;

  return 0;
}

int
ccache_parse (const void *data, size_t len, struct ccache *out)
{
  size_t pos = 0;
  int rc;

  rc = get_uint16 (&data, &len, &out->file_format_version);
  if (rc < 0)
    return rc;

  rc = get_uint16 (&data, &len, &out->headerlen);
  if (rc < 0)
    return rc;

  out->header = data;

  if (len < out->headerlen)
    return -1;
  data += out->headerlen;
  len -= out->headerlen;

  rc = parse_principal (&data, &len, &out->default_principal);
  if (rc < 0)
    return rc;

  out->credentials = data;
  out->credentialslen = len;

  return 0;
}

int
ccache_parse_credential (const void *data, size_t len,
			 struct ccache_credential *out, size_t * n)
{
  size_t savelen = len;
  int rc = parse_credential (&data, &len, out);

  if (rc < 0)
    return rc;

  *n = savelen - len;
  return 0;
}

void
ccache_print (struct ccache *ccache)
{
  size_t n;

  printf ("file_format_version %04x\n", ccache->file_format_version);
  printf ("headerlen %04x\n", ccache->headerlen);
  printf ("default_principal\n");
  ccache_print_principal (&ccache->default_principal);
}

void
ccache_print_principal (struct ccache_principal *princ)
{
  size_t n;

  printf ("\tname_type %04x\n", princ->name_type);
  printf ("\tnum_components %04x\n", princ->num_components);
  printf ("\trealmlen %04x\n", princ->realm.length);
  printf ("\trealm %.*s\n", princ->realm.length, princ->realm.data);

  for (n = 0; n < princ->num_components; n++)
    {
      printf ("\t\tcomponentlen %04x\n", princ->components[n].length);
      printf ("\t\tcomponent %.*s\n", princ->components[n].length,
	      princ->components[n].data);
    }
}

void
ccache_print_credential (struct ccache_credential *cred)
{
  size_t i;
  printf ("\tclient:\n");
  ccache_print_principal (&cred->client);
  printf ("\tserver:\n");
  ccache_print_principal (&cred->server);
  printf ("\tkey:\n");
  printf ("\t\tkeytype %04x\n", cred->key.keytype);
  printf ("\t\tetype %04x\n", cred->key.etype);
  printf ("\t\tkeylen %04x\n", cred->key.keylen);
  printf ("\t\tkey value: ");
  for (i = 0; i < cred->key.keylen; i++)
    printf ("%02x", ((char *) cred->key.keyvalue)[i] & 0xFF);
  printf ("\n");
  printf ("\ttimes:\n");
  printf ("\t\tauthtime %04x\n", cred->authtime);
  printf ("\t\tstarttime %04x\n", cred->starttime);
  printf ("\t\tendtime %04x\n", cred->endtime);
  printf ("\t\trenew_till %04x\n", cred->renew_till);
  printf ("\tis_skey %04x\n", cred->is_skey);
  printf ("\ttktflags %04x\n", cred->tktflags);
  printf ("\tticketlen %04x\n", cred->ticket.length);
  printf ("\tsecond_ticketlen %04x\n", cred->second_ticket.length);
}

#ifdef TEST
int
main (int argc, char *argv[])
{
  char buf[10240];
  size_t len;
  FILE *fh;
  int rc;
  struct ccache ccache;
  struct ccache_credential cred;
  size_t i = 0;

  if (argc <= 1)
    {
      printf ("Usage: %s <krb5ccache-file>\n", argv[0]);
      return 1;
    }

  fh = fopen (argv[1], "rb");
  if (!fh)
    {
      puts ("Error: cannot open file");
      return 1;
    }

  len = fread (buf, 1, sizeof (buf), fh);

  if (len >= sizeof (buf))
    {
      puts ("Error: file too large");
      return 1;
    }

  rc = ccache_parse (buf, len, &ccache);
  if (rc < 0)
    {
      puts ("Error: syntax error");
      return 1;
    }

  ccache_print (&ccache);

  while (ccache.credentialslen)
    {
      size_t n;

      rc = ccache_parse_credential (ccache.credentials,
				    ccache.credentialslen, &cred, &n);
      if (rc < 0)
	{
	  printf ("Error: cannot parse credential %d\n", i);
	  return rc;
	}

      printf ("\nCredential %d:\n", i++);

      ccache_print_credential (&cred);

      ccache.credentials += n;
      ccache.credentialslen -= n;
    }

  if (fclose (fh))
    {
      puts ("Error: cannot close file");
      return 1;
    }

  return 0;
}
#endif
