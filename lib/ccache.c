/* ccache.c --- Read MIT style Kerberos Credential Cache file.
 * Copyright (C) 2006, 2007, 2008  Simon Josefsson
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 3 of the License,
 * or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this file; if not, see http://www.gnu.org/licenses or
 * write to the Free Software Foundation, Inc., 51 Franklin Street,
 * Fifth Floor, Boston, MA 02110-1301, USA
 *
 */

#include "ccache.h"
#include <stdio.h>

/* See ccache.txt for a description of the file format.  Currently
   this implementation do not support addresses nor auth-data.  */

static int
get_uint8 (const char **data, size_t * len, uint8_t * i)
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
get_uint16 (const char **data, size_t * len, uint16_t * i)
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
get_uint32 (const char **data, size_t * len, uint32_t * i)
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
get_uint32_swapped (const char **data, size_t * len, uint32_t * i)
{
  const char *p = *data;
  if (*len < 4)
    return -1;
  *i = ((p[3] << 24) & 0xFF000000)
    | ((p[2] << 16) & 0xFF0000) | ((p[1] << 8) & 0xFF00) | (p[0] & 0xFF);
  *data += 4;
  *len -= 4;
  return 0;
}

static int
put_uint8 (uint8_t i, char **data, size_t * len)
{
  if (*len < 1)
    return -1;
  *(*data)++ = i;
  *len -= 1;
  return 0;
}

static int
put_uint16 (uint16_t i, char **data, size_t * len)
{
  if (*len < 2)
    return -1;
  *(*data)++ = (i >> 8) & 0xFF;
  *(*data)++ = i;
  *len -= 2;
  return 0;
}

static int
put_uint32 (uint32_t i, char **data, size_t * len)
{
  if (*len < 4)
    return -1;
  *(*data)++ = (i >> 24) & 0xFF;
  *(*data)++ = (i >> 16) & 0xFF;
  *(*data)++ = (i >> 8) & 0xFF;
  *(*data)++ = i;
  *len -= 4;
  return 0;
}

static int
put_uint32_swapped (uint32_t i, char **data, size_t * len)
{
  if (*len < 4)
    return -1;
  *(*data)++ = i;
  *(*data)++ = (i >> 8) & 0xFF;
  *(*data)++ = (i >> 16) & 0xFF;
  *(*data)++ = (i >> 24) & 0xFF;
  *len -= 4;
  return 0;
}

static int
parse_principal (const char **data, size_t * len,
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
  out->realm.data = (char*) *data;
  *data += out->realm.length;
  *len -= out->realm.length;

  /* Make sure realm will be zero terminated.  This limits component
     lengths to 2^24 bytes. */
  if (**(char**)data != '\0')
    return -1;

  for (n = 0; n < out->num_components; n++)
    {
      rc = get_uint32 (data, len, &out->components[n].length);
      if (rc < 0)
	return rc;

      if (*len < out->components[n].length)
	return -1;
      out->components[n].data = (char*) *data;
      *data += out->components[n].length;
      *len -= out->components[n].length;

      /* Make sure component is zero terminated.  This limits the
	 length of the next component to 2^24 bytes.  Note that you'll
	 have to test after the last component elsewhere. */
      if (*len > 0 && **(char**)data != '\0')
	return -1;
    }

  return 0;
}

static int
skip_address (const char **data, size_t * len)
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
skip_authdata (const char **data, size_t * len)
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
parse_credential (const char **data, size_t * len,
		  struct ccache_credential *out)
{
  uint32_t num_address;
  uint32_t num_authdata;
  int rc;

  rc = parse_principal (data, len, &out->client);
  if (rc < 0)
    return rc;

  /* Make sure the last component is zero terminated.  This limits the
     next name-type to 2^24 bytes.  */
  if (*len > 0 && **(char**)data != '\0')
    return -1;

  rc = parse_principal (data, len, &out->server);
  if (rc < 0)
    return rc;

  /* Make sure the last component is zero terminated.  This limits the
     next key-type to lower 1 byte.  */
  if (*len > 0 && **(char**)data != '\0')
    return -1;

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

  out->key.keyvalue = (char*) *data;

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

  rc = get_uint32_swapped (data, len, &out->tktflags);
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
  out->ticket.data = (char*) *data;
  *data += out->ticket.length;
  *len -= out->ticket.length;

  rc = get_uint32 (data, len, &out->second_ticket.length);
  if (rc < 0)
    return rc;

  if (*len < out->second_ticket.length)
    return -1;
  out->second_ticket.data = (char*) *data;
  *data += out->second_ticket.length;
  *len -= out->second_ticket.length;

  return 0;
}

int
ccache_parse (const char *data, size_t len, struct ccache *out)
{
  int rc;

  rc = get_uint16 (&data, &len, &out->file_format_version);
  if (rc < 0)
    return rc;

  rc = get_uint16 (&data, &len, &out->headerlen);
  if (rc < 0)
    return rc;

  if (len < out->headerlen)
    return -1;
  out->header = (char*) data;
  data += out->headerlen;
  len -= out->headerlen;

  rc = parse_principal (&data, &len, &out->default_principal);
  if (rc < 0)
    return rc;

  out->credentials = (char*) data;
  out->credentialslen = len;

  return 0;
}

int
ccache_parse_credential (const char *data, size_t len,
			 struct ccache_credential *out, size_t * n)
{
  size_t savelen = len;
  int rc = parse_credential (&data, &len, out);

  if (rc < 0)
    return rc;

  *n = savelen - len;
  return 0;
}

static int
pack_principal (struct ccache_principal *princ,
		char **out, size_t * len)

{
  size_t n;
  int rc;

  rc = put_uint32 (princ->name_type, out, len);
  if (rc < 0)
    return rc;

  rc = put_uint32 (princ->num_components, out, len);
  if (rc < 0)
    return rc;

  if (princ->num_components >= CCACHE_MAX_COMPONENTS)
    return -1;

  rc = put_uint32 (princ->realm.length, out, len);
  if (rc < 0)
    return rc;

  if (*len < princ->realm.length)
    return -1;
  memcpy (*out, princ->realm.data, princ->realm.length);
  *out += princ->realm.length;
  *len -= princ->realm.length;

  for (n = 0; n < princ->num_components; n++)
    {
      rc = put_uint32 (princ->components[n].length, out, len);
      if (rc < 0)
	return rc;

      if (*len < princ->components[n].length)
	return -1;
      memcpy (*out, princ->components[n].data, princ->components[n].length);
      *out += princ->components[n].length;
      *len -= princ->components[n].length;
    }

  return 0;
}

static int
pack_credential (struct ccache_credential *cred,
		 char **out, size_t *len)
{
  int rc;

  rc = pack_principal (&cred->client, out, len);
  if (rc < 0)
    return rc;

  rc = pack_principal (&cred->server, out, len);
  if (rc < 0)
    return rc;

  rc = put_uint16 (cred->key.keytype, out, len);
  if (rc < 0)
    return rc;

  rc = put_uint16 (cred->key.etype, out, len);
  if (rc < 0)
    return rc;

  rc = put_uint16 (cred->key.keylen, out, len);
  if (rc < 0)
    return rc;

  if (*len < cred->key.keylen)
    return -1;

  memcpy (*out, cred->key.keyvalue, cred->key.keylen);

  *out += cred->key.keylen;
  *len -= cred->key.keylen;

  rc = put_uint32 (cred->authtime, out, len);
  if (rc < 0)
    return rc;

  rc = put_uint32 (cred->starttime, out, len);
  if (rc < 0)
    return rc;

  rc = put_uint32 (cred->endtime, out, len);
  if (rc < 0)
    return rc;

  rc = put_uint32 (cred->renew_till, out, len);
  if (rc < 0)
    return rc;

  rc = put_uint8 (0, out, len);
  if (rc < 0)
    return rc;

  rc = put_uint32_swapped (cred->tktflags, out, len);
  if (rc < 0)
    return rc;

  /* XXX Write addresses. */
  rc = put_uint32 (0, out, len);
  if (rc < 0)
    return rc;

  /* XXX Write auth-data. */
  rc = put_uint32 (0, out, len);
  if (rc < 0)
    return rc;

  rc = put_uint32 (cred->ticket.length, out, len);
  if (rc < 0)
    return rc;

  if (*len < cred->ticket.length)
    return -1;
  memcpy (*out, cred->ticket.data, cred->ticket.length);
  *out += cred->ticket.length;
  *len -= cred->ticket.length;

  rc = put_uint32 (cred->second_ticket.length, out, len);
  if (rc < 0)
    return rc;

  if (*len < cred->second_ticket.length)
    return -1;
  memcpy (*out, cred->second_ticket.data, cred->second_ticket.length);
  *out += cred->second_ticket.length;
  *len -= cred->second_ticket.length;

  return 0;
}

int
ccache_pack_credential (struct ccache_credential *cred,
			char *out, size_t *len)
{
  size_t savelen = *len;
  int rc = pack_credential (cred, &out, len);

  if (rc < 0)
    return rc;

  *len = savelen - *len;
  return 0;
}

int
ccache_pack (struct ccache *info, char *data, size_t *len)
{
  size_t savelen = *len;
  int rc;

  rc = put_uint16 (info->file_format_version
		   ? info->file_format_version : 0x0504, &data, len);
  if (rc < 0)
    return rc;

  rc = put_uint16 (info->headerlen, &data, len);
  if (rc < 0)
    return rc;

  if (*len < info->headerlen)
    return -1;
  memcpy (data, info->header, info->headerlen);
  data += info->headerlen;
  *len -= info->headerlen;

  rc = pack_principal (&info->default_principal, &data, len);
  if (rc < 0)
    return rc;

  *len = savelen - *len;
  return 0;
}

void
ccache_print (struct ccache *ccache)
{
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
