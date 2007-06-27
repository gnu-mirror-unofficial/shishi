/* ccache.h --- Read MIT style Kerberos Credential Cache file.
 * Copyright (C) 2006, 2007  Simon Josefsson
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

#ifndef CCACHE_H
#define CCACHE_H 1

#include <stdint.h>
#include <string.h>

#define CCACHE_MAX_COMPONENTS 5
#define CCACHE_MAX_KEYLEN 32

struct ccache_header
{
  uint16_t tag;
  uint16_t taglen;
  char *tagdata;
};

struct ccache_buffer
{
  uint32_t length;
  char *data;
};

struct ccache_principal
{
  uint32_t name_type;
  uint32_t num_components;
  struct ccache_buffer realm;
  struct ccache_buffer components[CCACHE_MAX_COMPONENTS];
};

struct ccache_keyblock
{
  uint16_t keytype;
  uint16_t etype;
  uint16_t keylen;
  char *keyvalue;
  char storage[CCACHE_MAX_KEYLEN];  /* usable by caller for storing
				       keys that keyvalue point to. */
};

struct ccache_credential
{
  struct ccache_principal client;
  struct ccache_principal server;
  struct ccache_keyblock key;
  uint32_t authtime;
  uint32_t starttime;
  uint32_t endtime;
  uint32_t renew_till;
  uint8_t is_skey;
  uint32_t tktflags;
  struct ccache_buffer ticket;
  struct ccache_buffer second_ticket;
};

struct ccache
{
  uint16_t file_format_version;
  uint16_t headerlen;
  char *header;
  struct ccache_principal default_principal;
  size_t credentialslen;
  char *credentials;
};

extern int ccache_parse (const char *data, size_t length, struct ccache *out);

extern int ccache_parse_credential (const char *data, size_t len,
				    struct ccache_credential *out,
				    size_t * n);

extern int ccache_pack (struct ccache *info, char *data, size_t *len);
extern int ccache_pack_credential (struct ccache_credential *cred,
				   char *out, size_t *len);

extern void ccache_print (struct ccache *ccache);
extern void ccache_print_principal (struct ccache_principal *princ);
extern void ccache_print_credential (struct ccache_credential *cred);

#endif /* CCACHE_H */
