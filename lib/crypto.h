/* crypto.h	internal crypto header file
 * Copyright (C) 2002, 2003  Simon Josefsson
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

#ifndef _CRYPTO_H
#define _CRYPTO_H

int
_shishi_simplified_derivekey (Shishi * handle,
			      Shishi_key * key,
			      int keyusage,
			      int derivekeymode, Shishi_key ** outkey);
int
_shishi_simplified_checksum (Shishi * handle,
			     Shishi_key * key,
			     int keyusage,
			     int cksumtype,
			     const char *in, size_t inlen,
			     char **out, size_t * outlen);
int
_shishi_simplified_dencrypt (Shishi * handle,
			     Shishi_key * key,
			     const char *iv, size_t ivlen,
			     char **ivout, size_t * ivoutlen,
			     const char *in, size_t inlen,
			     char **out, size_t * outlen, int decryptp);
int
_shishi_simplified_encrypt (Shishi * handle,
			    Shishi_key * key,
			    int keyusage,
			    const char *iv, size_t ivlen,
			    char **ivout, size_t * ivoutlen,
			    const char *in, size_t inlen,
			    char **out, size_t * outlen);
int
_shishi_simplified_decrypt (Shishi * handle,
			    Shishi_key * key,
			    int keyusage,
			    const char *iv, size_t ivlen,
			    char **ivout, size_t * ivoutlen,
			    const char *in, size_t inlen,
			    char **out, size_t * outlen);

typedef enum
{
  SHISHI_DERIVEKEYMODE_CHECKSUM,
  SHISHI_DERIVEKEYMODE_PRIVACY,
  SHISHI_DERIVEKEYMODE_INTEGRITY
}
Shishi_derivekeymode;

typedef int (*Shishi_random_to_key_function) (Shishi * handle,
					      const char *random,
					      size_t randomlen,
					      Shishi_key * outkey);

typedef int (*Shishi_string_to_key_function) (Shishi * handle,
					      const char *password,
					      size_t passwordlen,
					      const char *salt,
					      size_t saltlen,
					      const char *parameter,
					      Shishi_key * outkey);

typedef int (*Shishi_encrypt_function) (Shishi * handle,
					Shishi_key * key,
					int keyusage,
					const char *iv, size_t ivlen,
					char **ivout, size_t * ivoutlen,
					const char *in, size_t inlen,
					char **out, size_t * outlen);

typedef int (*Shishi_decrypt_function) (Shishi * handle,
					Shishi_key * key,
					int keyusage,
					const char *iv, size_t ivlen,
					char **ivout, size_t * ivoutlen,
					const char *in, size_t inlen,
					char **out, size_t * outlen);

typedef int (*Shishi_checksum_function) (Shishi * handle,
					 Shishi_key * key,
					 int keyusage,
					 int cksumtype,
					 const char *in, size_t inlen,
					 char **out, size_t * outlen);

typedef int (*Shishi_verify_function) (Shishi * handle,
				       Shishi_key * key,
				       int keyusage,
				       int cksumtype,
				       const char *in, size_t inlen,
				       const char *cksum, size_t cksumlen);

struct cipherinfo
{
  int32_t type;
  char *name;
  int blocksize;
  int minpadsize;
  int confoundersize;
  int keylen;
  int randomlen;
  int defaultcksumtype;
  Shishi_random_to_key_function random2key;
  Shishi_string_to_key_function string2key;
  Shishi_encrypt_function encrypt;
  Shishi_decrypt_function decrypt;
};
typedef struct cipherinfo cipherinfo;

struct checksuminfo
{
  int32_t type;
  char *name;
  int cksumlen;
  Shishi_checksum_function checksum;
  Shishi_verify_function verify;
};
typedef struct checksuminfo checksuminfo;

extern cipherinfo null_info;

extern checksuminfo md4_info;
extern checksuminfo md5_info;

extern cipherinfo des_cbc_crc_info;
extern cipherinfo des_cbc_md4_info;
extern cipherinfo des_cbc_md5_info;
extern cipherinfo des_cbc_none_info;
extern checksuminfo md4_des_info;
extern checksuminfo md5_des_info;
extern checksuminfo md5_gss_info;

extern cipherinfo des3_cbc_none_info;
extern cipherinfo des3_cbc_sha1_kd_info;
extern checksuminfo hmac_sha1_des3_kd_info;

extern cipherinfo aes128_cts_hmac_sha1_96_info;
extern cipherinfo aes256_cts_hmac_sha1_96_info;
extern checksuminfo hmac_sha1_96_aes128_info;
extern checksuminfo hmac_sha1_96_aes256_info;

extern cipherinfo arcfour_hmac_info;
extern cipherinfo arcfour_hmac_exp_info;
extern checksuminfo arcfour_hmac_md5_info;

#endif
