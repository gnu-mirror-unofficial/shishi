/* crypto.c	kerberos crypto self tests
 * Copyright (C) 2002  Simon Josefsson
 *
 * This file is part of Shishi.
 *
 * Shishi is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * Shishi is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with Shishi; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "shishi.h"
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#if HAVE_INTTYPES_H
# include <inttypes.h>
#else
# if HAVE_STDINT_H
#  include <stdint.h>
# endif
#endif
#include <stdarg.h>

static int verbose = 0;
static int error_count = 0;
static int break_on_error = 0;

static void
fail ( const char *format, ... )
{
  va_list arg_ptr ;

  va_start( arg_ptr, format ) ;
  vfprintf (stderr, format, arg_ptr );
  va_end(arg_ptr);
  error_count++;
  if (break_on_error)
    exit(1);
}

static void
escapeprint (unsigned char *str,
	     int len)
{
  int i;

  printf("\t ;; `");
  for (i = 0; i < len; i++)
    if ((str[i] >= 'A' && str[i] <= 'Z') ||
	(str[i] >= 'a' && str[i] <= 'z') ||
	(str[i] >= '0' && str[i] <= '9') ||
	str[i] == '.')
      printf("%c", str[i]);
    else
      printf("\\x%02x", str[i]);
  printf("' (length %d bytes)\n", len);
}

static void
hexprint (unsigned char *str,
	  int len)
{
  int i;

  printf("\t ;; ");
  for (i = 0; i < len; i++)
    {
      printf("%02x ", str[i]);
      if ((i+1)%8 == 0) printf(" ");
      if ((i+1)%16 == 0 && i+1 < len) printf("\n\t ;; ");
    }
}

static void
binprint (unsigned char *str,
	  int len)
{
  int i;

  printf("\t ;; ");
  for (i = 0; i < len; i++)
    {
      printf("%d%d%d%d%d%d%d%d ", 
	     str[i] & 0x80 ? 1 : 0,
	     str[i] & 0x40 ? 1 : 0,
	     str[i] & 0x20 ? 1 : 0,
	     str[i] & 0x10 ? 1 : 0,
	     str[i] & 0x08 ? 1 : 0,
	     str[i] & 0x04 ? 1 : 0,
	     str[i] & 0x02 ? 1 : 0,
	     str[i] & 0x01 ? 1 : 0);
      if ((i+1)%3 == 0) printf(" ");
      if ((i+1)%6 == 0 && i+1 < len) printf("\n\t ;; ");
    }
}

static void
bin7print (unsigned char *str,
	   int len)
{
  int i;

  printf("\t ;; ");
  for (i = 0; i < len; i++)
    {
      printf("%d%d%d%d%d%d%d ", 
	     str[i] & 0x40 ? 1 : 0,
	     str[i] & 0x20 ? 1 : 0,
	     str[i] & 0x10 ? 1 : 0,
	     str[i] & 0x08 ? 1 : 0,
	     str[i] & 0x04 ? 1 : 0,
	     str[i] & 0x02 ? 1 : 0,
	     str[i] & 0x01 ? 1 : 0);
      if ((i+1)%3 == 0) printf(" ");
      if ((i+1)%6 == 0 && i+1 < len) printf("\n\t ;; ");
    }
}

struct drdk {
  int type;
  char *key;
  int nusage;
  char *usage;
  char *dr;
  char *dk;
} drdk[] = {
  {
    SHISHI_DES3_CBC_HMAC_SHA1_KD,
    "\xd3\xf8\x29\x8c\xcb\x16\x64\x38\xdc\xb9\xb9\x3e"
    "\xe5\xa7\x62\x92\x86\xa4\x91\xf8\x38\xf8\x02\xfb",
    8,
    "kerberos",
    "\x22\x70\xdb\x56\x5d\x2a\x3d\x64\xcf\xbf"
    "\xdc\x53\x05\xd4\xf7\x78\xa6\xde\x42\xd9\xda",
    "\x23\x70\xda\x57\x5d\x2a\x3d\xa8\x64\xce\xbf\xdc"
    "\x52\x04\xd5\x6d\xf7\x79\xa7\xdf\x43\xd9\xda\x43",
  }, {
    SHISHI_DES3_CBC_HMAC_SHA1_KD,
    "\xdc\xe0\x6b\x1f\x64\xc8\x57\xa1\x1c\x3d\xb5\x7c"
    "\x51\x89\x9b\x2c\xc1\x79\x10\x08\xce\x97\x3b\x92",
    5,
    "\x00\x00\x00\x01\x55",
    "\x93\x50\x79\xd1\x44\x90\xa7\x5c\x30\x93"
    "\xc4\xa6\xe8\xc3\xb0\x49\xc7\x1e\x6e\xe7\x05",
    "\x92\x51\x79\xd0\x45\x91\xa7\x9b\x5d\x31\x92\xc4"
    "\xa7\xe9\xc2\x89\xb0\x49\xc7\x1f\x6e\xe6\x04\xcd"
  }, {
    SHISHI_DES3_CBC_HMAC_SHA1_KD,
    "\x5e\x13\xd3\x1c\x70\xef\x76\x57\x46\x57\x85\x31"
    "\xcb\x51\xc1\x5b\xf1\x1c\xa8\x2c\x97\xce\xe9\xf2",
    5,
    "\x00\x00\x00\x01\xaa",
    "\x9f\x58\xe5\xa0\x47\xd8\x94\x10\x1c\x46"
    "\x98\x45\xd6\x7a\xe3\xc5\x24\x9e\xd8\x12\xf2",
    "\x9e\x58\xe5\xa1\x46\xd9\x94\x2a\x10\x1c\x46\x98"
    "\x45\xd6\x7a\x20\xe3\xc4\x25\x9e\xd9\x13\xf2\x07",
  }, {
    SHISHI_DES3_CBC_HMAC_SHA1_KD,
    "\x98\xe6\xfd\x8a\x04\xa4\xb6\x85\x9b\x75\xa1\x76"
    "\x54\x0b\x97\x52\xba\xd3\xec\xd6\x10\xa2\x52\xbc",
    5,
    "\x00\x00\x00\x01\x55",
    "\x12\xff\xf9\x0c\x77\x3f\x95\x6d\x13\xfc"
    "\x2c\xa0\xd0\x84\x03\x49\xdb\xd3\x99\x08\xeb",
    "\x13\xfe\xf8\x0d\x76\x3e\x94\xec\x6d\x13\xfd\x2c"
    "\xa1\xd0\x85\x07\x02\x49\xda\xd3\x98\x08\xea\xbf",
  }, {
    SHISHI_DES3_CBC_HMAC_SHA1_KD,
    "\x62\x2a\xec\x25\xa2\xfe\x2c\xad\x70\x94\x68\x0b"
    "\x7c\x64\x94\x02\x80\x08\x4c\x1a\x7c\xec\x92\xb5",
    5,
    "\x00\x00\x00\x01\xaa",
    "\xf8\xde\xbf\x05\xb0\x97\xe7\xdc\x06\x03"
    "\x68\x6a\xca\x35\xd9\x1f\xd9\xa5\x51\x6a\x70",
    "\xf8\xdf\xbf\x04\xb0\x97\xe6\xd9\xdc\x07\x02\x68"
    "\x6b\xcb\x34\x89\xd9\x1f\xd9\xa4\x51\x6b\x70\x3e",
  }, {
    SHISHI_DES3_CBC_HMAC_SHA1_KD,
    "\xc1\x08\x16\x49\xad\xa7\x43\x62\xe6\xa1\x45\x9d"
    "\x01\xdf\xd3\x0d\x67\xc2\x23\x4c\x94\x07\x04\xda",
    5,
    "\x00\x00\x00\x01\x55",
    "\x34\x80\x56\xec\x98\xfc\xc5\x17\x17\x1d"
    "\x2b\x4d\x7a\x94\x93\xaf\x48\x2d\x99\x91\x75",
    "\x34\x80\x57\xec\x98\xfd\xc4\x80\x16\x16\x1c\x2a"
    "\x4c\x7a\x94\x3e\x92\xae\x49\x2c\x98\x91\x75\xf7",
  }, {
    SHISHI_DES3_CBC_HMAC_SHA1_KD,
    "\x5d\x15\x4a\xf2\x38\xf4\x67\x13\x15\x57\x19\xd5"
    "\x5e\x2f\x1f\x79\x0d\xd6\x61\xf2\x79\xa7\x91\x7c",
    5,
    "\x00\x00\x00\x01\xaa",
    "\xa8\x81\x8b\xc3\x67\xda\xda\xcb\xe9\xa6"
    "\xc8\x46\x27\xfb\x60\xc2\x94\xb0\x12\x15\xe5",
    "\xa8\x80\x8a\xc2\x67\xda\xda\x3d\xcb\xe9\xa7\xc8"
    "\x46\x26\xfb\xc7\x61\xc2\x94\xb0\x13\x15\xe5\xc1",
  }, {
    SHISHI_DES3_CBC_HMAC_SHA1_KD,
    "\x79\x85\x62\xe0\x49\x85\x2f\x57\xdc\x8c\x34\x3b"
    "\xa1\x7f\x2c\xa1\xd9\x73\x94\xef\xc8\xad\xc4\x43",
    5,
    "\x00\x00\x00\x01\x55",
    "\xc8\x13\xf8\x8b\x3b\xe2\xb2\xf7\x54\x24"
    "\xce\x91\x75\xfb\xc8\x48\x3b\x88\xc8\x71\x3a",
    "\xc8\x13\xf8\x8a\x3b\xe3\xb3\x34\xf7\x54\x25\xce"
    "\x91\x75\xfb\xe3\xc8\x49\x3b\x89\xc8\x70\x3b\x49",
  }, {
    SHISHI_DES3_CBC_HMAC_SHA1_KD,
    "\x26\xdc\xe3\x34\xb5\x45\x29\x2f\x2f\xea\xb9\xa8"
    "\x70\x1a\x89\xa4\xb9\x9e\xb9\x94\x2c\xec\xd0\x16",
    5,
    "\x00\x00\x00\x01\xaa",
    "\xf5\x8e\xfc\x6f\x83\xf9\x3e\x55\xe6\x95"
    "\xfd\x25\x2c\xf8\xfe\x59\xf7\xd5\xba\x37\xec",
    "\xf4\x8f\xfd\x6e\x83\xf8\x3e\x73\x54\xe6\x94\xfd"
    "\x25\x2c\xf8\x3b\xfe\x58\xf7\xd5\xba\x37\xec\x5d",
  }
};

struct nfold {
  int n;
  char *in;
  char *out;
} nfold[] = {
  { 64, "012345", "\xBE\x07\x26\x31\x27\x6B\x19\x55" },
  { 56, "password", "\x78\xA0\x7B\x6C\xAF\x85\xFA" },
  { 64, "Rough Consensus, and Running Code", 
    "\xBB\x6E\xD3\x08\x70\xB7\xF0\xE0" },
  { 168, "password", 
    "\x59\xE4\xA8\xCA\x7C\x03\x85\xC3\xC3\x7B"
    "\x3F\x6D\x20\x00\x24\x7C\xB6\xE6\xBD\x5B\x3E" },
  { 192, "MASSACHVSETTS INSTITVTE OF TECHNOLOGY",
    "\xDB\x3B\x0D\x8F\x0B\x06\x1E\x60\x32\x82\xB3\x08"
    "\xA5\x08\x41\x22\x9A\xD7\x98\xFA\xB9\x54\x0C\x1B" },
  { 64, "kerberos",
    "\x6b\x65\x72\x62\x65\x72\x6f\x73" },
  { 128, "kerberos",
    "\x6b\x65\x72\x62\x65\x72\x6f\x73\x7b\x9b\x5b\x2b\x93\x13\x2b\x93" },
  { 168, "kerberos",
    "\x83\x72\xc2\x36\x34\x4e\x5f\x15\x50\xcd"
    "\x07\x47\xe1\x5d\x62\xca\x7a\x5a\x3b\xce\xa4" },
  { 256, "kerberos",
    "\x6b\x65\x72\x62\x65\x72\x6f\x73\x7b\x9b\x5b\x2b\x93\x13\x2b\x93"
    "\x5c\x9b\xdc\xda\xd9\x5c\x98\x99\xc4\xca\xe4\xde\xe6\xd6\xca\xe4" },
  { 168, "Q",
    "\x51\x8a\x54\xa2\x15\xa8\x45\x2a\x51\x8a"
    "\x54\xa2\x15\xa8\x45\x2a\x51\x8a\x54\xa2\x15" },
  { 192, "Q",
    "\x51\x8a\x54\xa2\x15\xa8\x45\x2a\x51\x8a\x54\xa2"
    "\x15\xa8\x45\x2a\x51\x8a\x54\xa2\x15\xa8\x45\x2a" },
  { 168, "ab",
    "\xba\x24\xcf\x29\x7f\x49\xf5\x4b\xab\x62"
    "\x5d\x12\xe7\x94\x3f\xa4\xfb\x25\xd5\x31\xae" },
  { 192, "ab",
    "\x61\x62\x0b\x13\x58\x98\xc4\xc2\x26\x16\x30\xb1"
    "\x85\x89\x2c\x4c\x62\x61\x13\x0b\x98\x58\xc2\xc4" }
};

struct crc32 {
  char *in;
  int len;
  uint32_t crc32;
} crc32[] = {
  { "foo", 3, 0x7332bc33 },
  { "test0123456789", 14, 0xb83e88d6 },
  { "MASSACHVSETTS INSTITVTE OF TECHNOLOGY", 37, 0xe34180f7 },
  { "\x80\x00", 2, 0x3b83984b },
  { "\x00\x08", 2, 0x0edb8832 },
  { "\x00\x80", 2, 0xedb88320 },
  { "\x80", 1, 0xedb88320 },
  { "\x80\x00\x00\x00", 4, 0xed59b63b },
  { "\x00\x00\x00\x01", 4, 0x77073096 }
};

struct str2key {
  char *password;
  char *salt;
  char *key;
  int etype;
} str2key[] = { 
#define ESZETT "\xC3\x9F"
#define S_CARON "\xC5\xA1"
#define C_ACUTE "\xC4\x87"
#define G_CLEF "\xF0\x9D\x84\x9E"
  { "password", 
    "ATHENA.MIT.EDUraeburn", 
    "\xCB\xC2\x2F\xAE\x23\x52\x98\xE3",
    SHISHI_DES_CBC_MD5 },
  { "potatoe", 
    "WHITEHOUSE.GOVdanny", 
    "\xDF\x3D\x32\xA7\x4F\xD9\x2A\x01",
    SHISHI_DES_CBC_MD5 },
  { "\xF0\x9D\x84\x9E", 
    "EXAMPLE.COMpianist", 
    "\x4F\xFB\x26\xBA\xB0\xCD\x94\x13",
    SHISHI_DES_CBC_MD5 },
  { ESZETT, 
    "ATHENA.MIT.EDUJuri" S_CARON "i" C_ACUTE, 
    "\x62\xC8\x1A\x52\x32\xB5\xE6\x9D",
    SHISHI_DES_CBC_MD5 },
  { "11119999", 
    "AAAAAAAA",
    "\x98\x40\x54\xD0\xF1\xA7\x3E\x31",
    SHISHI_DES_CBC_MD5 }, 
  { "NNNN6666", 
    "FFFFAAAA", 
    "\xC4\xBF\x6B\x25\xAD\xF7\xA4\xF8",
    SHISHI_DES_CBC_MD5 },
  { "password",
    "ATHENA.MIT.EDUraeburn",
    "\x85\x0b\xb5\x13\x58\x54\x8c\xd0\x5e\x86\x76\x8c"
    "\x31\x3e\x3b\xfe\xf7\x51\x19\x37\xdc\xf7\x2c\x3e",
    SHISHI_DES3_CBC_HMAC_SHA1_KD },
  { "potatoe",
    "WHITEHOUSE.GOVdanny",
    "\xdf\xcd\x23\x3d\xd0\xa4\x32\x04\xea\x6d\xc4\x37"
    "\xfb\x15\xe0\x61\xb0\x29\x79\xc1\xf7\x4f\x37\x7a",
    SHISHI_DES3_CBC_HMAC_SHA1_KD },
  { "penny",
    "EXAMPLE.COMbuckaroo",
    "\x6d\x2f\xcd\xf2\xd6\xfb\xbc\x3d\xdc\xad\xb5\xda"
    "\x57\x10\xa2\x34\x89\xb0\xd3\xb6\x9d\x5d\x9d\x4a",
    SHISHI_DES3_CBC_HMAC_SHA1_KD },
  { ESZETT,
    "ATHENA.MIT.EDUJuri" S_CARON "i" C_ACUTE,
    "\x16\xd5\xa4\x0e\x1c\xe3\xba\xcb\x61\xb9\xdc\xe0"
    "\x04\x70\x32\x4c\x83\x19\x73\xa7\xb9\x52\xfe\xb0",
    SHISHI_DES3_CBC_HMAC_SHA1_KD },
  { G_CLEF,
    "EXAMPLE.COMpianist",
    "\x85\x76\x37\x26\x58\x5d\xbc\x1c\xce\x6e\xc4\x3e"
    "\x1f\x75\x1f\x07\xf1\xc4\xcb\xb0\x98\xf4\x0b\x19",
    SHISHI_DES3_CBC_HMAC_SHA1_KD }
};

int
main (int argc, char *argv[])
{
  Shishi *handle;
  unsigned char key[3*8];
  unsigned char out[BUFSIZ];
  int i,j;
  int res;

  do
    if (strcmp (argv[argc-1], "-v") == 0 ||
	strcmp (argv[argc-1], "--verbose") == 0)
      verbose = 1;
    else if (strcmp (argv[argc-1], "-b") == 0 ||
	     strcmp (argv[argc-1], "--break-on-error") == 0)
      break_on_error = 1;
    else if (strcmp (argv[argc-1], "-h") == 0 ||
	     strcmp (argv[argc-1], "-?") == 0 ||
	     strcmp (argv[argc-1], "--help") == 0)
      {
	printf("Usage: %s [-vbh?] [--verbose] [--break-on-error] [--help]\n", 
	       argv[0]);
	return 1;
      }
  while (argc-- > 1);

  handle = shishi_init ();
  if (handle == NULL)
    {
      fail("Could not initialize shishi\n");
      return 1;
    }

  if (verbose)
    shishi_cfg(handle, strdup("verbose,debug"));

  for (i = 0; i < sizeof(drdk) / sizeof(drdk[0]); i++)
    {
      if (verbose)
	printf("DR entry %d\n", i);

      res = shishi_dr (handle, drdk[i].type, 
		       drdk[i].key, strlen(drdk[i].key),
		       drdk[i].usage, drdk[i].nusage,
		       out, strlen(drdk[i].dr));
      if (res != SHISHI_OK)
	{
	  fail("shishi_dr() entry %d failed (%s)\n", 
	       i, shishi_strerror_details(handle));
	  continue;
	}

      if (verbose)
	{
	  printf("DR(%s, key, usage)\n", 
		 shishi_cipher_name(drdk[i].type));

	  printf("key:\n");
	  escapeprint(drdk[i].key, strlen(drdk[i].key));
	  hexprint(drdk[i].key, strlen(drdk[i].key)); puts("");
	  binprint(drdk[i].key, strlen(drdk[i].key)); puts("");

	  printf("usage:\n");
	  escapeprint(drdk[i].usage, drdk[i].nusage);
	  hexprint(drdk[i].usage, drdk[i].nusage); puts("");
	  binprint(drdk[i].usage, drdk[i].nusage); puts("");

	  printf("computed DR:\n");
	  escapeprint(out, strlen(drdk[i].dr));
	  hexprint(out, strlen(drdk[i].dr)); puts("");
	  binprint(out, strlen(drdk[i].dr)); puts("");

	  printf("expected DR:\n");
	  escapeprint(drdk[i].dr, strlen(drdk[i].dr));
	  hexprint(drdk[i].dr, strlen(drdk[i].dr)); puts("");
	  binprint(drdk[i].dr, strlen(drdk[i].dr)); puts("");
	}

      if (memcmp (drdk[i].dr, out, strlen(drdk[i].dr)) != 0)
	{
	  fail("shishi_dr() entry %d failed\n", i);
	  if (verbose)
	    printf("ERROR\n");
	}
      else if (verbose)
	printf("OK\n");

      res = shishi_dk (handle, drdk[i].type, 
		       drdk[i].key, strlen(drdk[i].key),
		       drdk[i].usage, drdk[i].nusage,
		       out, strlen(drdk[i].dk));
      if (res != SHISHI_OK)
	{
	  fail("shishi_dk() entry %d failed (%s)\n", 
	       i, shishi_strerror_details(handle));
	  continue;
	}

      if (verbose)
	{
	  printf("DK(%s, key, usage)\n", 
		 shishi_cipher_name(drdk[i].type));

	  printf("key:\n");
	  escapeprint(drdk[i].key, strlen(drdk[i].key));
	  hexprint(drdk[i].key, strlen(drdk[i].key)); puts("");
	  binprint(drdk[i].key, strlen(drdk[i].key)); puts("");

	  printf("usage:\n");
	  escapeprint(drdk[i].usage, drdk[i].nusage);
	  hexprint(drdk[i].usage, drdk[i].nusage); puts("");
	  binprint(drdk[i].usage, drdk[i].nusage); puts("");

	  printf("computed DK:\n");
	  escapeprint(out, strlen(drdk[i].dr));
	  hexprint(out, strlen(drdk[i].dr)); puts("");
	  binprint(out, strlen(drdk[i].dr)); puts("");

	  printf("expected DK:\n");
	  escapeprint(drdk[i].dk, strlen(drdk[i].dk));
	  hexprint(drdk[i].dk, strlen(drdk[i].dk)); puts("");
	  binprint(drdk[i].dk, strlen(drdk[i].dk)); puts("");
	}

      if (memcmp (drdk[i].dk, out, strlen(drdk[i].dk)) != 0)
	{
	  fail("shishi_dk() entry %d failed\n", i);
	  if (verbose)
	    printf("ERROR\n");
	}
      else if (verbose)
	printf("OK\n");
    }

  for (i = 0; i < sizeof(nfold) / sizeof(nfold[0]); i++)
    {
      if (verbose)
	printf("N-FOLD entry %d\n", i);

      res = shishi_n_fold (handle, 
			   nfold[i].in, strlen(nfold[i].in),
			   out, nfold[i].n / 8);
      if (res != SHISHI_OK)
	{
	  fail("shishi_n_fold() entry %d failed (%s)\n", 
	       i, shishi_strerror_details(handle));
	  continue;
	}

      if (verbose)
	{
	  printf("in:\n");
	  escapeprint(nfold[i].in, strlen(nfold[i].in));
	  hexprint(nfold[i].in, strlen(nfold[i].in)); puts("");
	  binprint(nfold[i].in, strlen(nfold[i].in)); puts("");

	  printf("out:\n");
	  escapeprint(out, nfold[i].n / 8);
	  hexprint(out, nfold[i].n / 8); puts("");
	  binprint(out, nfold[i].n / 8); puts("");

	  printf("expected out:\n");
	  escapeprint(nfold[i].out, nfold[i].n / 8);
	  hexprint(nfold[i].out, nfold[i].n / 8); puts("");
	  binprint(nfold[i].out, nfold[i].n / 8); puts("");
	}

      if (memcmp (nfold[i].out, out, nfold[i].n / 8) != 0)
	{
	  fail("shishi_n_fold() entry %d failed\n", i);
	  if (verbose)
	    printf("ERROR\n");
	}
      else if (verbose)
	printf("OK\n");
    }

  for (i = 0; i < sizeof(str2key) / sizeof(str2key[0]); i++)
    {
      int n_password = strlen(str2key[i].password);
      int saltlen = strlen(str2key[i].salt);
      int keylen = sizeof(key);

      if (verbose)
	printf("STRING-TO-KEY entry %d\n", i);

      res = shishi_string_to_key (handle, str2key[i].etype,
				  str2key[i].password, n_password,
				  str2key[i].salt, saltlen, key, &keylen);
      if (res != SHISHI_OK)
	{
	  fail("shishi_string_to_key() entry %d failed (%s)\n", 
	       i, shishi_strerror_details(handle));
	  continue;
	}

      if (verbose)
	{
	  printf("password:\n");
	  escapeprint(str2key[i].password, n_password);
	  hexprint(str2key[i].password, n_password); puts("");
	  binprint(str2key[i].password, n_password); puts("");

	  printf("salt:\n");
	  escapeprint(str2key[i].salt, saltlen);
	  hexprint(str2key[i].password, saltlen); puts("");
	  binprint(str2key[i].password, saltlen); puts("");

	  printf("computed key:\n");
	  escapeprint(key, keylen);
	  hexprint(key, keylen); puts("");
	  binprint(key, keylen); puts("");

	  printf("expected key:\n");
	  escapeprint(str2key[i].key, strlen(str2key[i].key));
	  hexprint(str2key[i].key, strlen(str2key[i].key)); puts("");
	  binprint(str2key[i].key, strlen(str2key[i].key)); puts("");
	}

      if (memcmp (str2key[i].key, key, keylen) != 0)
	{
	  fail("shishi_string_to_key() entry %d failed\n", i);
	    
	  if (verbose)
	    printf("ERROR\n");
	}
      else if (verbose)
	printf("OK\n");
    }

  for (i = 0; i < sizeof(crc32) / sizeof(crc32[0]); i++)
    {
      uint32_t crc;

      if (verbose)
	printf("MOD-CRC32 entry %d\n", i);

      crc =  shishi_mod_crc32 (crc32[i].in, crc32[i].len);

      if (verbose)
	{
	  printf("in:\n");
	  escapeprint(crc32[i].in, crc32[i].len);
	  hexprint(crc32[i].in, crc32[i].len); puts("");
	  binprint(crc32[i].in, crc32[i].len); puts("");

	  printf("computed mod-crc32: %08x\n", crc);

	  printf("expected mod-crc32: %08x\n", crc32[i].crc32);
	}

      if (crc != crc32[i].crc32)
	{
	  fail("shishi_mod_crc32() entry %d failed\n", i);
	    
	  if (verbose)
	    printf("ERROR\n");
	}
      else if (verbose)
	printf("OK\n");
    }

  if (verbose)
    printf("Crypt self tests done with %d errors\n", error_count);

  return error_count ? 1 : 0;
}
