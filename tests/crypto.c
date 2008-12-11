/* crypto.c --- Shishi crypto self tests.
 * Copyright (C) 2002, 2003, 2004, 2006, 2007, 2008  Simon Josefsson
 *
 * This file is part of Shishi.
 *
 * Shishi is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * Shishi is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Shishi; if not, see http://www.gnu.org/licenses or write
 * to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
 * Floor, Boston, MA 02110-1301, USA
 *
 */

#include "utils.c"

struct drdk
{
  int type;
  const char *key;
  int nusage;
  const char *usage;
  const char *dr;
  const char *dk;
};
const struct drdk drdk[] = {
#if WITH_3DES
  {SHISHI_DES3_CBC_HMAC_SHA1_KD,
   "\xd3\xf8\x29\x8c\xcb\x16\x64\x38\xdc\xb9\xb9\x3e"
   "\xe5\xa7\x62\x92\x86\xa4\x91\xf8\x38\xf8\x02\xfb",
   8,
   "kerberos",
   "\x22\x70\xdb\x56\x5d\x2a\x3d\x64\xcf\xbf"
   "\xdc\x53\x05\xd4\xf7\x78\xa6\xde\x42\xd9\xda",
   "\x23\x70\xda\x57\x5d\x2a\x3d\xa8\x64\xce\xbf\xdc"
   "\x52\x04\xd5\x6d\xf7\x79\xa7\xdf\x43\xd9\xda\x43"},
  {SHISHI_DES3_CBC_HMAC_SHA1_KD,
   "\xdc\xe0\x6b\x1f\x64\xc8\x57\xa1\x1c\x3d\xb5\x7c"
   "\x51\x89\x9b\x2c\xc1\x79\x10\x08\xce\x97\x3b\x92",
   5,
   "\x00\x00\x00\x01\x55",
   "\x93\x50\x79\xd1\x44\x90\xa7\x5c\x30\x93"
   "\xc4\xa6\xe8\xc3\xb0\x49\xc7\x1e\x6e\xe7\x05",
   "\x92\x51\x79\xd0\x45\x91\xa7\x9b\x5d\x31\x92\xc4"
   "\xa7\xe9\xc2\x89\xb0\x49\xc7\x1f\x6e\xe6\x04\xcd"},
  {SHISHI_DES3_CBC_HMAC_SHA1_KD,
   "\x5e\x13\xd3\x1c\x70\xef\x76\x57\x46\x57\x85\x31"
   "\xcb\x51\xc1\x5b\xf1\x1c\xa8\x2c\x97\xce\xe9\xf2",
   5,
   "\x00\x00\x00\x01\xaa",
   "\x9f\x58\xe5\xa0\x47\xd8\x94\x10\x1c\x46"
   "\x98\x45\xd6\x7a\xe3\xc5\x24\x9e\xd8\x12\xf2",
   "\x9e\x58\xe5\xa1\x46\xd9\x94\x2a\x10\x1c\x46\x98"
   "\x45\xd6\x7a\x20\xe3\xc4\x25\x9e\xd9\x13\xf2\x07"},
  {SHISHI_DES3_CBC_HMAC_SHA1_KD,
   "\x98\xe6\xfd\x8a\x04\xa4\xb6\x85\x9b\x75\xa1\x76"
   "\x54\x0b\x97\x52\xba\xd3\xec\xd6\x10\xa2\x52\xbc",
   5,
   "\x00\x00\x00\x01\x55",
   "\x12\xff\xf9\x0c\x77\x3f\x95\x6d\x13\xfc"
   "\x2c\xa0\xd0\x84\x03\x49\xdb\xd3\x99\x08\xeb",
   "\x13\xfe\xf8\x0d\x76\x3e\x94\xec\x6d\x13\xfd\x2c"
   "\xa1\xd0\x85\x07\x02\x49\xda\xd3\x98\x08\xea\xbf"},
  {SHISHI_DES3_CBC_HMAC_SHA1_KD,
   "\x62\x2a\xec\x25\xa2\xfe\x2c\xad\x70\x94\x68\x0b"
   "\x7c\x64\x94\x02\x80\x08\x4c\x1a\x7c\xec\x92\xb5",
   5,
   "\x00\x00\x00\x01\xaa",
   "\xf8\xde\xbf\x05\xb0\x97\xe7\xdc\x06\x03"
   "\x68\x6a\xca\x35\xd9\x1f\xd9\xa5\x51\x6a\x70",
   "\xf8\xdf\xbf\x04\xb0\x97\xe6\xd9\xdc\x07\x02\x68"
   "\x6b\xcb\x34\x89\xd9\x1f\xd9\xa4\x51\x6b\x70\x3e"},
  {SHISHI_DES3_CBC_HMAC_SHA1_KD,
   "\xc1\x08\x16\x49\xad\xa7\x43\x62\xe6\xa1\x45\x9d"
   "\x01\xdf\xd3\x0d\x67\xc2\x23\x4c\x94\x07\x04\xda",
   5,
   "\x00\x00\x00\x01\x55",
   "\x34\x80\x56\xec\x98\xfc\xc5\x17\x17\x1d"
   "\x2b\x4d\x7a\x94\x93\xaf\x48\x2d\x99\x91\x75",
   "\x34\x80\x57\xec\x98\xfd\xc4\x80\x16\x16\x1c\x2a"
   "\x4c\x7a\x94\x3e\x92\xae\x49\x2c\x98\x91\x75\xf7"},
  {SHISHI_DES3_CBC_HMAC_SHA1_KD,
   "\x5d\x15\x4a\xf2\x38\xf4\x67\x13\x15\x57\x19\xd5"
   "\x5e\x2f\x1f\x79\x0d\xd6\x61\xf2\x79\xa7\x91\x7c",
   5,
   "\x00\x00\x00\x01\xaa",
   "\xa8\x81\x8b\xc3\x67\xda\xda\xcb\xe9\xa6"
   "\xc8\x46\x27\xfb\x60\xc2\x94\xb0\x12\x15\xe5",
   "\xa8\x80\x8a\xc2\x67\xda\xda\x3d\xcb\xe9\xa7\xc8"
   "\x46\x26\xfb\xc7\x61\xc2\x94\xb0\x13\x15\xe5\xc1"},
  {SHISHI_DES3_CBC_HMAC_SHA1_KD,
   "\x79\x85\x62\xe0\x49\x85\x2f\x57\xdc\x8c\x34\x3b"
   "\xa1\x7f\x2c\xa1\xd9\x73\x94\xef\xc8\xad\xc4\x43",
   5,
   "\x00\x00\x00\x01\x55",
   "\xc8\x13\xf8\x8b\x3b\xe2\xb2\xf7\x54\x24"
   "\xce\x91\x75\xfb\xc8\x48\x3b\x88\xc8\x71\x3a",
   "\xc8\x13\xf8\x8a\x3b\xe3\xb3\x34\xf7\x54\x25\xce"
   "\x91\x75\xfb\xe3\xc8\x49\x3b\x89\xc8\x70\x3b\x49"},
  {SHISHI_DES3_CBC_HMAC_SHA1_KD,
   "\x26\xdc\xe3\x34\xb5\x45\x29\x2f\x2f\xea\xb9\xa8"
   "\x70\x1a\x89\xa4\xb9\x9e\xb9\x94\x2c\xec\xd0\x16",
   5,
   "\x00\x00\x00\x01\xaa",
   "\xf5\x8e\xfc\x6f\x83\xf9\x3e\x55\xe6\x95"
   "\xfd\x25\x2c\xf8\xfe\x59\xf7\xd5\xba\x37\xec",
   "\xf4\x8f\xfd\x6e\x83\xf8\x3e\x73\x54\xe6\x94\xfd"
   "\x25\x2c\xf8\x3b\xfe\x58\xf7\xd5\xba\x37\xec\x5d"}
#endif
};

struct nfold
{
  int n;
  const char *in;
  const char *out;
};
const struct nfold nfold[] = {
  {64, "012345", "\xBE\x07\x26\x31\x27\x6B\x19\x55"},
  {56, "password", "\x78\xA0\x7B\x6C\xAF\x85\xFA"},
  {64, "Rough Consensus, and Running Code",
   "\xBB\x6E\xD3\x08\x70\xB7\xF0\xE0"},
  {168, "password", "\x59\xE4\xA8\xCA\x7C\x03\x85\xC3\xC3\x7B"
   "\x3F\x6D\x20\x00\x24\x7C\xB6\xE6\xBD\x5B\x3E"},
  {192, "MASSACHVSETTS INSTITVTE OF TECHNOLOGY",
   "\xDB\x3B\x0D\x8F\x0B\x06\x1E\x60\x32\x82\xB3\x08"
   "\xA5\x08\x41\x22\x9A\xD7\x98\xFA\xB9\x54\x0C\x1B"},
  {64, "kerberos", "\x6b\x65\x72\x62\x65\x72\x6f\x73"},
  {128, "kerberos",
   "\x6b\x65\x72\x62\x65\x72\x6f\x73\x7b\x9b\x5b\x2b\x93\x13\x2b\x93"},
  {168, "kerberos",
   "\x83\x72\xc2\x36\x34\x4e\x5f\x15\x50\xcd"
   "\x07\x47\xe1\x5d\x62\xca\x7a\x5a\x3b\xce\xa4"},
  {256, "kerberos",
   "\x6b\x65\x72\x62\x65\x72\x6f\x73\x7b\x9b\x5b\x2b\x93\x13\x2b\x93"
   "\x5c\x9b\xdc\xda\xd9\x5c\x98\x99\xc4\xca\xe4\xde\xe6\xd6\xca\xe4"},
  {168, "Q",
   "\x51\x8a\x54\xa2\x15\xa8\x45\x2a\x51\x8a"
   "\x54\xa2\x15\xa8\x45\x2a\x51\x8a\x54\xa2\x15"},
  {192, "Q",
   "\x51\x8a\x54\xa2\x15\xa8\x45\x2a\x51\x8a\x54\xa2"
   "\x15\xa8\x45\x2a\x51\x8a\x54\xa2\x15\xa8\x45\x2a"},
  {168, "ab",
   "\xba\x24\xcf\x29\x7f\x49\xf5\x4b\xab\x62"
   "\x5d\x12\xe7\x94\x3f\xa4\xfb\x25\xd5\x31\xae"},
  {192, "ab",
   "\x61\x62\x0b\x13\x58\x98\xc4\xc2\x26\x16\x30\xb1"
   "\x85\x89\x2c\x4c\x62\x61\x13\x0b\x98\x58\xc2\xc4"}
};

struct str2key
{
  const char *password;
  const char *salt;
  const char *key;
  int etype;
  const char *parameters;
};
const struct str2key str2key[] = {
#define ESZETT "\xC3\x9F"
#define S_CARON "\xC5\xA1"
#define C_ACUTE "\xC4\x87"
#define G_CLEF "\xF0\x9D\x84\x9E"
#if WITH_DES
  {"password",
   "ATHENA.MIT.EDUraeburn",
   "\xCB\xC2\x2F\xAE\x23\x52\x98\xE3", SHISHI_DES_CBC_MD5, NULL},
  {"potatoe",
   "WHITEHOUSE.GOVdanny",
   "\xDF\x3D\x32\xA7\x4F\xD9\x2A\x01", SHISHI_DES_CBC_MD5, NULL},
  {"\xF0\x9D\x84\x9E",
   "EXAMPLE.COMpianist",
   "\x4F\xFB\x26\xBA\xB0\xCD\x94\x13", SHISHI_DES_CBC_MD5, NULL},
  {ESZETT,
   "ATHENA.MIT.EDUJuri" S_CARON "i" C_ACUTE,
   "\x62\xC8\x1A\x52\x32\xB5\xE6\x9D", SHISHI_DES_CBC_MD5, NULL},
  {"11119999",
   "AAAAAAAA", "\x98\x40\x54\xD0\xF1\xA7\x3E\x31", SHISHI_DES_CBC_MD5, NULL},
  {"NNNN6666",
   "FFFFAAAA", "\xC4\xBF\x6B\x25\xAD\xF7\xA4\xF8", SHISHI_DES_CBC_MD5, NULL},
#endif
#if WITH_3DES
  {"password",
   "ATHENA.MIT.EDUraeburn",
   "\x85\x0b\xb5\x13\x58\x54\x8c\xd0\x5e\x86\x76\x8c"
   "\x31\x3e\x3b\xfe\xf7\x51\x19\x37\xdc\xf7\x2c\x3e",
   SHISHI_DES3_CBC_HMAC_SHA1_KD, NULL},
  {"potatoe",
   "WHITEHOUSE.GOVdanny",
   "\xdf\xcd\x23\x3d\xd0\xa4\x32\x04\xea\x6d\xc4\x37"
   "\xfb\x15\xe0\x61\xb0\x29\x79\xc1\xf7\x4f\x37\x7a",
   SHISHI_DES3_CBC_HMAC_SHA1_KD, NULL},
  {"penny",
   "EXAMPLE.COMbuckaroo",
   "\x6d\x2f\xcd\xf2\xd6\xfb\xbc\x3d\xdc\xad\xb5\xda"
   "\x57\x10\xa2\x34\x89\xb0\xd3\xb6\x9d\x5d\x9d\x4a",
   SHISHI_DES3_CBC_HMAC_SHA1_KD, NULL},
  {ESZETT,
   "ATHENA.MIT.EDUJuri" S_CARON "i" C_ACUTE,
   "\x16\xd5\xa4\x0e\x1c\xe3\xba\xcb\x61\xb9\xdc\xe0"
   "\x04\x70\x32\x4c\x83\x19\x73\xa7\xb9\x52\xfe\xb0",
   SHISHI_DES3_CBC_HMAC_SHA1_KD, NULL},
  {G_CLEF,
   "EXAMPLE.COMpianist",
   "\x85\x76\x37\x26\x58\x5d\xbc\x1c\xce\x6e\xc4\x3e"
   "\x1f\x75\x1f\x07\xf1\xc4\xcb\xb0\x98\xf4\x0b\x19",
   SHISHI_DES3_CBC_HMAC_SHA1_KD, NULL},
#endif
#if WITH_AES
  {"password",
   "ATHENA.MIT.EDUraeburn",
   "\x42\x26\x3c\x6e\x89\xf4\xfc\x28\xb8\xdf\x68\xee\x09\x79\x9f\x15",
   SHISHI_AES128_CTS_HMAC_SHA1_96, "\x00\x00\x00\x01"},
  {"password",
   "ATHENA.MIT.EDUraeburn",
   "\xfe\x69\x7b\x52\xbc\x0d\x3c\xe1\x44\x32\xba\x03\x6a\x92\xe6\x5b"
   "\xbb\x52\x28\x09\x90\xa2\xfa\x27\x88\x39\x98\xd7\x2a\xf3\x01\x61",
   SHISHI_AES256_CTS_HMAC_SHA1_96, "\x00\x00\x00\x01"},
  {"password",
   "ATHENA.MIT.EDUraeburn",
   "\xc6\x51\xbf\x29\xe2\x30\x0a\xc2\x7f\xa4\x69\xd6\x93\xbd\xda\x13",
   SHISHI_AES128_CTS_HMAC_SHA1_96, "\x00\x00\x00\x02"},
  {"password",
   "ATHENA.MIT.EDUraeburn",
   "\xa2\xe1\x6d\x16\xb3\x60\x69\xc1\x35\xd5\xe9\xd2\xe2\x5f\x89\x61"
   "\x02\x68\x56\x18\xb9\x59\x14\xb4\x67\xc6\x76\x22\x22\x58\x24\xff",
   SHISHI_AES256_CTS_HMAC_SHA1_96, "\x00\x00\x00\x02"},
  {"password",
   "ATHENA.MIT.EDUraeburn",
   "\x4c\x01\xcd\x46\xd6\x32\xd0\x1e\x6d\xbe\x23\x0a\x01\xed\x64\x2a",
   SHISHI_AES128_CTS_HMAC_SHA1_96, "\x00\x00\x04\xB0"},
  {"password",
   "ATHENA.MIT.EDUraeburn",
   "\x55\xa6\xac\x74\x0a\xd1\x7b\x48\x46\x94\x10\x51\xe1\xe8\xb0\xa7"
   "\x54\x8d\x93\xb0\xab\x30\xa8\xbc\x3f\xf1\x62\x80\x38\x2b\x8c\x2a",
   SHISHI_AES256_CTS_HMAC_SHA1_96, "\x00\x00\x04\xB0"},
  {"password",
   "\x12\x34\x56\x78\x78\x56\x34\x12",
   "\xe9\xb2\x3d\x52\x27\x37\x47\xdd\x5c\x35\xcb\x55\xbe\x61\x9d\x8e",
   SHISHI_AES128_CTS_HMAC_SHA1_96, "\x00\x00\x00\x05"},
  {"password",
   "\x12\x34\x56\x78\x78\x56\x34\x12",
   "\x97\xa4\xe7\x86\xbe\x20\xd8\x1a\x38\x2d\x5e\xbc\x96\xd5\x90\x9c"
   "\xab\xcd\xad\xc8\x7c\xa4\x8f\x57\x45\x04\x15\x9f\x16\xc3\x6e\x31",
   SHISHI_AES256_CTS_HMAC_SHA1_96, "\x00\x00\x00\x05"},
  {"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
   "pass phrase equals block size",
   "\x59\xd1\xbb\x78\x9a\x82\x8b\x1a\xa5\x4e\xf9\xc2\x88\x3f\x69\xed",
   SHISHI_AES128_CTS_HMAC_SHA1_96, "\x00\x00\x04\xB0"},
  {"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
   "pass phrase equals block size",
   "\x89\xad\xee\x36\x08\xdb\x8b\xc7\x1f\x1b\xfb\xfe\x45\x94\x86\xb0"
   "\x56\x18\xb7\x0c\xba\xe2\x20\x92\x53\x4e\x56\xc5\x53\xba\x4b\x34",
   SHISHI_AES256_CTS_HMAC_SHA1_96, "\x00\x00\x04\xB0"},
  {"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
   "pass phrase exceeds block size",
   "\xcb\x80\x05\xdc\x5f\x90\x17\x9a\x7f\x02\x10\x4c\x00\x18\x75\x1d",
   SHISHI_AES128_CTS_HMAC_SHA1_96, "\x00\x00\x04\xB0"},
  {"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
   "pass phrase exceeds block size",
   "\xd7\x8c\x5c\x9c\xb8\x72\xa8\xc9\xda\xd4\x69\x7f\x0b\xb5\xb2\xd2"
   "\x14\x96\xc8\x2b\xeb\x2c\xae\xda\x21\x12\xfc\xee\xa0\x57\x40\x1b",
   SHISHI_AES256_CTS_HMAC_SHA1_96, "\x00\x00\x04\xB0"},
  {G_CLEF,
   "EXAMPLE.COMpianist",
   "\xf1\x49\xc1\xf2\xe1\x54\xa7\x34\x52\xd4\x3e\x7f\xe6\x2a\x56\xe5",
   SHISHI_AES128_CTS_HMAC_SHA1_96, "\x00\x00\x00\x32"},
  {G_CLEF,
   "EXAMPLE.COMpianist",
   "\x4b\x6d\x98\x39\xf8\x44\x06\xdf\x1f\x09\xcc\x16\x6d\xb4\xb8\x3c"
   "\x57\x18\x48\xb7\x84\xa3\xd6\xbd\xc3\x46\x58\x9a\x3e\x39\x3f\x9e",
   SHISHI_AES256_CTS_HMAC_SHA1_96, "\x00\x00\x00\x32"},
#endif
#if WITH_ARCFOUR
  {"foo", "",
   "\xac\x8e\x65\x7f\x83\xdf\x82\xbe\xea\x5d\x43\xbd\xaf\x78\x00\xcc",
   SHISHI_ARCFOUR_HMAC, NULL}
#endif
};

struct pkcs5
{
  int iterations;
  const char *password;
  const char *salt;
  int dklen;
  const char *expected;
};
const struct pkcs5 pkcs5[] = {
  {1, "password", "ATHENA.MIT.EDUraeburn", 16,
   "\xCD\xED\xB5\x28\x1B\xB2\xF8\x01\x56\x5A\x11\x22\xB2\x56\x35\x15"},
  {2, "password", "ATHENA.MIT.EDUraeburn", 16,
   "\x01\xdb\xee\x7f\x4a\x9e\x24\x3e\x98\x8b\x62\xc7\x3c\xda\x93\x5d"},
  {2, "password", "ATHENA.MIT.EDUraeburn", 32,
   "\x01\xdb\xee\x7f\x4a\x9e\x24\x3e\x98\x8b\x62\xc7\x3c\xda\x93\x5d"
   "\xa0\x53\x78\xb9\x32\x44\xec\x8f\x48\xa9\x9e\x61\xad\x79\x9d\x86"},
  {1200, "password", "ATHENA.MIT.EDUraeburn", 16,
   "\x5c\x08\xeb\x61\xfd\xf7\x1e\x4e\x4e\xc3\xcf\x6b\xa1\xf5\x51\x2b"},
  {1200, "password", "ATHENA.MIT.EDUraeburn", 32,
   "\x5c\x08\xeb\x61\xfd\xf7\x1e\x4e\x4e\xc3\xcf\x6b\xa1\xf5\x51\x2b"
   "\xa7\xe5\x2d\xdb\xc5\xe5\x14\x2f\x70\x8a\x31\xe2\xe6\x2b\x1e\x13"},
  {5, "password", "\x12\x34\x56\x78\x78\x56\x34\x12\x00", 16,
   "\xd1\xda\xa7\x86\x15\xf2\x87\xe6\xa1\xc8\xb1\x20\xd7\x06\x2a\x49"},
  {5, "password", "\x12\x34\x56\x78\x78\x56\x34\x12\x00", 32,
   "\xd1\xda\xa7\x86\x15\xf2\x87\xe6\xa1\xc8\xb1\x20\xd7\x06\x2a\x49"
   "\x3f\x98\xd2\x03\xe6\xbe\x49\xa6\xad\xf4\xfa\x57\x4b\x6e\x64\xee"},
  {1200, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
   "pass phrase equals block size", 16,
   "\x13\x9c\x30\xc0\x96\x6b\xc3\x2b\xa5\x5f\xdb\xf2\x12\x53\x0a\xc9"},
  {1200, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
   "pass phrase equals block size", 32,
   "\x13\x9c\x30\xc0\x96\x6b\xc3\x2b\xa5\x5f\xdb\xf2\x12\x53\x0a\xc9"
   "\xc5\xec\x59\xf1\xa4\x52\xf5\xcc\x9a\xd9\x40\xfe\xa0\x59\x8e\xd1"},
  {1200, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
   "pass phrase exceeds block size", 16,
   "\x9c\xca\xd6\xd4\x68\x77\x0c\xd5\x1b\x10\xe6\xa6\x87\x21\xbe\x61"},
  {1200, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
   "pass phrase exceeds block size", 32,
   "\x9c\xca\xd6\xd4\x68\x77\x0c\xd5\x1b\x10\xe6\xa6\x87\x21\xbe\x61"
   "\x1a\x8b\x4d\x28\x26\x01\xdb\x3b\x36\xbe\x92\x46\x91\x5e\xc8\x2a"},
  {50, G_CLEF "\x00", "EXAMPLE.COMpianist", 16,
   "\x6b\x9c\xf2\x6d\x45\x45\x5a\x43\xa5\xb8\xbb\x27\x6a\x40\x3b\x39"},
  {50, G_CLEF "\x00", "EXAMPLE.COMpianist", 32,
   "\x6b\x9c\xf2\x6d\x45\x45\x5a\x43\xa5\xb8\xbb\x27\x6a\x40\x3b\x39"
   "\xe7\xfe\x37\xa0\xc4\x1e\x02\xc2\x81\xff\x30\x69\xe1\xe9\x4f\x52"},
  {500, "All n-entities must communicate with other n-entities via n-1 "
   "entiteeheehees", "\x12\x34\x56\x78\x78\x56\x34\x12\x00", 16,
   "\x6A\x89\x70\xBF\x68\xC9\x2C\xAE\xA8\x4A\x8D\xF2\x85\x10\x85\x86"}
};

void
test (Shishi * handle)
{
  Shishi_key *key, *key2;
  char out[BUFSIZ];
  size_t i;
  int res;

  if (debug)
    shishi_cfg (handle, strdup ("verbose-crypto,verbose-crypto-noise"));

  for (i = 0; i < sizeof (drdk) / sizeof (drdk[0]); i++)
    {
      if (debug)
	printf ("DR entry %d\n", i);

      res = shishi_key_from_value (handle, drdk[i].type, drdk[i].key, &key);

      if (res == SHISHI_OK)
	res = shishi_dr (handle, key, drdk[i].usage, drdk[i].nusage,
			 out, strlen (drdk[i].dr));

      shishi_key_done (key);

      if (res != SHISHI_OK)
	{
	  fail ("shishi_dr() entry %d failed (%s)\n",
		i, shishi_error (handle));
	  continue;
	}

      if (debug)
	{
	  printf ("DR(%s, key, usage)\n", shishi_cipher_name (drdk[i].type));

	  printf ("key:\n");
	  escapeprint (drdk[i].key, strlen (drdk[i].key));
	  hexprint (drdk[i].key, strlen (drdk[i].key));
	  puts ("");
	  binprint (drdk[i].key, strlen (drdk[i].key));
	  puts ("");

	  printf ("usage:\n");
	  escapeprint (drdk[i].usage, drdk[i].nusage);
	  hexprint (drdk[i].usage, drdk[i].nusage);
	  puts ("");
	  binprint (drdk[i].usage, drdk[i].nusage);
	  puts ("");

	  printf ("computed DR:\n");
	  escapeprint (out, strlen (drdk[i].dr));
	  hexprint (out, strlen (drdk[i].dr));
	  puts ("");
	  binprint (out, strlen (drdk[i].dr));
	  puts ("");

	  printf ("expected DR:\n");
	  escapeprint (drdk[i].dr, strlen (drdk[i].dr));
	  hexprint (drdk[i].dr, strlen (drdk[i].dr));
	  puts ("");
	  binprint (drdk[i].dr, strlen (drdk[i].dr));
	  puts ("");
	}

      if (memcmp (drdk[i].dr, out, strlen (drdk[i].dr)) != 0)
	{
	  fail ("shishi_dr() entry %d failed\n", i);
	  if (debug)
	    printf ("ERROR\n");
	}
      else if (debug)
	success ("OK\n");

      res = shishi_key_from_value (handle, drdk[i].type, drdk[i].key, &key);

      if (res == SHISHI_OK)
	res = shishi_key_from_value (handle, drdk[i].type, NULL, &key2);

      if (res == SHISHI_OK)
	res = shishi_dk (handle, key, drdk[i].usage, drdk[i].nusage, key2);

      shishi_key_done (key);

      if (res != SHISHI_OK)
	{
	  fail ("shishi_dk() entry %d failed (%s)\n",
		i, shishi_error (handle));
	  continue;
	}

      if (debug)
	{
	  printf ("DK(%s, key, usage)\n", shishi_cipher_name (drdk[i].type));

	  printf ("key:\n");
	  escapeprint (drdk[i].key, strlen (drdk[i].key));
	  hexprint (drdk[i].key, strlen (drdk[i].key));
	  puts ("");
	  binprint (drdk[i].key, strlen (drdk[i].key));
	  puts ("");

	  printf ("usage:\n");
	  escapeprint (drdk[i].usage, drdk[i].nusage);
	  hexprint (drdk[i].usage, drdk[i].nusage);
	  puts ("");
	  binprint (drdk[i].usage, drdk[i].nusage);
	  puts ("");

	  printf ("computed DK:\n");
	  escapeprint (shishi_key_value (key2), shishi_key_length (key2));
	  hexprint (shishi_key_value (key2), shishi_key_length (key2));
	  puts ("");
	  binprint (shishi_key_value (key2), shishi_key_length (key2));
	  puts ("");

	  printf ("expected DK:\n");
	  escapeprint (drdk[i].dk, strlen (drdk[i].dk));
	  hexprint (drdk[i].dk, strlen (drdk[i].dk));
	  puts ("");
	  binprint (drdk[i].dk, strlen (drdk[i].dk));
	  puts ("");
	}

      if (!(shishi_key_length (key2) == strlen (drdk[i].dk) &&
	    memcmp (drdk[i].dk, shishi_key_value (key2),
		    strlen (drdk[i].dk)) == 0))
	{
	  fail ("shishi_dk() entry %d failed\n", i);
	  if (debug)
	    printf ("ERROR\n");
	}
      else if (debug)
	success ("OK\n");

      shishi_key_done (key2);
    }

  for (i = 0; i < sizeof (nfold) / sizeof (nfold[0]); i++)
    {
      if (debug)
	printf ("N-FOLD entry %d\n", i);

      res = shishi_n_fold (handle,
			   nfold[i].in, strlen (nfold[i].in),
			   out, nfold[i].n / 8);
      if (res != SHISHI_OK)
	{
	  fail ("shishi_n_fold() entry %d failed (%s)\n",
		i, shishi_error (handle));
	  continue;
	}

      if (debug)
	{
	  printf ("in:\n");
	  escapeprint (nfold[i].in, strlen (nfold[i].in));
	  hexprint (nfold[i].in, strlen (nfold[i].in));
	  puts ("");
	  binprint (nfold[i].in, strlen (nfold[i].in));
	  puts ("");

	  printf ("out:\n");
	  escapeprint (out, nfold[i].n / 8);
	  hexprint (out, nfold[i].n / 8);
	  puts ("");
	  binprint (out, nfold[i].n / 8);
	  puts ("");

	  printf ("expected out:\n");
	  escapeprint (nfold[i].out, nfold[i].n / 8);
	  hexprint (nfold[i].out, nfold[i].n / 8);
	  puts ("");
	  binprint (nfold[i].out, nfold[i].n / 8);
	  puts ("");
	}

      if (memcmp (nfold[i].out, out, nfold[i].n / 8) != 0)
	{
	  fail ("shishi_n_fold() entry %d failed\n", i);
	  if (debug)
	    printf ("ERROR\n");
	}
      else if (debug)
	success ("OK\n");
    }

  for (i = 0; i < sizeof (str2key) / sizeof (str2key[0]); i++)
    {
      int n_password = strlen (str2key[i].password);
      int saltlen = strlen (str2key[i].salt);
      int keylen = sizeof (key);
      const char *name = shishi_cipher_name (str2key[i].etype);

      if (debug)
	printf ("STRING-TO-KEY entry %d (key type %s)\n", i,
		name ? name : "NO NAME");

      res = shishi_key_from_string (handle, str2key[i].etype,
				    str2key[i].password, n_password,
				    str2key[i].salt, saltlen,
				    str2key[i].parameters, &key);
      if (res != SHISHI_OK)
	{
	  fail ("shishi_string_to_key() entry %d failed (%s)\n",
		i, shishi_error (handle));
	  continue;
	}

      if (debug)
	{
	  printf ("password:\n");
	  escapeprint (str2key[i].password, n_password);
	  hexprint (str2key[i].password, n_password);
	  puts ("");
	  binprint (str2key[i].password, n_password);
	  puts ("");

	  printf ("salt:\n");
	  escapeprint (str2key[i].salt, saltlen);
	  hexprint (str2key[i].salt, saltlen);
	  puts ("");
	  binprint (str2key[i].salt, saltlen);
	  puts ("");

	  printf ("computed key:\n");
	  escapeprint (shishi_key_value (key), shishi_key_length (key));
	  hexprint (shishi_key_value (key), shishi_key_length (key));
	  puts ("");
	  binprint (shishi_key_value (key), shishi_key_length (key));
	  puts ("");

	  printf ("expected key:\n");
	  escapeprint (str2key[i].key, strlen (str2key[i].key));
	  hexprint (str2key[i].key, strlen (str2key[i].key));
	  puts ("");
	  binprint (str2key[i].key, strlen (str2key[i].key));
	  puts ("");
	}

      if (memcmp (str2key[i].key, shishi_key_value (key), keylen) != 0)
	{
	  fail ("shishi_string_to_key() entry %d failed\n", i);

	  if (debug)
	    printf ("ERROR\n");
	}
      else if (debug)
	success ("OK\n");

      shishi_key_done (key);
    }

  for (i = 0; i < sizeof (pkcs5) / sizeof (pkcs5[0]); i++)
    {
      if (debug)
	printf ("PKCS5 entry %d\n", i);

      res = shishi_pbkdf2_sha1 (handle,
				pkcs5[i].password, strlen (pkcs5[i].password),
				pkcs5[i].salt, strlen (pkcs5[i].salt),
				pkcs5[i].iterations, pkcs5[i].dklen, out);
      if (res != SHISHI_OK)
	{
	  fail ("PKCS5 entry %d failed fatally: %d\n", i, res);
	  continue;
	}

      if (debug)
	{
	  printf ("password:\n");
	  escapeprint (pkcs5[i].password, strlen (pkcs5[i].password));
	  hexprint (pkcs5[i].password, strlen (pkcs5[i].password));
	  puts ("");
	  binprint (pkcs5[i].password, strlen (pkcs5[i].password));
	  puts ("");

	  printf ("salt:\n");
	  escapeprint (pkcs5[i].salt, strlen (pkcs5[i].salt));
	  hexprint (pkcs5[i].salt, strlen (pkcs5[i].salt));
	  puts ("");
	  binprint (pkcs5[i].salt, strlen (pkcs5[i].salt));
	  puts ("");

	  printf ("computed key:\n");
	  escapeprint (out, pkcs5[i].dklen);
	  hexprint (out, pkcs5[i].dklen);
	  puts ("");
	  binprint (out, pkcs5[i].dklen);
	  puts ("");

	  printf ("expected key:\n");
	  escapeprint (pkcs5[i].expected, pkcs5[i].dklen);
	  hexprint (pkcs5[i].expected, pkcs5[i].dklen);
	  puts ("");
	  binprint (pkcs5[i].expected, pkcs5[i].dklen);
	  puts ("");
	}

      if (memcmp (pkcs5[i].expected, out, pkcs5[i].dklen) != 0)
	{
	  fail ("PKCS5 entry %d failed\n", i);

	  if (debug)
	    printf ("ERROR\n");
	}
      else if (debug)
	success ("OK\n");
    }
}
