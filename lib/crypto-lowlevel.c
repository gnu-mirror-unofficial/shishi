#include <gcrypt.h>

#define MAX_BLOCK_LEN 32

void
lowlevel_set_alginfo(int keytype, int inlen,
		     int *alg, int *mode, int *flags, int *zeropad)
{
  if (alg)
    *alg = 0;
  if (mode)
    *mode = GCRY_CIPHER_MODE_CBC;
  if (flags)
    *flags = 0;
  if (zeropad)
    *zeropad = 0;

  switch (keytype)
    {
    case SHISHI_DES3_CBC_HMAC_SHA1_KD:
      if (alg)
	*alg = GCRY_CIPHER_3DES;
      if (zeropad)
	*zeropad = (inlen % 8) != 0;
      break;

    case SHISHI_DES_CBC_CRC:
    case SHISHI_DES_CBC_MD4:
    case SHISHI_DES_CBC_MD5:
      if (alg)
	*alg = GCRY_CIPHER_DES;
      if (zeropad)
	*zeropad = (inlen % 8) != 0;
      break;

    case SHISHI_AES128_CTS_HMAC_SHA1_96:
    case SHISHI_AES256_CTS_HMAC_SHA1_96:
      if (alg)
	*alg = GCRY_CIPHER_AES;
      if (flags)
	*flags = GCRY_CIPHER_CBC_CTS;
      break;

    default:
      printf("urk");
      exit(1);
      break;
    }
}

static int
lowlevel_dencrypt (Shishi * handle,
		   int keytype,
		   char *out,
		   int *outlen,
		   char *in,
		   int inlen, char *key, int keylen, int direction)
{
  int res;
  GCRY_CIPHER_HD ch;
  int j;
  char *tmp;
  int tmplen;
  int alg, mode, flags, zeropad;

  lowlevel_set_alginfo(keytype, inlen, &alg, &mode, &flags, &zeropad);

  ch = gcry_cipher_open (alg, mode, flags);
  if (ch == NULL)
    {
      puts ("open fail");
      return !SHISHI_OK;
    }

  res = gcry_cipher_setkey (ch, key, keylen);
  if (res != GCRYERR_SUCCESS)
    {
      if (res == GCRYERR_WEAK_KEY)
	{
	  printf ("weak key\n");
	}
      else
	{
	  puts ("setkey fail");
	}
      return !SHISHI_OK;
    }

  res = gcry_cipher_setiv (ch, NULL, 0);
  if (res != 0)
    {
      printf ("iv res %d err %s\n", res, gcry_strerror (res));
    }

  if (zeropad)
    {
      puts("--> 0 pad");
      tmplen = inlen;
      tmplen += 8 - tmplen % 8;
      tmp = (char *) malloc (tmplen);
      memcpy (tmp, in, inlen);
      memset (tmp + inlen, 0, tmplen - inlen);
    }
  else
    {
      tmp = in;
      tmplen = inlen;
    }

  if (direction)
    res = gcry_cipher_decrypt (ch, out, *outlen, tmp, tmplen);
  else
    res = gcry_cipher_encrypt (ch, out, *outlen, tmp, tmplen);

  if (zeropad)
    free (tmp);

  if (res != 0)
    {
      printf ("crypt res %d err %s\n", res, gcry_strerror (res));
    }

  *outlen = tmplen;

  gcry_cipher_close (ch);

  return SHISHI_OK;
}

static int
lowlevel_verify (Shishi * handle, int keytype, 
		 char *out, int *outlen, 
		 char *in, int inlen,
		 char *key, int keylen)
{
  GCRY_MD_HD mdh;
  char *hash;
  int i;
  int res;
  int halg = GCRY_MD_SHA1;
  int hlen = gcry_md_get_algo_dlen(halg);
  int calg;
  int blen;

  lowlevel_set_alginfo(keytype, inlen, &calg, NULL, NULL, NULL);
  blen = gcry_cipher_get_algo_blklen(calg);

#if 1
  printf("hlen %d blen %d\n", hlen, blen);
  printf("expect: ");
  for (i = 0; i < hlen; i++)
    printf("%02x", in[inlen - hlen + i] & 0xFF);
  printf("\n");
#endif

  res = gcry_control (GCRYCTL_INIT_SECMEM, 512, 0);
  if (res != GCRYERR_SUCCESS)
    return SHISHI_GCRYPT_ERROR;

  mdh = gcry_md_open (halg, GCRY_MD_FLAG_HMAC);
  if (mdh == NULL)
    return SHISHI_GCRYPT_ERROR;

  res = gcry_md_setkey (mdh, key, keylen);
  if (res != GCRYERR_SUCCESS)
    return SHISHI_GCRYPT_ERROR;

  gcry_md_write (mdh, out, *outlen);
  
  hash = gcry_md_read (mdh, halg);
  if (hash == NULL)
    return SHISHI_GCRYPT_ERROR;

#if 1
  printf("hash: ");
  for (i = 0; i < hlen; i++)
    printf("%02x", hash[i] & 0xFF);
  printf("\n");
#endif

  if (memcmp(hash, &in[inlen - hlen], hlen) == 0)
    {
      memmove (out, out + blen, *outlen - blen);
      *outlen -= blen;
      res = SHISHI_OK;
    }
  else
    {
      if (DEBUG(handle))
	printf ("verify fail\n");
      res = !SHISHI_OK;
    }

  gcry_md_close (mdh);

  return res;
}
