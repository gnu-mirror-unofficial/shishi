/* crypto.c	interface to cryptographic functionality
 * Copyright (C) 2002  Simon Josefsson
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

#include "shishi.h"
#include "data.h"

#include <errno.h>
extern int errno;

int
crypto (Shishi * handle, struct arguments arg)
{
  int res;
  FILE *infh, *outfh;
  unsigned char key[BUFSIZ];
  int keylen = sizeof (key);
  unsigned char data[BUFSIZ];
  int datalen;
  unsigned char encrypted[BUFSIZ];
  int encryptedlen;
  int i;
  char salt[BUFSIZ];

  if (arg.cname == NULL)
    arg.cname = shishi_principal_default_get (handle);

  if (arg.realm == NULL)
    arg.realm = shishi_realm_default_get (handle);

  if (arg.verbose)
    printf (_
	    ("crypto alg=%d enc=%d dec=%d str2key=%s cname=%s realm=%s input=%s type=%d output=%s type=%d\n"),
	    arg.algorithm, arg.encrypt_p, arg.decrypt_p, arg.stringtokey,
	    arg.cname, arg.realm, arg.inputfile, arg.inputtype,
	    arg.outputfile, arg.outputtype);

  if (arg.algorithm == 0)
    {
      arg.algorithm = SHISHI_DES_CBC_MD5;

      if (!arg.silent)
	fprintf (stderr, "No algorithm specified, defaulting to %s\n",
		 shishi_cipher_name (arg.algorithm));
    }

  if (arg.stringtokey)
    {
      if (strlen (arg.realm) + strlen (arg.cname) > sizeof (salt))
	{
	  fprintf (stderr, _("Too long realm/principal...\n"));
	  return 1;
	}
      strcpy (salt, arg.realm);
      strcat (salt, arg.cname);

      res = shishi_string_to_key (handle,
				  arg.stringtokey,
				  strlen (arg.stringtokey),
				  salt,
				  strlen (salt),
				  NULL, key, &keylen, arg.algorithm);
      if (res != SHISHI_OK)
	{
	  fprintf (stderr, _("Error in string2key: %s\n"),
		   shishi_strerror_details (handle));
	  return 1;
	}

    }
  else if (arg.keyvalue)
    {
      if (strlen (arg.keyvalue) > sizeof (key))
	{
	  fprintf (stderr, "keyvalue too large\n");
	  return 1;
	}
      keylen = shishi_from_base64 (key, arg.keyvalue);
      if (keylen <= 0)
	{
	  fprintf (stderr, "base64 decoding of key value failed\n");
	  return 1;
	}
    }

  if (arg.verbose || (!arg.encrypt_p && !arg.decrypt_p))
    {
      char b64der[BUFSIZ];

      shishi_to_base64 (b64der, key, keylen, sizeof (b64der));
      fprintf (stderr, _("Key: %s\n"), b64der);
    }

  if (arg.encrypt_p || arg.decrypt_p)
    {
      if (arg.inputfile)
	{
	  infh = fopen (arg.inputfile, "r");
	  if (infh == NULL)
	    {
	      fprintf (stderr, _("Cannot open `%s': %s\n"),
		       arg.inputfile, strerror (errno));
	      return 1;
	    }
	}
      else
	infh = stdin;

      if (arg.outputfile)
	{
	  outfh = fopen (arg.outputfile, "w");
	  if (outfh == NULL)
	    {
	      fprintf (stderr, _("Cannot open `%s': %s\n"),
		       arg.outputfile, strerror (errno));
	      return 1;
	    }
	}
      else
	outfh = stdout;

      datalen = fread (data, sizeof (data[0]),
		       sizeof (data) / sizeof (data[0]), infh);
      if (datalen == 0)
	{
	  fprintf (stderr, _("Error reading `%s'\n"), arg.inputfile);
	  return 1;
	}
      printf (_("Read %d bytes...\n"), datalen);

      if (arg.encrypt_p)
	{
	  encryptedlen = sizeof (encrypted);
	  res = shishi_encrypt (handle, 0, encrypted, &encryptedlen,
				data, datalen, key, keylen, arg.algorithm);
	}
      else if (arg.decrypt_p)
	{
	  encryptedlen = sizeof (encrypted);
	  res = shishi_decrypt (handle, 0, encrypted, &encryptedlen,
				data, datalen, key, keylen, arg.algorithm);
	}

      if (res != SHISHI_OK)
	{
	  fprintf (stderr, _("Error ciphering: %s\n"),
		   shishi_strerror_details (handle));
	  // return 1;
	}

      if (arg.outputtype == SHISHI_FILETYPE_HEX)
	{
	  for (i = 0; i < encryptedlen; i++)
	    {
	      if ((i % 16) == 0)
		fprintf (outfh, "\n");
	      fprintf (outfh, "%02x ", encrypted[i]);
	    }
	  fprintf (outfh, "\n");
	}
      else if (arg.outputtype == SHISHI_FILETYPE_BINARY)
	{
	  i = fwrite (encrypted, sizeof (encrypted[0]), encryptedlen, outfh);
	  if (i != encryptedlen)
	    {
	      fprintf (stderr, _("Short write (%d < %d)...\n"), i,
		       encryptedlen);
	      return 1;
	    }
	  printf (_("Wrote %d bytes...\n"), encryptedlen);
	}

      if (arg.inputfile)
	{
	  res = fclose (infh);
	  if (res != 0)
	    {
	      fprintf (stderr, _("Could not close `%s': %s\n"),
		       arg.inputfile, strerror (errno));
	      return 1;
	    }
	}
    }

  return 0;
}
