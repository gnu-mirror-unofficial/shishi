/* crypto.c	interface to cryptographic functionality
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

#include "data.h"

int
crypto (Shishi * handle, struct arguments arg)
{
  FILE *infh, *outfh;
  Shishi_key *key;
  char *in, *out;
  size_t inlen, outlen;
  int rc;
  int i;

  if (arg.cname == NULL)
    arg.cname = shishi_principal_default (handle);

  if (arg.realm == NULL)
    arg.realm = shishi_realm_default (handle);

  if (arg.salt == NULL)
    {
      arg.salt = malloc (strlen (arg.realm) + strlen (arg.cname) + 1);
      if (!arg.salt)
	return SHISHI_MALLOC_ERROR;
      strcpy (arg.salt, arg.realm);
      strcat (arg.salt, arg.cname);
    }

  rc = shishi_key (handle, &key);
  if (rc != SHISHI_OK)
    {
      shishi_error_printf (handle, _("Cannot create key: %s"),
			   shishi_strerror (rc));
      return rc;
    }

  shishi_key_type_set (key, arg.algorithm);
  shishi_key_version_set (key, arg.kvno);
  shishi_key_principal_set (key, arg.cname);
  shishi_key_realm_set (key, arg.realm);

  if (arg.password)
    {
      rc = shishi_string_to_key (handle, arg.algorithm,
				 arg.password,
				 strlen (arg.password),
				 arg.salt,
				 strlen (arg.salt), arg.parameter, key);
      if (rc != SHISHI_OK)
	{
	  shishi_error_printf (handle, _("Error in string2key"));
	  return rc;
	}

    }
  else if (arg.keyvalue)
    {
      rc = shishi_key_from_base64 (handle, arg.algorithm, arg.keyvalue, &key);
      if (rc != SHISHI_OK)
	{
	  fprintf (stderr, _("Could not create key: %s\n"),
		   shishi_strerror (rc));
	  return rc;
	}
    }
  else if (arg.random)
    {
      char buf[BUFSIZ];

      rc = shishi_randomize (handle, buf,
			     shishi_cipher_randomlen (arg.algorithm));
      if (rc != SHISHI_OK)
	return rc;

      shishi_random_to_key (handle, arg.algorithm,
			    buf, shishi_cipher_randomlen (arg.algorithm),
			    key);
    }
  else if (arg.readkeyfile)
    {
      key = shishi_keys_for_server_in_file (handle, arg.readkeyfile,
					    arg.cname);
#if 0
      shishi_key_from_file (handle, arg.writekeyfile, arg.algorithm, key,
			    keylen, arg.kvno, arg.cname, arg.realm);
#endif

      if (key == NULL)
	{
	  fprintf (stderr, _("Could not find key: %s\n"),
		   shishi_strerror_details (handle));
	  return 1;
	}
    }
  else
    {
      fprintf (stderr, "Nothing to do.\n");
      return SHISHI_OK;
    }

  if (shishi_key_type (key) == SHISHI_NULL && !arg.silent)
    fprintf (stderr,
	     "warning: using %s is silly, consider using --algorithm.\n",
	     shishi_cipher_name (arg.algorithm));

  if (arg.verbose ||
      ((arg.password || arg.random || arg.keyvalue) &&
       !(arg.encrypt_p || arg.decrypt_p)))
    {
      shishi_key_print (handle, stdout, key);
    }

#if 0
  currently broken
  if (arg.encrypt_p || arg.decrypt_p)
    {
      if (arg.inputfile)
	{
	  infh = fopen (arg.inputfile, "r");
	  if (infh == NULL)
	    {
	      shishi_error_printf (handle, _("`%s': %s\n"),
				   arg.inputfile, strerror (errno));
	      return SHISHI_FOPEN_ERROR;
	    }
	}
      else
	infh = stdin;

      if (arg.outputfile)
	{
	  outfh = fopen (arg.outputfile, "w");
	  if (outfh == NULL)
	    {
	      shishi_error_printf (handle, _("`%s': %s\n"),
				   arg.inputfile, strerror (errno));
	      return SHISHI_FOPEN_ERROR;
	    }
	}
      else
	outfh = stdout;

      outlen = fread (out, sizeof (out[0]),
		      sizeof (out) / sizeof (out[0]), infh);
      if (outlen == 0)
	{
	  fprintf (stderr, _("Error reading `%s'\n"), arg.inputfile);
	  return !SHISHI_OK;
	}
      if (arg.verbose)
	printf (_("Read %d bytes...\n"), outlen);

      if (arg.encrypt_p)
	rc = shishi_encrypt (handle, key, arg.keyusage,
			     out, outlen, &in, &inlen);
      else
	rc = shishi_decrypt (handle, key, arg.keyusage,
			     in, inlen, &out, &outlen);
      if (rc != SHISHI_OK)
	{
	  shishi_error_printf (handle, _("Error ciphering\n"));
	  return rc;
	}

      if (arg.outputtype == SHISHI_FILETYPE_HEX)
	{
	  for (i = 0; i < inlen; i++)
	    {
	      if ((i % 16) == 0)
		fprintf (outfh, "\n");
	      fprintf (outfh, "%02x ", in[i]);
	    }
	  fprintf (outfh, "\n");
	}
      else if (arg.outputtype == SHISHI_FILETYPE_BINARY)
	{
	  i = fwrite (in, sizeof (in[0]), inlen, outfh);
	  if (i != inlen)
	    {
	      fprintf (stderr, _("Short write (%d < %d)...\n"), i, inlen);
	      return 1;
	    }
	  printf (_("Wrote %d bytes...\n"), inlen);
	}

      if (arg.outputfile)
	{
	  rc = fclose (outfh);
	  if (rc != 0)
	    {
	      shishi_error_printf (handle, _("`%s': %s\n"),
				   arg.outputfile, strerror (errno));
	      return SHISHI_FCLOSE_ERROR;
	    }
	}

      if (arg.inputfile)
	{
	  rc = fclose (infh);
	  if (rc != 0)
	    {
	      shishi_error_printf (handle, _("`%s': %s\n"),
				   arg.inputfile, strerror (errno));
	      return SHISHI_FCLOSE_ERROR;
	    }
	}
    }
#endif

  if (arg.writekeyfile)
    {
      shishi_key_to_file (handle, arg.writekeyfile, key);
    }

  return 0;
}
