
static int
crypto (Shishi * handle, struct arguments arg)
{
  Shishi_key *key;
  int rc;

  if (arg.cname == NULL)
    arg.cname = shishi_principal_default (handle);

  if (arg.crealm == NULL)
    arg.crealm = shishi_realm_default (handle);

  if (arg.salt == NULL)
    {
      char *cname, *tok, *tokptr;

      cname = xstrdup (arg.cname);
      arg.salt = xstrdup (arg.crealm);
      tok = strtok_r (cname, "/", &tokptr);
      while (tok)
	{
	  arg.salt =
	    xrealloc (arg.salt, strlen (arg.salt) + strlen (tok) + 1);
	  strcat (arg.salt, tok);
	  tok = strtok_r (NULL, "/", &tokptr);
	}
      free (cname);
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
  shishi_key_realm_set (key, arg.crealm);

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

      rc = shishi_randomize (handle, 1, buf,
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
		   shishi_error (handle));
	  return 1;
	}
    }
  else
    {
      fprintf (stderr, "Nothing to do.\n");
      return SHISHI_OK;
    }

  if (arg.verbose ||
      ((arg.password || arg.random || arg.keyvalue) &&
       !(arg.encrypt_p || arg.decrypt_p)))
    {
      shishi_key_print (handle, stdout, key);
    }

#if 0
  currently broken if (arg.encrypt_p || arg.decrypt_p)
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

static void
parse_filename (char *arg, int *type, char **var)
{
  if (strncasecmp (arg, TYPE_TEXT_NAME ",", strlen (TYPE_TEXT_NAME ",")) == 0)
    {
      (*type) = SHISHI_FILETYPE_TEXT;
      arg += strlen (TYPE_TEXT_NAME ",");
    }
  else if (strncasecmp (arg, TYPE_DER_NAME ",", strlen (TYPE_DER_NAME ",")) ==
	   0)
    {
      (*type) = SHISHI_FILETYPE_DER;
      arg += strlen (TYPE_DER_NAME ",");
    }
  else if (strncasecmp (arg, TYPE_HEX_NAME ",", strlen (TYPE_HEX_NAME ",")) ==
	   0)
    {
      (*type) = SHISHI_FILETYPE_HEX;
      arg += strlen (TYPE_HEX_NAME ",");
    }
  else if (strncasecmp (arg, TYPE_BASE64_NAME ",",
			strlen (TYPE_BASE64_NAME ",")) == 0)
    {
      (*type) = SHISHI_FILETYPE_BASE64;
      arg += strlen (TYPE_BASE64_NAME ",");
    }
  else if (strncasecmp (arg, TYPE_BINARY_NAME ",",
			strlen (TYPE_BINARY_NAME ",")) == 0)
    {
      (*type) = SHISHI_FILETYPE_BINARY;
      arg += strlen (TYPE_BINARY_NAME ",");
    }
  else
    (*type) = 0;
  *var = strdup (arg);
}

int
foo (void)
{

 case OPTION_CRYPTO_ENCRYPT:
   arguments->command = OPTION_CRYPTO;
   if (arguments->decrypt_p)
     argp_error (state, _("Cannot both encrypt and decrypt."));
   arguments->encrypt_p = 1;
   break;

 case OPTION_CRYPTO_DECRYPT:
   arguments->command = OPTION_CRYPTO;
   if (arguments->encrypt_p)
     argp_error (state, _("Cannot both encrypt and decrypt."));
   arguments->decrypt_p = 1;
   break;

 case OPTION_CRYPTO_KEY_VALUE:
   arguments->keyvalue = strdup (arg);
   break;

 case OPTION_CRYPTO_KEY_USAGE:
   if (arguments->command != OPTION_CRYPTO)
     argp_error (state, _("Option `%s' only valid with CRYPTO."),
		 state->argv[state->next - 1]);
   arguments->keyusage = atoi (arg);
   break;

 case OPTION_CRYPTO_KEY_VERSION:
   if (arguments->command != OPTION_CRYPTO)
     argp_error (state, _("Option `%s' only valid with CRYPTO."),
		 state->argv[state->next - 1]);
   arguments->kvno = atoi (arg);
   break;

 case OPTION_CRYPTO_PARAMETER:
   if (arguments->command != OPTION_CRYPTO)
     argp_error (state, _("Option `%s' only valid with CRYPTO."),
		 state->argv[state->next - 1]);
   arguments->parameter = strdup (arg);
   break;

 case OPTION_CRYPTO_PASSWORD:
   arguments->password = strdup (arg);
   break;

 case OPTION_CRYPTO_RANDOM:
   if (arguments->command != OPTION_CRYPTO)
     argp_error (state, _("Option `%s' only valid with CRYPTO."),
		 state->argv[state->next - 1]);
   arguments->random = 1;
   break;

 case OPTION_CRYPTO_READ_DATA_FILE:
   if (arguments->command != OPTION_CRYPTO)
     argp_error (state, _("Option `%s' only valid with CRYPTO."),
		 state->argv[state->next - 1]);
   parse_filename (arg, &arguments->inputtype, &arguments->inputfile);
   if (arguments->inputtype == SHISHI_FILETYPE_TEXT ||
       arguments->inputtype == SHISHI_FILETYPE_DER)
     arguments->inputtype = SHISHI_FILETYPE_BINARY;
   break;

 case OPTION_CRYPTO_READ_KEY_FILE:
   if (arguments->command != OPTION_CRYPTO)
     argp_error (state, _("Option `%s' only valid with CRYPTO."),
		 state->argv[state->next - 1]);
   arguments->readkeyfile = strdup (arg);
   break;

 case OPTION_CRYPTO_SALT:
   if (arguments->command != OPTION_CRYPTO)
     argp_error (state, _("Option `%s' only valid with CRYPTO."),
		 state->argv[state->next - 1]);
   arguments->salt = strdup (arg);
   break;

 case OPTION_CRYPTO_STR2KEY:
   arguments->command = OPTION_CRYPTO;
   if (arg)
     {
       if (arguments->password)
	 argp_error (state, _("Password specified twice."));
       arguments->password = strdup (arg);
     }
   break;

 case OPTION_CRYPTO_WRITE_DATA_FILE:
   if (arguments->command != OPTION_CRYPTO)
     argp_error (state, _("Option `%s' only valid with CRYPTO."),
		 state->argv[state->next - 1]);
   parse_filename (arg, &arguments->outputtype, &arguments->outputfile);
   if (arguments->outputtype == SHISHI_FILETYPE_TEXT ||
       arguments->outputtype == SHISHI_FILETYPE_DER)
     arguments->outputtype = SHISHI_FILETYPE_BINARY;
   break;

 case OPTION_CRYPTO_WRITE_KEY_FILE:
   if (arguments->command != OPTION_CRYPTO)
     argp_error (state, _("Option `%s' only valid with CRYPTO."),
		 state->argv[state->next - 1]);
   arguments->writekeyfile = strdup (arg);
   break;


}


#if 0
{"key-value", OPTION_CRYPTO_KEY_VALUE, "KEY", 0,
    "Cipher key to decrypt response (discouraged).", 0},
#endif

/************** CRYPTO */

{0, 0, 0, 0,
    "Options for low-level cryptography (CRYPTO-OPTIONS):", 100},

{"client-name", OPTION_CLIENT_NAME, "NAME", 0,
    "Username. Default is login name.", 0},
#if 0
{"decrypt", OPTION_CRYPTO_DECRYPT, 0, 0,
    "Decrypt data.", 0},

{"encrypt", OPTION_CRYPTO_ENCRYPT, 0, 0,
    "Encrypt data.", 0},

{"key-usage", OPTION_CRYPTO_KEY_USAGE, "KEYUSAGE", 0,
    "Encrypt or decrypt using specified key usage.  Default is 0, which "
    "means no key derivation are performed.", 0},

{"key-value", OPTION_CRYPTO_KEY_VALUE, "KEY", 0,
    "Base64 encoded key value.", 0},
#endif
{"key-version", OPTION_CRYPTO_KEY_VERSION, "INTEGER", 0,
    "Version number of key. Default is 0.", 0},

{"random", OPTION_CRYPTO_RANDOM, 0, 0,
    "Generate key from random data.", 0},
#if 0
{"read-key-file", OPTION_CRYPTO_READ_KEY_FILE, "FILE", 0,
    "Read cipher key from FILE", 0},

{"read-data-file", OPTION_CRYPTO_READ_DATA_FILE, "[TYPE,]FILE", 0,
    "Read data from FILE in TYPE, BASE64, HEX or BINARY (default).", 0},
#endif
{"realm", OPTION_REALM, "REALM", 0,
    "Realm of principal. Defaults to DNS domain of local host. ", 0},

{"salt", OPTION_CRYPTO_SALT, "SALT", 0,
    "Salt to use for --string-to-key. Defaults to concatenation of "
    "realm and (unwrapped) client name.", 0},

{"string-to-key", OPTION_CRYPTO_STR2KEY, "[PASSWORD]", OPTION_ARG_OPTIONAL,
    "Convert password into Kerberos key.  Note that --client-name, --realm, "
    "and --salt influence the generated key.", 0},

{"parameter", OPTION_CRYPTO_PARAMETER, "STRING", 0,
    "String-to-key parameter. This data is specific for each encryption "
    "algorithm and rarely needed.", 0},
#if 0
{"write-key-file", OPTION_CRYPTO_WRITE_KEY_FILE, "FILE", 0,
    "Append cipher key to FILE", 0},

{"write-data-file", OPTION_CRYPTO_WRITE_DATA_FILE, "[TYPE,]FILE", 0,
    "Write data to FILE in TYPE, BASE64, HEX or BINARY (default).", 0},
#endif


  case OPTION_CRYPTO:
      rc = crypto (handle, arg);
if (rc != SHISHI_OK)
  fprintf (stderr, "Operation failed:\n%s\n%s\n",
	   shishi_strerror (rc), shishi_error (handle));
break;
