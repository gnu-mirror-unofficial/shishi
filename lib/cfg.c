/* cfg.c	configuration file functions.
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

#include "internal.h"

enum
{
  DEFAULT_REALM_OPTION = 0,
  DEFAULT_PRINCIPAL_OPTION,
  CLIENT_KDC_ETYPES_OPTION,
  REALM_KDC_OPTION,
  KDC_OPTION,
  KDC_TIMEOUT_OPTION,
  KDC_RETRIES_OPTION,
  VERBOSE_CRYPTO_OPTION,
  VERBOSE_ASN1_OPTION,
  VERBOSE_NOICE_OPTION,
  VERBOSE_OPTION,
  STRINGPROCESS_OPTION,
  THE_END
};

static const char *_shishi_opts[] = {
  /* [DEFAULT_REALM_OPTION] =     */ "default-realm",
  /* [DEFAULT_PRINCIPAL_OPTION] = */ "default-principal",
  /* [CLIENT_KDC_ETYPES_OPTION] = */ "client-kdc-etypes",
  /* [REALM_KDC_OPTION] =         */ "realm-kdc",
  /* [KDC_OPTION] =               */ "kdc",
  /* [KDC_TIMEOUT_OPTION] =       */ "kdc-timeout",
  /* [KDC_RETRIES_OPTION] =       */ "kdc-retries",
  /* [VERBOSE_CRYPTO_OPTION] =    */ "verbose-crypto",
  /* [VERBOSE_ASN1_OPTION] =      */ "verbose-asn1",
  /* [VERBOSE_NOICE_OPTION] =     */ "verbose-noice",
  /* [VERBOSE_OPTION] =           */ "verbose",
  /* [STRINGPROCESS_OPTION] =     */ "stringprocess",
  /* [THE_END] =                  */ NULL
};

/**
 * shishi_cfg:
 * @option: string with shishi library option.
 *
 * Configure shishi library with given option.
 *
 * Return Value: Returns SHISHI_OK if option was valid.
 **/
int
shishi_cfg (Shishi * handle, char *option)
{
  char *value;
  char *tmp;
  char *realm = NULL;
  int res;
  int i;

  while (option != NULL && *option != '\0')
    {
      switch (getsubopt (&option, _shishi_opts, &value))
	{
	case KDC_TIMEOUT_OPTION:
	  if (value && atoi (value) > 0)
	    handle->kdctimeout = atoi (value);
	  else if (value)
	    fprintf (stderr, "Invalid KDC timeout value: `%s'\n", value);
	  else
	    fprintf (stderr, "Missing KDC timeout value.\n");
	  break;

	case KDC_RETRIES_OPTION:
	  if (value && atoi (value) > 0)
	    handle->kdcretries = atoi (value);
	  else if (value)
	    fprintf (stderr, "Invalid KDC retries value: `%s'\n", value);
	  else
	    fprintf (stderr, "Missing KDC retries value.\n");
	  break;

	case REALM_KDC_OPTION:
	  realm = strdup (value);
	  for (i = 0; i < handle->nrealminfos; i++)
	    if (strcmp (realm, handle->realminfos[i].name) == 0)
	      {
		if (handle->realminfos[i].nkdcaddresses > 0 ||
		    handle->realminfos[i].kdcaddresses)
		  {
		    if (handle->realminfos[i].kdcaddresses)
		      free (handle->realminfos[i].kdcaddresses);
		    handle->realminfos[i].kdcaddresses = NULL;
		    handle->realminfos[i].nkdcaddresses = 0;
		  }
		break;
	      }
	  handle->realminfos = realloc (handle->realminfos,
					(handle->nrealminfos + 1) *
					sizeof (*handle->realminfos));
	  if (handle->realminfos == NULL)
	    return SHISHI_MALLOC_ERROR;
	  handle->realminfos[handle->nrealminfos].name = realm;
	  handle->realminfos[handle->nrealminfos].kdcaddresses = NULL;
	  handle->realminfos[handle->nrealminfos].nkdcaddresses = 0;
	  handle->nrealminfos++;
	  break;
	case DEFAULT_REALM_OPTION:
	  handle->default_realm = strdup (value);
	  break;
	case DEFAULT_PRINCIPAL_OPTION:
	  handle->default_principal = strdup (value);
	  break;
	case CLIENT_KDC_ETYPES_OPTION:
	  res = shishi_cfg_clientkdcetype_set (handle, value);
	  if (res != SHISHI_OK)
	    return res;
	  break;
	case KDC_OPTION:
	  handle->kdc = strdup (value);
	  break;
	case STRINGPROCESS_OPTION:
	  handle->stringprocess = strdup (value);
	  break;
	case VERBOSE_OPTION:
	  handle->verbose = value && atoi (value) ? atoi (value) :
	    ~0 & ~VERBOSES;
	  break;
	case VERBOSE_CRYPTO_OPTION:
	  handle->verbose |= SHISHI_VERBOSE_CRYPTO;
	  break;
	case VERBOSE_ASN1_OPTION:
	  handle->verbose |= SHISHI_VERBOSE_ASN1;
	  break;
	case VERBOSE_NOICE_OPTION:
	  handle->verbose |= SHISHI_VERBOSE_NOICE;
	  break;
	case -1:
	  for (i = 0; i < handle->nrealminfos; i++)
	    if (realm && handle->realminfos[i].name == realm)
	      {
		struct Shishi_realminfo *ri = &handle->realminfos[i];
		struct sockaddr_in *sinaddr;
		struct hostent *he;
		struct servent *se;

		he = gethostbyname (value);
		if (he == NULL ||
		    he->h_addr_list[0] == NULL || he->h_addrtype != AF_INET)
		  {
		    fprintf (stderr, "Unknown KDC host `%s' (h_errno %d)\n",
			     value, h_errno);
		    break;
		  }

		ri->kdcaddresses = realloc (ri->kdcaddresses,
					    (ri->nkdcaddresses + 1) *
					    sizeof (*ri->kdcaddresses));
		if (ri->kdcaddresses == NULL)
		  return SHISHI_MALLOC_ERROR;
		ri->kdcaddresses[ri->nkdcaddresses].name = strdup (value);
		sinaddr = (struct sockaddr_in *)
		  &ri->kdcaddresses[ri->nkdcaddresses].sockaddress;
		memset (sinaddr, 0, sizeof (struct sockaddr));
		ri->nkdcaddresses++;

		sinaddr->sin_family = he->h_addrtype;
		memcpy (&sinaddr->sin_addr, he->h_addr_list[0], he->h_length);
		se = getservbyname ("kerberos", NULL);
		if (se)
		  sinaddr->sin_port = se->s_port;
		else
		  sinaddr->sin_port = htons (88);
	      }
	  if (realm)
	    break;
	  /* fall through */

	default:
	  fprintf (stderr, "Unknown option `%s'\n", value);
	  break;
	}
    }

  return SHISHI_OK;
}

/**
 * shishi_cfg_from_file:
 * @cfg: filename to read configuration from.
 *
 * Configure shishi library using configuration file.
 *
 * Return Value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_cfg_from_file (Shishi * handle, const char *cfg)
{
  char line[BUFSIZ];
  char *value;
  char *tmp;
  int res;
  FILE *fh;

  if (cfg == NULL)
    return SHISHI_OK;

  fh = fopen (cfg, "r");
  if (fh == NULL)
    {
      shishi_warn (handle, "`%s': %s", cfg, strerror (errno));
      return SHISHI_FOPEN_ERROR;
    }

  while (!feof (fh) && !ferror (fh))
    {
      if (!fgets (line, sizeof (line), fh))
	continue;

      line[strlen (line) - 1] = '\0';

      while (line[0] && strchr (" \t\r\n", line[0]))
	memmove (line, line + 1, strlen (line));

      if (line[0] == '#' || line[0] == '\0')
	continue;

      if (strchr (line, ' ') && (strchr (line, '=') == NULL ||
				 strchr (line, ' ') < strchr (line, '=')))
	{
	  char *p = strchr (line, ' ');
	  while (*(p + 1) == ' ' || *(p + 1) == '=')
	    memmove (p, p + 1, strlen (p + 1) + 1);
	  *p = '=';
	}

      shishi_cfg (handle, line);
    }

  if (fclose (fh) != 0)
    return SHISHI_FCLOSE_ERROR;

  if (VERBOSE (handle))
    shishi_cfg_print (handle, stdout);

  return SHISHI_OK;
}

/**
 * shishi_cfg_print:
 * @handle: Shishi library handle create by shishi_init().
 * @fh: file descriptor opened for writing.
 *
 * Print library configuration status, mostly for debugging purposes.
 *
 * Return Value: Returns SHISHI_OK.
 **/
int
shishi_cfg_print (Shishi * handle, FILE * fh)
{
  int i, j;

  fprintf (fh, "Shishi initial library configuration:\n");
  fprintf (fh, "\tDefault realm: %s\n",
	   handle->default_realm ? handle->default_realm : "(NULL)");
  fprintf (fh, "\tDefault principal: %s\n",
	   handle->default_principal ? handle->default_principal : "(NULL)");
  fprintf (fh, "\tClient KDC etypes:");
  for (i = 0; i < handle->nclientkdcetypes; i++)
    fprintf (fh, " %s", shishi_cipher_name (handle->clientkdcetypes[i]));
  fprintf (fh, "\n");
  fprintf (fh, "\tKDC: %s\n", handle->kdc ? handle->kdc : "(NULL)");
  fprintf (fh, "\tVerbose: %d\n", handle->verbose);
  for (i = 0; i < handle->nrealminfos; i++)
    {
      fprintf (fh, "\tRealm %s's KDCs:", handle->realminfos[i].name);
      for (j = 0; j < handle->realminfos[i].nkdcaddresses; j++)
	fprintf (fh, " %s (%s)", handle->realminfos[i].kdcaddresses[j].name,
		 inet_ntoa (((struct sockaddr_in *) &handle->realminfos[i].
			     kdcaddresses[j].sockaddress)->sin_addr));
      fprintf (fh, "\n");
    }

  return SHISHI_OK;
}

/**
 * shishi_cfg_default_systemfile:
 * @handle: Shishi library handle create by shishi_init().
 *
 * Return value: Return system configuration filename.
 **/
const char *
shishi_cfg_default_systemfile (Shishi * handle)
{
  return SYSTEMCFGFILE;
}

/**
 * shishi_cfg_default_userfile:
 * @handle: Shishi library handle create by shishi_init().
 *
 * Return value: Return user configuration filename.
 **/
const char *
shishi_cfg_default_userfile (Shishi * handle)
{
  char *home;

  if (!handle->usercfgfile)
    {
      home = getenv ("HOME");

      if (home == NULL)
	home = "";

      shishi_asprintf (&handle->usercfgfile, "%s%s", home, USERCFG_FILE);
    }

  return handle->usercfgfile;
}

/**
 * shishi_cfg_clientkdcetype_set:
 * @handle: Shishi library handle create by shishi_init().
 * @value: string with encryption types.
 *
 * Set the "client-kdc-etypes" configuration option from given string.
 * The string contains encryption types (integer or names) separated
 * by comma or whitespace, e.g. "aes256-cts-hmac-sha1-96
 * des3-cbc-sha1-kd des-cbc-md5".
 *
 * Return value: Return SHISHI_OK iff successful.
 **/
int
shishi_cfg_clientkdcetype_set (Shishi * handle, char *value)
{
  char *ptrptr;
  char *val;
  int i;
  int tot = 0;

  if (value == NULL || *value == '\0')
    return SHISHI_OK;

  for (i = 0; val = strtok_r (i == 0 ? value : NULL, ", \t", &ptrptr); i++)
    {
      int etype = shishi_cipher_parse (val);

      if (etype == -1)
	fprintf (stderr, "Ignoring unknown encryption type: `%s'\n", val);
      else
	{
	  int *new;

	  tot++;
	  new = realloc (handle->clientkdcetypes,
			 tot * sizeof (*handle->clientkdcetypes));
	  if (handle->clientkdcetypes == NULL)
	    return SHISHI_MALLOC_ERROR;
	  handle->clientkdcetypes = new;
	  handle->clientkdcetypes[tot - 1] = etype;
	  handle->nclientkdcetypes = tot;
	}
    }

  return SHISHI_OK;
}
