/* cfg.h --- Configuration file functions.
 * Copyright (C) 2002-2021 Simon Josefsson
 *
 * This file is part of Shishi.
 *
 * Shishi is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * Shishi is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Shishi; if not, see http://www.gnu.org/licenses or write
 * to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
 * Floor, Boston, MA 02110-1301, USA
 *
 */

#include "internal.h"

/* Get prototypes. */
#include "cfg.h"

#include "low-crypto.h"

enum
{
  DEFAULT_REALM_OPTION = 0,
  DEFAULT_PRINCIPAL_OPTION,
  CLIENT_KDC_ETYPES_OPTION,
  REALM_KDC_OPTION,
  SERVER_REALM_OPTION,
  KDC_TIMEOUT_OPTION,
  KDC_RETRIES_OPTION,
  TICKET_LIFE_OPTION,
  RENEW_LIFE_OPTION,
  AUTHORIZATION_TYPES_OPTION,
  VERBOSE_CRYPTO_NOISE_OPTION,
  VERBOSE_CRYPTO_OPTION,
  VERBOSE_ASN1_OPTION,
  VERBOSE_NOISE_OPTION,
  VERBOSE_OPTION,
  STRINGPROCESS_OPTION,
  QUICK_RANDOM,
  THE_END
};

static const char *const _shishi_opts[] = {
  /* [DEFAULT_REALM_OPTION] =        */ "default-realm",
  /* [DEFAULT_PRINCIPAL_OPTION] =    */ "default-principal",
  /* [CLIENT_KDC_ETYPES_OPTION] =    */ "client-kdc-etypes",
  /* [REALM_KDC_OPTION] =            */ "realm-kdc",
  /* [SERVER_REALM_OPTION] =         */ "server-realm",
  /* [KDC_TIMEOUT_OPTION] =          */ "kdc-timeout",
  /* [KDC_RETRIES_OPTION] =          */ "kdc-retries",
  /* [TICKET_LIFE_OPTION] =          */ "ticket-life",
  /* [RENEW_LIFE_OPTION] =           */ "renew-life",
  /* [AUTHORIZATION_TYPES_OPTION] =  */ "authorization-types",
  /* [VERBOSE_CRYPTO_NOISE_OPTION] = */ "verbose-crypto-noise",
  /* [VERBOSE_CRYPTO_OPTION] =       */ "verbose-crypto",
  /* [VERBOSE_ASN1_OPTION] =         */ "verbose-asn1",
  /* [VERBOSE_NOISE_OPTION] =        */ "verbose-noise",
  /* [VERBOSE_OPTION] =              */ "verbose",
  /* [STRINGPROCESS_OPTION] =        */ "stringprocess",
  /* [QUICK_RANDOM] =                */ "quick-random",
  /* [THE_END] =                     */ NULL
};

struct Shishi_realminfo *
_shishi_realminfo (Shishi * handle, const char *realm)
{
  size_t i;

  for (i = 0; i < handle->nrealminfos; i++)
    if (strcmp (realm, handle->realminfos[i].name) == 0)
      return &handle->realminfos[i];

  return NULL;
}

struct Shishi_realminfo *
_shishi_realminfo_new (Shishi * handle, char *realm)
{
  struct Shishi_realminfo *ri;

  ri = _shishi_realminfo (handle, realm);
  if (ri)
    return ri;

  handle->realminfos = xrealloc (handle->realminfos,
				 (++handle->nrealminfos) *
				 sizeof (*handle->realminfos));

  ri = &handle->realminfos[handle->nrealminfos - 1];
  memset (ri, 0, sizeof (*ri));
  ri->name = realm;

  return ri;
}

/**
 * shishi_cfg:
 * @handle: Shishi library handle created by shishi_init().
 * @option: String containing shishi library options.
 *
 * Configures the shishi library according to the options
 * given in @option.
 *
 * Return value: Returns %SHISHI_OK if @option is valid
 *   and configuration was successful.
 **/
int
shishi_cfg (Shishi * handle, const char *option)
{
  char *opt = option ? xstrdup (option) : NULL;
  char *p = opt;
  char *value;
  int res;
  size_t i;

  while (p != NULL && *p != '\0')
    {
      switch (getsubopt (&p, (char *const *) _shishi_opts, &value))
	{
	case KDC_TIMEOUT_OPTION:
	  if (value && atoi (value) > 0)
	    handle->kdctimeout = atoi (value);
	  else if (value)
	    shishi_warn (handle, "Invalid KDC timeout value: `%s'", value);
	  else
	    shishi_warn (handle, "Missing KDC timeout value");
	  break;

	case KDC_RETRIES_OPTION:
	  if (value && atoi (value) > 0)
	    handle->kdcretries = atoi (value);
	  else if (value)
	    shishi_warn (handle, "Invalid KDC retries value: `%s'", value);
	  else
	    shishi_warn (handle, "Missing KDC retries value");
	  break;

	case TICKET_LIFE_OPTION:
	  {
	    time_t now = time (NULL);
	    time_t then = shishi_get_date (value, &now);
	    int diff = difftime (then, now);

	    if (value && then != -1 && diff > 0)
	      handle->ticketlife = diff;
	    else if (diff <= 0 && diff + 60 * 60 * 24 > 0)
	      /* Hack to support "17:00" as always meaning the next 17:00. */
	      handle->ticketlife = 60 * 60 * 24 + diff;
	    else if (diff <= 0)
	      shishi_warn (handle, "Negative ticket life date: `%s'", value);
	    else if (then == -1)
	      shishi_warn (handle, "Invalid ticket life date: `%s'", value);
	    else
	      shishi_warn (handle, "Missing ticket life value");
	  }
	  break;

	case RENEW_LIFE_OPTION:
	  {
	    time_t now = time (NULL);
	    time_t then = shishi_get_date (value, &now);
	    int diff = difftime (then, now);

	    if (value && then != -1 && diff > 0)
	      handle->renewlife = diff;
	    else if (diff <= 0)
	      shishi_warn (handle, "Negative renew life date: `%s'", value);
	    else if (then == -1)
	      shishi_warn (handle, "Invalid renew life date: `%s'", value);
	    else
	      shishi_warn (handle, "Missing renew life value");
	  }
	  break;

	case REALM_KDC_OPTION:
	  {
	    struct Shishi_realminfo *ri;
	    char *realm = NULL;
	    char *protstr;
	    int transport = UDP;
	    int add_realm = 1;

	    realm = xstrdup (value);
	    for (i = 0; i < handle->nrealminfos; i++)
	      if (strcmp (realm, handle->realminfos[i].name) == 0)
		{
		  if (handle->realminfos[i].nkdcaddresses > 0 ||
		      handle->realminfos[i].kdcaddresses)
		    {
		      free (handle->realminfos[i].kdcaddresses);
		      handle->realminfos[i].kdcaddresses = NULL;
		      handle->realminfos[i].nkdcaddresses = 0;
		      ri = &handle->realminfos[i];
		      add_realm = 0;
		    }
		  break;
		}
	    if (add_realm)
	      {
		handle->realminfos = xrealloc (handle->realminfos,
					       (handle->nrealminfos + 1) *
					       sizeof (*handle->realminfos));
		memset (&handle->realminfos[handle->nrealminfos], 0,
			sizeof (handle->realminfos[handle->nrealminfos]));
		handle->realminfos[handle->nrealminfos].name = realm;
		ri = &handle->realminfos[handle->nrealminfos];
		handle->nrealminfos++;
	      }
	    if ((protstr = strchr (p, '/')))
	      {
		*protstr = '\0';
		protstr++;
		if (strcasecmp (protstr, "udp") == 0)
		  transport = UDP;
		else if (strcasecmp (protstr, "tcp") == 0)
		  transport = TCP;
		else if (strcasecmp (protstr, "tls") == 0)
		  transport = TLS;
		else
		  shishi_warn (handle,
			       "Ignoring unknown KDC transport: %s",
				   protstr);
	      }

	    ri->kdcaddresses = xrealloc (ri->kdcaddresses,
					 (ri->nkdcaddresses + 1) *
					   sizeof (*ri->kdcaddresses));
	    ri->kdcaddresses[ri->nkdcaddresses].transport = transport;
	    ri->kdcaddresses[ri->nkdcaddresses].hostname = xstrdup (p);
	    if ((protstr = strchr (value, ':')))
	      {
		*protstr = '\0';
		protstr++;
		ri->kdcaddresses[ri->nkdcaddresses].port = protstr;
	      }
	    else
	      ri->kdcaddresses[ri->nkdcaddresses].port = NULL;
	    ri->nkdcaddresses++;

	    p = NULL;	/* Done with suboptions.  */
	  }
	  break;

	case SERVER_REALM_OPTION:
	  {
	    struct Shishi_realminfo *ri;
	    char *subopts, *part, *next;

	    if (!p || (*p == 0))
	      {
		shishi_warn (handle, "Empty server-realm for '%s'.", value);
		break;
	      }

	    ri = _shishi_realminfo_new (handle, xstrdup (value));

	    part = subopts = xstrdup (p);	/* List of patterns.  */
	    while (part && *part)
	      {
		next = strchr (part, ',');
		if (next)
		  *(next++) = '\0';

		ri->serverwildcards = xrealloc (ri->serverwildcards,
						++ri->nserverwildcards *
						sizeof (*ri->serverwildcards));
		ri->serverwildcards[ri->nserverwildcards - 1] = xstrdup (part);
		part = next;
	      }
	    p = NULL;	/* Done with suboptions.  */
	  }
	  break;

	case DEFAULT_REALM_OPTION:
	  handle->default_realm = xstrdup (value);
	  break;

	case DEFAULT_PRINCIPAL_OPTION:
	  handle->default_principal = xstrdup (value);
	  break;

	case CLIENT_KDC_ETYPES_OPTION:
	  res = shishi_cfg_clientkdcetype_set (handle, value);
	  if (res != SHISHI_OK)
	    goto out;
	  break;

	case AUTHORIZATION_TYPES_OPTION:
	  res = shishi_cfg_authorizationtype_set (handle, value);
	  if (res != SHISHI_OK)
	    goto out;
	  break;

	case STRINGPROCESS_OPTION:
	  free (handle->stringprocess);
	  handle->stringprocess = xstrdup (value);
	  break;

	case QUICK_RANDOM:
	  _shishi_quick_random ();
	  break;

	case VERBOSE_OPTION:
	  handle->verbose = value && atoi (value) ? atoi (value) :
	    ~0 & ~VERBOSES;
	  break;

	case VERBOSE_CRYPTO_NOISE_OPTION:
	  handle->verbose |= SHISHI_VERBOSE_CRYPTO_NOISE;
	  break;

	case VERBOSE_CRYPTO_OPTION:
	  handle->verbose |= SHISHI_VERBOSE_CRYPTO;
	  break;

	case VERBOSE_ASN1_OPTION:
	  handle->verbose |= SHISHI_VERBOSE_ASN1;
	  break;

	case VERBOSE_NOISE_OPTION:
	  handle->verbose |= SHISHI_VERBOSE_NOISE;
	  break;

	case -1:
	  if (!value)
	    break;
	  /* fall through */

	default:
	  shishi_warn (handle, "Unknown option: `%s'", value);
	  break;
	}
    }

  res = SHISHI_OK;

out:
  free (opt);
  return res;
}

/**
 * shishi_cfg_from_file:
 * @handle: Shishi library handle created by shishi_init().
 * @cfg: Name of configuration file.
 *
 * Configures the shishi library using a configuration file
 * located at @cfg.
 *
 * Return value: Returns %SHISHI_OK if successful.
 **/
int
shishi_cfg_from_file (Shishi * handle, const char *cfg)
{
  char *line = NULL;
  size_t len = 0;
  FILE *fh;

  if (cfg == NULL)
    return SHISHI_OK;

  fh = fopen (cfg, "r");
  if (fh == NULL)
    return SHISHI_FOPEN_ERROR;

  while (!feof (fh))
    {
      ssize_t n = getline (&line, &len, fh);
      char *p = line;
      char *q;

      if (n <= 0)
	/* End of file or error.  */
	break;

      while (strlen (p) > 0 && (p[strlen (p) - 1] == '\n' ||
				p[strlen (p) - 1] == '\r'))
	p[strlen (p) - 1] = '\0';

      while (*p && strchr (" \t\r\n", *p))
	p++;

      if (*p == '\0' || *p == '#')
	continue;

      q = strchr (p, ' ');
      if (q && (strchr (p, '=') == NULL || q < strchr (p, '=')))
	*q = '=';

      shishi_cfg (handle, p);
    }

  free (line);

  if (ferror (fh))
    shishi_error_printf (handle, "Error reading configuration file");

  if (fclose (fh) != 0)
    return SHISHI_IO_ERROR;

  return SHISHI_OK;
}

const char *
_shishi_transport2string (int transport)
{
  if (transport == UDP)
    return "UDP";
  else if (transport == TCP)
    return "TCP";
  else if (transport == TLS)
    return "TLS";
  else
    return "UNKNOWN";
}

/**
 * shishi_cfg_print:
 * @handle: Shishi library handle created by shishi_init().
 * @fh: File stream handle opened for writing.
 *
 * Prints library configuration status to @fh.  This function is
 * mostly intended for debugging purposes.
 *
 * Return value: Always returns %SHISHI_OK.
 **/
int
shishi_cfg_print (Shishi * handle, FILE * fh)
{
  size_t i, j;
  time_t tmp, now = time (NULL);

  fprintf (fh, "Shishi initial library configuration:\n");
  fprintf (fh, "\tDefault realm: %s\n",
	   handle->default_realm ? handle->default_realm : "(NULL)");
  fprintf (fh, "\tDefault principal: %s\n",
	   handle->default_principal ? handle->default_principal : "(NULL)");
  fprintf (fh, "\tClient KDC etypes:");
  for (i = 0; i < handle->nclientkdcetypes; i++)
    fprintf (fh, " %s", shishi_cipher_name (handle->clientkdcetypes[i]));
  fprintf (fh, "\n");
  fprintf (fh, "\tVerbose: %d\n", handle->verbose);
  tmp = now + handle->ticketlife;
  fprintf (fh, "\tTicket life: %d seconds. %s",
	   handle->ticketlife, ctime (&tmp));
  tmp = now + handle->renewlife;
  fprintf (fh, "\tRenew life: %d seconds. %s",
	   handle->renewlife, ctime (&tmp));
  for (i = 0; i < handle->nrealminfos; i++)
    {
      fprintf (fh, "\tKDCs for realm %s:\n", handle->realminfos[i].name);
      for (j = 0; j < handle->realminfos[i].nkdcaddresses; j++)
	fprintf (fh, "\t\tTransport %s host %s port %s\n",
		 _shishi_transport2string (handle->realminfos[i].
					   kdcaddresses[j].transport),
		 handle->realminfos[i].kdcaddresses[j].hostname,
		 handle->realminfos[i].kdcaddresses[j].port);
    }

  return SHISHI_OK;
}

/**
 * shishi_cfg_default_systemfile:
 * @handle: Shishi library handle created by shishi_init().
 *
 * The system configuration file name is decided at compile
 * time, but is replaced by assigning another file name to
 * the environment variable $SHISHI_CONFIG.  This call offers
 * a single interface for determining the file name, to which
 * the library turns for its settings.
 *
 * Return value: Returns file name of present system configuration.
 **/
const char *
shishi_cfg_default_systemfile (Shishi * handle)
{
  char *file;

  file = getenv ("SHISHI_CONFIG");
  if (file)
    return file;

  return SYSTEMCFGFILE;
}

#define BASE_DIR "/.shishi"

/**
 * shishi_cfg_default_userdirectory:
 * @handle: Shishi library handle created by shishi_init().
 *
 * The default user directory, referred to for Shishi ticket cache
 * and other purposes, is normally computed by appending the fixed
 * string "/.shishi" to the content of the environment variable $HOME.
 *
 * This hard coded directory, i.e., "$HOME/.shishi/", can be replaced
 * by whatever complete path is stored in the environment variable
 * $SHISHI_HOME.
 *
 * Return value: Returns the user's directory name where the Shishi
 *   library will search for configuration files, ticket caches,
 *   etcetera.
 **/
const char *
shishi_cfg_default_userdirectory (Shishi * handle)
{
  char *home;
  char *envdir;

  envdir = getenv ("SHISHI_HOME");
  if (envdir)
    return envdir;

  if (!handle->userdirectory)
    {
      home = getenv ("HOME");

      asprintf (&handle->userdirectory, "%s%s", home ? home : "", BASE_DIR);
    }

  return handle->userdirectory;
}

/**
 * shishi_cfg_userdirectory_file:
 * @handle: Shishi library handle created by shishi_init().
 * @file: Basename of file to use for the user's configuration
 *   settings of the library.
 *
 * Reports the full path to the file where the Shishi library
 * expects to find the user's library configuration, given that
 * the file itself is named by the parameter @file.
 *
 * The answer is composed from the value of @file and the directory
 * returned by shishi_cfg_default_userdirectory().  Typically, the
 * returned string would be expanded from "$HOME/.shishi/@file".
 *
 * Return value: Returns the absolute filename to the argument @file,
 *   relative to the user specific Shishi configuration directory.
 **/
char *
shishi_cfg_userdirectory_file (Shishi * handle, const char *file)
{
  char *out;

  asprintf (&out, "%s/%s", shishi_cfg_default_userdirectory (handle), file);

  return out;
}

#define USERCFG_FILE "shishi.conf"

/**
 * shishi_cfg_default_userfile:
 * @handle: Shishi library handle created by shishi_init().
 *
 * Reports the absolute filename of the default user configuration
 * file.  This is typically "$HOME/.shishi/shishi.conf".
 *
 * The value of $SHISHI_HOME will change the directory part,
 * as stated regarding shishi_cfg_default_userdirectory().
 *
 * Return value: Returns the user's configuration filename.
 **/
const char *
shishi_cfg_default_userfile (Shishi * handle)
{
  if (!handle->usercfgfile)
    handle->usercfgfile =
      shishi_cfg_userdirectory_file (handle, USERCFG_FILE);

  return handle->usercfgfile;
}

/**
 * shishi_cfg_clientkdcetype:
 * @handle: Shishi library handle created by shishi_init().
 * @etypes: Pointer to an array of encryption types.
 *
 * Sets the variable @etypes to a static array of preferred encryption
 * types applicable to clients.
 *
 * Return value: Returns the number of encryption types referred to
 *   by the updated array pointer, or zero, should no type exist.
 **/
int
shishi_cfg_clientkdcetype (Shishi * handle, int32_t ** etypes)
{
  *etypes = handle->clientkdcetypes;
  return handle->nclientkdcetypes;
}

/**
 * shishi_cfg_clientkdcetype_fast:
 * @handle: Shishi library handle created by shishi_init().
 *
 * Extracts the default encryption type from the list of preferred
 * encryption types acceptable to the client.
 *
 * When the preferred list is empty, %SHISHI_AES256_CTS_HMAC_SHA1_96
 * is returned as a sensible default type.
 *
 * Return value: Returns the default encryption type.
 **/
int32_t
shishi_cfg_clientkdcetype_fast (Shishi * handle)
{
  if (handle->nclientkdcetypes > 0)
    return handle->clientkdcetypes[0];
  else
    return SHISHI_AES256_CTS_HMAC_SHA1_96;
}

/**
 * shishi_cfg_clientkdcetype_set:
 * @handle: Shishi library handle created by shishi_init().
 * @value: String naming acceptable encryption types.
 *
 * Sets the configuration option "client-kdc-etypes" from @value.
 * The string contains encryption types, integers or names,
 * separated by comma or by whitespace.  An example naming three
 * encryption types could be:
 *
 * aes256-cts-hmac-sha1-96  des3-cbc-sha1-kd  des-cbc-md5
 *
 * Return value: Returns %SHISHI_OK if successful, and
 *   %SHISHI_INVALID_ARGUMENT otherwise.
 **/
int
shishi_cfg_clientkdcetype_set (Shishi * handle, char *value)
{
  char *ptrptr;
  char *val, *tmpvalue;
  int i;
  int tot = 0;
  int rc = SHISHI_INVALID_ARGUMENT;

  if (value == NULL || *value == '\0')
    return SHISHI_OK;

  tmpvalue = xstrdup (value);

  for (i = 0; (val = strtok_r (i == 0 ? tmpvalue : NULL, ", \t", &ptrptr)); i++)
    {
      int etype = shishi_cipher_parse (val);

      if (etype == -1)
	shishi_warn (handle, "Ignoring unknown encryption type: `%s'", val);
      else
	{
	  int *new;

	  tot++;
	  new = xrealloc (handle->clientkdcetypes,
			  tot * sizeof (*handle->clientkdcetypes));
	  handle->clientkdcetypes = new;
	  handle->clientkdcetypes[tot - 1] = etype;
	  handle->nclientkdcetypes = tot;
	  rc = SHISHI_OK;	/* At least one valid type.  */
	}
    }

  free (tmpvalue);

  return rc;
}

/**
 * shishi_cfg_authorizationtype_set:
 * @handle: Shishi library handle created by shishi_init().
 * @value: String listing acceptable authorization types.
 *
 * Sets the configuration option "authorization-types" from @value.
 * The string contains authorization types, integers or names,
 * separated by comma or whitespace.
 *
 * As an example, "k5login basic" would first check Kerberos5
 * authentication based on preset principals, and then fall back
 * to the basic test of identical principal names.
 *
 * Return value: Returns %SHISHI_OK if successful, and
 *   %SHISHI_INVALID_ARGUMENT otherwise.
 **/
int
shishi_cfg_authorizationtype_set (Shishi * handle, char *value)
{
  char *ptrptr;
  char *val, *tmpvalue;
  int i;
  int tot = 0;
  int rc = SHISHI_INVALID_ARGUMENT;

  if (value == NULL || *value == '\0')
    return SHISHI_OK;

  tmpvalue = xstrdup (value);

  for (i = 0; (val = strtok_r (i == 0 ? tmpvalue : NULL, ", \t", &ptrptr)); i++)
    {
      int atype = shishi_authorization_parse (val);

      if (atype == -1)
	shishi_warn (handle, "Ignoring unknown authorization type: `%s'",
		     val);
      else
	{
	  int *new;

	  tot++;
	  new = xrealloc (handle->authorizationtypes,
			  tot * sizeof (*handle->authorizationtypes));
	  handle->authorizationtypes = new;
	  handle->authorizationtypes[tot - 1] = atype;
	  handle->nauthorizationtypes = tot;
	  rc = SHISHI_OK;	/* At least one valid type.  */
	}
    }

  free (tmpvalue);

  return rc;
}
