/* cfg.c	configuration file functions.
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

#include "internal.h"

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
  VERBOSE_CRYPTO_NOICE_OPTION,
  VERBOSE_CRYPTO_OPTION,
  VERBOSE_ASN1_OPTION,
  VERBOSE_NOICE_OPTION,
  VERBOSE_OPTION,
  STRINGPROCESS_OPTION,
  THE_END
};

static char *const _shishi_opts[] = {
  /* [DEFAULT_REALM_OPTION] =        */ "default-realm",
  /* [DEFAULT_PRINCIPAL_OPTION] =    */ "default-principal",
  /* [CLIENT_KDC_ETYPES_OPTION] =    */ "client-kdc-etypes",
  /* [REALM_KDC_OPTION] =            */ "realm-kdc",
  /* [SERVER_REALM_OPTION] =         */ "server-realm",
  /* [KDC_TIMEOUT_OPTION] =          */ "kdc-timeout",
  /* [KDC_RETRIES_OPTION] =          */ "kdc-retries",
  /* [TICKET_LIFE_OPTION] =          */ "ticket-life",
  /* [RENEW_LIFE_OPTION] =           */ "renew-life",
  /* [VERBOSE_CRYPTO_NOICE_OPTION] = */ "verbose-crypto-noice",
  /* [VERBOSE_CRYPTO_OPTION] =       */ "verbose-crypto",
  /* [VERBOSE_ASN1_OPTION] =         */ "verbose-asn1",
  /* [VERBOSE_NOICE_OPTION] =        */ "verbose-noice",
  /* [VERBOSE_OPTION] =              */ "verbose",
  /* [STRINGPROCESS_OPTION] =        */ "stringprocess",
  /* [THE_END] =                     */ NULL
};

int getsubopt (char **optionp, char *const *tokens, char **valuep);

struct Shishi_realminfo *
shishi_realminfo (Shishi * handle, const char *realm)
{
  size_t i;

  for (i = 0; i < handle->nrealminfos; i++)
    if (strcmp (realm, handle->realminfos[i].name) == 0)
      return &handle->realminfos[i];

  return NULL;
}

struct Shishi_realminfo *
shishi_realminfo_new (Shishi * handle, char *realm)
{
  struct Shishi_realminfo *ri;

  ri = shishi_realminfo (handle, realm);
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
 * @handle: Shishi library handle create by shishi_init().
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
  char *realm = NULL;
  int res;
  size_t i;

  while (option != NULL && *option != '\0')
    {
      switch (getsubopt (&option, _shishi_opts, &value))
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
	    time_t then = get_date (value, &now);
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
	    time_t then = get_date (value, &now);
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
	  realm = xstrdup (value);
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
	  handle->realminfos = xrealloc (handle->realminfos,
					 (handle->nrealminfos + 1) *
					 sizeof (*handle->realminfos));
	  handle->realminfos[handle->nrealminfos].name = realm;
	  handle->realminfos[handle->nrealminfos].kdcaddresses = NULL;
	  handle->realminfos[handle->nrealminfos].nkdcaddresses = 0;
	  handle->nrealminfos++;
	  break;

	case SERVER_REALM_OPTION:
	  {
	    struct Shishi_realminfo *ri;
	    ri = shishi_realminfo_new (handle, value);
	    ri->serverwildcards = xrealloc (ri->serverwildcards,
					    ++ri->nserverwildcards *
					    sizeof (*ri->serverwildcards));
	    ri->serverwildcards[ri->nserverwildcards - 1] = xstrdup (value);
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
	    return res;
	  break;

	case STRINGPROCESS_OPTION:
	  handle->stringprocess = xstrdup (value);
	  break;

	case VERBOSE_OPTION:
	  handle->verbose = value && atoi (value) ? atoi (value) :
	    ~0 & ~VERBOSES;
	  break;

	case VERBOSE_CRYPTO_NOICE_OPTION:
	  handle->verbose |= SHISHI_VERBOSE_CRYPTO_NOICE;
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
	  if (!value)
	    break;
	  for (i = 0; i < handle->nrealminfos; i++)
	    if (realm && handle->realminfos[i].name == realm)
	      {
		struct Shishi_realminfo *ri = &handle->realminfos[i];
		struct sockaddr_in *sinaddr;
		struct hostent *he;
		struct servent *se;
		char *p;
		int protocol = UDP;

		if ((p = strchr (value, '/')))
		  {
		    *p = '\0';
		    p++;
		    if (strcmp (p, "udp") == 0)
		      protocol = UDP;
		    else if (strcmp (p, "tcp") == 0)
		      protocol = TCP;
		    else if (strcmp (p, "tls") == 0)
		      protocol = TLS;
		    else
		      shishi_warn (handle,
				   "Ignoring unknown KDC parameter: %s", p);
		  }

		he = gethostbyname (value);	/* XXX move to netio.c */
		if (he == NULL ||
		    he->h_addr_list[0] == NULL || he->h_addrtype != AF_INET)
		  {
		    shishi_warn (handle,
				 "Unknown KDC host `%s' (h_errno %d)",
				 value, h_errno);
		    break;
		  }

		ri->kdcaddresses = xrealloc (ri->kdcaddresses,
					     (ri->nkdcaddresses + 1) *
					     sizeof (*ri->kdcaddresses));
		ri->kdcaddresses[ri->nkdcaddresses].name = xstrdup (value);
		ri->kdcaddresses[ri->nkdcaddresses].protocol = protocol;
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
	  shishi_warn (handle, "Unknown option: `%s'", value);
	  break;
	}
    }

  return SHISHI_OK;
}

/**
 * shishi_cfg_from_file:
 * @handle: Shishi library handle create by shishi_init().
 * @cfg: filename to read configuration from.
 *
 * Configure shishi library using configuration file.
 *
 * Return Value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_cfg_from_file (Shishi * handle, const char *cfg)
{
  struct linebuffer lb;
  FILE *fh;

  if (cfg == NULL)
    return SHISHI_OK;

  fh = fopen (cfg, "r");
  if (fh == NULL)
    {
      shishi_warn (handle, "`%s': %s", cfg, strerror (errno));
      return SHISHI_FOPEN_ERROR;
    }

  initbuffer (&lb);

  while (readlinebuffer (&lb, fh))
    {
      char *p = lb.buffer;
      char *q;

      p[lb.length - 1] = '\0';

      while (*p && strchr (" \t\r\n", *p))
	p++;

      if (*p == '\0' || *p == '#')
	continue;

      q = strchr (p, ' ');
      if (q && (strchr (p, '=') == NULL || q < strchr (p, '=')))
	*q = '=';

      shishi_cfg (handle, p);
    }

  if (ferror (fh))
    shishi_error_printf (handle, "Error reading configuration file");

  freebuffer (&lb);

  if (fclose (fh) != 0)
    return SHISHI_FCLOSE_ERROR;

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
  fprintf (fh, "\tKDC: %s\n", handle->kdc ? handle->kdc : "(NULL)");
  fprintf (fh, "\tVerbose: %d\n", handle->verbose);
  tmp = now + handle->ticketlife;
  fprintf (fh, "\tTicket life: %d seconds. %s",
	   handle->ticketlife, ctime (&tmp));
  tmp = now + handle->renewlife;
  fprintf (fh, "\tRenew life: %d seconds. %s",
	   handle->renewlife, ctime (&tmp));
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
 * shishi_cfg_default_userdirectory:
 * @handle: Shishi library handle create by shishi_init().
 *
 * Return value: Return directory with configuration files etc.
 **/
const char *
shishi_cfg_default_userdirectory (Shishi * handle)
{
  char *home;

  if (!handle->userdirectory)
    {
      home = getenv ("HOME");

      if (home == NULL)
	home = "";

      asprintf (&handle->userdirectory, "%s%s", home, BASE_DIR);
    }

  return handle->userdirectory;
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

      asprintf (&handle->usercfgfile, "%s%s", home, USERCFG_FILE);
    }

  return handle->usercfgfile;
}

/**
 * shishi_cfg_clientkdcetype:
 * @handle: Shishi library handle create by shishi_init().
 * @etypes: output array with encryption types.
 *
 * Set the etypes variable to the array of preferred client etypes.
 *
 * Return value: Return the number of encryption types in the array,
 *               0 means none.
 **/
int
shishi_cfg_clientkdcetype (Shishi * handle, int32_t ** etypes)
{
  *etypes = handle->clientkdcetypes;
  return handle->nclientkdcetypes;
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

  for (i = 0; (val = strtok_r (i == 0 ? value : NULL, ", \t", &ptrptr)); i++)
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
	}
    }

  return SHISHI_OK;
}
