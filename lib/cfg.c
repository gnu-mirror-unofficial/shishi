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
  KDC_OPTION,
  VERBOSE_OPTION,
  DEBUG_OPTION,
  THE_END
};

static const char *_shishi_opts[] = {
  /* [DEFAULT_REALM_OPTION] =     */ "default-realm",
  /* [DEFAULT_PRINCIPAL_OPTION] = */ "default-principal",
  /* [CLIENT_KDC_ETYPES_OPTION] = */ "client-kdc-etypes",
  /* [KDC_OPTION] =               */ "kdc",
  /* [VERBOSE_OPTION] =           */ "verbose",
  /* [DEBUG_OPTION] =             */ "debug",
  /* [THE_END] =                  */ NULL
};

/**
 * shishi_cfg:
 * @option: string with shishi library option.
 *
 * Configure shishi library with option..
 * 
 * Return Value: Returns SHISHI_OK if option was valid.
 **/
int
shishi_cfg (Shishi * handle, char *option)
{
  char *value;
  char *tmp;
  int res;

  while (option != NULL && *option != '\0')
    {
      switch (getsubopt (&option, _shishi_opts, &value))
	{
	case DEFAULT_REALM_OPTION:
	  handle->default_realm = strdup(value);
	  break;
	case DEFAULT_PRINCIPAL_OPTION:
	  handle->default_principal = strdup(value);
	  break;
	case CLIENT_KDC_ETYPES_OPTION:
	  {
	    char *ptrptr;
	    char *val;
	    int i;
	    int tot = 0;

	    for (i = 0; 
		 val = strtok_r(i == 0 ? value : NULL, ", \t\n\r", &ptrptr); 
		 i++)
	      {
		int etype = shishi_etype_parse (val);

		if (etype == -1)
		  fprintf(stderr, "Ignoring unknown encryption type: `%s'\n", 
			  val);
		else
		  {
		    int *new;

		    tot++;
		    new = realloc(handle->clientkdcetypes, 
				  tot * sizeof(*handle->clientkdcetypes));
		    if (handle->clientkdcetypes == NULL)
		      return SHISHI_MALLOC_ERROR;
		    handle->clientkdcetypes = new;
		    handle->clientkdcetypes[tot-1] = etype;
		    handle->nclientkdcetypes = tot;
		  }
	      }
	  }
	  break;
	case KDC_OPTION:
	  handle->kdc = strdup(value);
	  break;
	case VERBOSE_OPTION:
	  handle->verbose = 1;
	  break;
	case DEBUG_OPTION:
	  handle->debug = value && atoi (value) ? atoi (value) : 1;
	  break;
	default:
	  fprintf (stderr, "Unknown option `%s'\n", value);
	  break;
	}
    }


  return SHISHI_OK;
}

/**
 * shishi_readcfg:
 * @cfg: filename to read configuration from.
 *
 * Configure shishi library using configuration file.
 * 
 * Return Value: Returns SHISHI_OK.
 **/
int
shishi_readcfg (Shishi * handle, char *cfg)
{
  char line[BUFSIZ];
  char *value;
  char *tmp;
  int res;
  FILE *fh;

  if (cfg == NULL)
    return SHISHI_OK;

  fh = fopen(cfg, "r");
  if (fh == NULL)
    return SHISHI_FOPEN_ERROR;

  while (!feof(fh) && !ferror(fh))
    {
      if (!fgets(line, sizeof(line), fh))
	continue;

      line[strlen(line)-1] = '\0';

      while (line[0] && strchr(" \t\r\n", line[0]))
	memmove(line, line+1, strlen(line));

      if (line[0] == '#' || line[0] == '\0')
	continue;

      if (strchr(line, ' ') && (strchr(line, '=') == NULL || 
				strchr(line, ' ') < strchr(line, '=')))
	*strchr(line, ' ') = '=';

      shishi_cfg(handle, line);
    }

  if (fclose(fh) != 0)
   return SHISHI_FCLOSE_ERROR;

  if (shishi_debug(handle))
    shishi_dumpcfg(handle);

  return SHISHI_OK;
}

/**
 * shishi_dumpcfg: 
 * @handle: Shishi library handle create by shishi_init().
 * 
 * Return Value: Returns SHISHI_OK.
 **/
int
shishi_dumpcfg (Shishi * handle)
{
  int i;

  printf ("Shishi initial library configuration:\n");
  printf ("\tDefault realm: %s\n",
	  handle->default_realm ? handle->default_realm : "(NULL)");
  printf ("\tDefault principal: %s\n",
	  handle->default_principal ? handle->
	  default_principal : "(NULL)");
  printf("\tClient KDC etypes:");
  for (i=0; i < handle->nclientkdcetypes; i++)
    printf(" %s", shishi_cipher_name(handle->clientkdcetypes[i]));
  printf("\n");
  printf ("\tKDC: %s\n", handle->kdc ? handle->kdc : "(NULL)");
  printf ("\tVerbose: %d\n", handle->verbose);
  printf ("\tDebug: %d\n", handle->debug);

  return SHISHI_OK;
}
