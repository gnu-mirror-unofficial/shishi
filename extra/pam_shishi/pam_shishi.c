/* pam_shishi.c	PAM module using Shishi.
 * Copyright (C) 2002-2012 Simon Josefsson
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Shishi; if not, see http://www.gnu.org/licenses or write
 * to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
 * Floor, Boston, MA 02110-1301, USA
 *
 */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef STDC_HEADERS
# include <stdio.h>
# include <stdlib.h>
# include <stdarg.h>
# include <ctype.h>
# include <string.h>
#endif

#include <shishi.h>

/* These #defines must be present according to PAM documentation. */
#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_SECURITY_PAM_APPL_H
# include <security/pam_appl.h>
#endif
#ifdef HAVE_SECURITY_PAM_MODULES_H
# include <security/pam_modules.h>
#endif

#ifdef HAVE_SECURITY_PAM_EXT_H
# include <syslog.h>
# include <security/pam_ext.h>
# define SHISHI_LINUXPAM_LOGGING 1
#endif
#ifdef HAVE_SECURITY_OPENPAM_H
# include <security/openpam.h>
# define SHISHI_OPENPAM_LOGGING 1
#endif

#if defined DEBUG_PAM && defined HAVE_SECURITY__PAM_MACROS_H
# define DEBUG
# include <security/_pam_macros.h>
#else
# define D(x)			/* nothing */
#endif

/* Rely on <security/pam_modules.h>
 * for settings in general, as PAM_EXTERN
 * is not universal among PAM implementations.
 */
#ifndef PAM_EXTERN
# define PAM_EXTERN
#endif /* !PAM_EXTERN */

/* Flagging of options.  */
static int opt_debug;
static const char *opt_principal = NULL;
static const char *opt_realm = NULL;

static char *servername = NULL;
static char *principal = NULL;

void
parse_argv (int argc, const char **argv)
{
  int i;

  for (i = 0; i < argc; i++)
    {
      if (!strcmp ("debug", argv[i]))
	opt_debug++;
      else if (!strncmp ("principal=", argv[i], strlen ("principal=")))
	opt_principal = argv[i] + strlen ("principal=");
      else if (!strncmp ("realm=", argv[i], strlen ("realm=")))
	opt_realm = argv[i] + strlen ("realm=");
    }
}

PAM_EXTERN int
pam_sm_authenticate (pam_handle_t * pamh,
		     int flags, int argc, const char **argv)
{
  Shishi *h = NULL;
  Shishi_key *key = NULL;
  Shishi_tkt *tkt = NULL;
  Shishi_tkts_hint hint;
  int retval, rc;
  const char *user = NULL;
  const char *password = NULL;
  char *realm = NULL;
  int i;
  struct pam_conv *conv;
  struct pam_message *pmsg[1], msg[1];
  struct pam_response *resp;
  int nargs = 1;

  D (("called."));
  D (("flags %d argc %d", flags, argc));
  for (i = 0; i < argc; i++)
    D (("argv[%d]=%s", i, argv[i]));

  parse_argv (argc, argv);

  rc = shishi_init (&h);
  if (rc != SHISHI_OK)
    {
      h = NULL;
      D (("shishi_init() failed: %s", shishi_strerror (retval)));
      retval = PAM_AUTHINFO_UNAVAIL;
      goto done;
    }

  /* Extract overriding realm setting.  */
  if (opt_realm && *opt_realm)
    shishi_realm_default_set (h, opt_realm);

  /* Extract overriding host principal name.  */
  if (opt_principal && *opt_principal)
    {
      rc = shishi_parse_name (h, opt_principal, &principal, &realm);
      if (rc != SHISHI_OK)
	{
	  D (("Could not parse name: %s\n", shishi_strerror (rc)));
	  retval = PAM_AUTHINFO_UNAVAIL;
	  goto done;
	}

      /* The present REALM is allowed to override OPT_REALM.
       * PRINCIPAL is available for later use in the ticket.
       */
      if (realm && *realm)
	shishi_realm_default_set (h, realm);
    }

  /* Detect the calling user client.  */
  retval = pam_get_user (pamh, &user, NULL);
  if (retval != PAM_SUCCESS)
    {
      D (("get user returned error: %s", pam_strerror (pamh, retval)));
      goto done;
    }
  D (("get user returned: %s", user));

  shishi_principal_default_set (h, user);

  if (opt_debug)
    {
#if defined SHISHI_LINUXPAM_LOGGING
      pam_syslog (pamh, LOG_INFO, "Request from `%s@%s'.",
		  shishi_principal_default (h), shishi_realm_default (h));
#elif defined SHISHI_OPENPAM_LOGGING
      openpam_log (PAM_LOG_VERBOSE, "Request from `%s@%s'.",
		   shishi_principal_default (h), shishi_realm_default (h));
#endif
    }

  retval = pam_get_item (pamh, PAM_AUTHTOK, (const void **) &password);
  if (retval != PAM_SUCCESS)
    {
      D (("get password returned error: %s", pam_strerror (pamh, retval)));
      goto done;
    }
  D (("get password returned: %s", password));

  if (password == NULL)
    {
      retval = pam_get_item (pamh, PAM_CONV, (const void **) &conv);
      if (retval != PAM_SUCCESS)
	{
	  D (("get conv returned error: %s", pam_strerror (pamh, retval)));
	  goto done;
	}

      pmsg[0] = &msg[0];
      asprintf ((char **) &msg[0].msg, "Password for `%s@%s': ",
		shishi_principal_default (h), shishi_realm_default (h));
      msg[0].msg_style = PAM_PROMPT_ECHO_OFF;
      resp = NULL;

      retval = conv->conv (nargs, (const struct pam_message **) pmsg,
			   &resp, conv->appdata_ptr);

      free ((char *) msg[0].msg);

      if (retval != PAM_SUCCESS)
	{
	  D (("conv returned error: %s", pam_strerror (pamh, retval)));
	  goto done;
	}

      D (("conv returned: %s", resp->resp));

      password = resp->resp;

      retval = pam_set_item (pamh, PAM_AUTHTOK, password);
      if (retval != PAM_SUCCESS)
	{
	  D (("set_item returned error: %s", pam_strerror (pamh, retval)));
	  goto done;
	}
    }

  /* Is the service name "host" being overridden?  */
  if (principal && *principal && strchr (principal, '/'))
    {
      servername = strdup (principal);
      if (!servername)
	{
	  retval = PAM_BUF_ERR;
	  D (("failed at duplicating name: %s", principal));
	  goto done;
	}
    }

  if (!servername)
    servername= shishi_server_for_local_service (h, "host");

  memset (&hint, 0, sizeof (hint));
  hint.client = (char *) shishi_principal_default (h);
  hint.server = servername;
  hint.passwd = (char *) password;

  tkt = shishi_tkts_get (shishi_tkts_default (h), &hint);
  if (tkt == NULL)
    {
      free (servername);
      D (("TGS exchange failed: %s\n", shishi_error (h)));
      retval = PAM_AUTHINFO_UNAVAIL;
      goto done;
    }

  key = shishi_hostkeys_for_serverrealm (h, servername,
					 shishi_realm_default (h));
  if (key == NULL)
    {
      free (servername);
      D (("Key not found: %s\n", shishi_error (h)));
      retval = PAM_AUTHINFO_UNAVAIL;
      goto done;
    }

  if (opt_debug)
    {
#if defined SHISHI_LINUXPAM_LOGGING
      pam_syslog (pamh, LOG_INFO, "Requested server `%s@%s'.",
		  servername, shishi_realm_default (h));
#elif defined SHISHI_OPENPAM_LOGGING
      openpam_log (PAM_LOG_VERBOSE, "Requested server `%s@%s'.",
		  servername, shishi_realm_default (h));
#endif
    }

  free (servername);

  rc = shishi_tkt_decrypt (tkt, key);
  if (rc != SHISHI_OK)
    {
      D (("Could not decrypt ticket: %s\n", shishi_strerror (rc)));
      retval = PAM_AUTHINFO_UNAVAIL;
      goto done;
    }

  retval = PAM_SUCCESS;

done:
  if (h)
    shishi_done (h);
  pam_set_data (pamh, "shishi_setcred_return", (void *) (intptr_t) retval, NULL);
  D (("done. [%s]", pam_strerror (pamh, retval)));

  return retval;
}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t * pamh, int flags, int argc, const char **argv)
{
  int retval;
  int auth_retval;

  D (("called."));

  retval = pam_get_data (pamh, "shishi_setcred_return",
			 (const void **) &auth_retval);
  if (retval != PAM_SUCCESS)
    return PAM_CRED_UNAVAIL;

  /* XXX save ticket in user's file here
     XXX support CRED_EXPIRED */

  switch (auth_retval)
    {
    case PAM_SUCCESS:
      retval = PAM_SUCCESS;
      break;

    case PAM_USER_UNKNOWN:
      retval = PAM_USER_UNKNOWN;
      break;

    case PAM_AUTH_ERR:
    default:
      retval = PAM_CRED_ERR;
      break;
    }

  D (("done. [%s]", pam_strerror (pamh, retval)));

  return retval;
}

PAM_EXTERN int
pam_sm_acct_mgmt (pam_handle_t * pamh, int flags, int argc, const char **argv)
{
  int retval;

  D (("called."));

  /* TODO: check if password expired? */
  retval = PAM_SUCCESS;

  D (("done. [%s]", pam_strerror (pamh, retval)));

  return retval;
}

PAM_EXTERN int
pam_sm_open_session (pam_handle_t * pamh,
		     int flags, int argc, const char **argv)
{
  int retval;

  D (("called."));

  /* TODO: afslog()? */
  retval = PAM_SUCCESS;

  D (("done. [%s]", pam_strerror (pamh, retval)));

  return retval;
}

PAM_EXTERN int
pam_sm_close_session (pam_handle_t * pamh,
		      int flags, int argc, const char **argv)
{
  int retval;

  D (("called."));

  /* TODO: destroy tickets? destroy AFS tokens? */
  retval = PAM_SUCCESS;

  D (("done. [%s]", pam_strerror (pamh, retval)));

  return retval;
}

PAM_EXTERN int
pam_sm_chauthtok (pam_handle_t * pamh, int flags, int argc, const char **argv)
{
  int retval;

  D (("called."));

  /* TODO: Change password */
  retval = PAM_SUCCESS;

  D (("done. [%s]", pam_strerror (pamh, retval)));

  return retval;
}

/* Linux-PAM.  */
#ifdef PAM_STATIC

struct pam_module _pam_shishi_modstruct = {
  "pam_shishi",
  pam_sm_authenticate,
  pam_sm_setcred,
  pam_sm_acct_mgmt,
  pam_sm_open_session,
  pam_sm_close_session,
  pam_sm_chauthtok
};

#endif /* PAM_STATIC */

/* OpenPAM */
#ifdef PAM_MODULE_ENTRY

PAM_MODULE_ENTRY("pam_shishi");

#endif /* PAM_MODULE_ENTRY */
