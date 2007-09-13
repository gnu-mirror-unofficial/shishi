/* pam_shishi.c	PAM module using Shishi.
 * Copyright (C) 2002, 2003, 2007  Simon Josefsson
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
#include "config.h"
#endif

#ifdef STDC_HEADERS
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#endif

#include <shishi.h>

/* Libtool defines PIC for shared objects */
#ifndef PIC
#define PAM_STATIC
#endif

/* These #defines must be present according to PAM documentation. */
#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif
#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif

#if defined(DEBUG_PAM) && defined(HAVE_SECURITY__PAM_MACROS_H)
#define DEBUG
#include <security/_pam_macros.h>
#else
#define D(x)			/* nothing */
#endif

#ifndef PAM_EXTERN
#ifdef PAM_STATIC
#define PAM_EXTERN static
#else
#define PAM_EXTERN extern
#endif
#endif

PAM_EXTERN int
pam_sm_authenticate (pam_handle_t * pamh,
		     int flags, int argc, const char **argv)
{
  Shishi *h = NULL;
  Shishi_key *key = NULL;
  Shishi_tkt *tkt = NULL;
  int retval, rc;
  const char *user = NULL;
  const char *password = NULL;
  int i;
  struct pam_conv *conv;
  struct pam_message *pmsg[1], msg[1];
  struct pam_response *resp;
  int nargs = 1;

  D (("called."));
  D (("flags %d argc %d", flags, argc));
  for (i = 0; i < argc; i++)
    D (("argv[%d]=%s", i, argv[i]));

  rc = shishi_init (&h);
  if (rc != SHISHI_OK)
    {
      h = NULL;
      D (("shishi_init() failed: %s", shishi_strerror (retval)));
      retval = PAM_AUTHINFO_UNAVAIL;
      goto done;
    }

  retval = pam_get_user (pamh, &user, NULL);
  if (retval != PAM_SUCCESS)
    {
      D (("get user returned error: %s", pam_strerror (pamh, retval)));
      goto done;
    }
  D (("get user returned: %s", user));

  shishi_principal_default_set (h, user);

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

      retval = pam_set_item(pamh, PAM_AUTHTOK, password);
      if (retval != PAM_SUCCESS)
	{
	  D (("set_item returned error: %s", pam_strerror (pamh, retval)));
	  goto done;
	}
    }

  tkt = shishi_tkts_get_for_localservicepasswd (shishi_tkts_default (h),
						 "host", password);
  if (tkt == NULL)
    {
      D (("TGS exchange failed: %s\n", shishi_error (h)));
      retval = PAM_AUTHINFO_UNAVAIL;
      goto done;
    }

  key = shishi_hostkeys_for_localservice (h, "host");
  if (key == NULL)
    {
      D (("Key not found: %s\n", shishi_error (h)));
      retval = PAM_AUTHINFO_UNAVAIL;
      goto done;
    }

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
  pam_set_data (pamh, "shishi_setcred_return", (void *) retval, NULL);
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

#endif
