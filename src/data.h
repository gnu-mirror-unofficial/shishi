/* data.h	global data structures for shishi application
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

#ifndef DATA_H
#define DATA_H

#if HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef STDC_HEADERS
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#endif

#include <unistd.h>
#include <ctype.h>
#include <netdb.h>
#include <pwd.h>
#include <sys/types.h>

#include <argp.h>
#include <locale.h>


#if HAVE_INTTYPES_H
# include <inttypes.h>
#else
# if HAVE_STDINT_H
#  include <stdint.h>
# endif
#endif

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#if HAVE_STRING_H
# if !STDC_HEADERS && HAVE_MEMORY_H
#  include <memory.h>
# endif
# include <string.h>
#endif
#if HAVE_STRINGS_H
# include <strings.h>
#endif

#include <errno.h>
extern int errno;

#include "shishi.h"

#include "gettext.h"
#define _(String) gettext (String)
#define _N(S1, S2, N) ngettext (S1, S2, N)
#define gettext_noop(String) String
#define N_(String) gettext_noop (String)

/* Short and long parameter */
enum
{
  COMMAND_AP,
  COMMAND_AS,
  COMMAND_CLIENT,
  COMMAND_CRYPTO,
  COMMAND_KDC,
  COMMAND_LIST,
  COMMAND_SERVER,
  COMMAND_TGS
};

/* Long parameters only */
enum
{
  OPTION_KDC_REQUEST = 300,
  OPTION_KDC_SENDRECV,
  OPTION_KDC_RESPONSE,
  OPTION_KDC_WRITE_AP_REQUEST_FILE,
  OPTION_KDC_WRITE_AUTHENTICATOR_FILE,
  OPTION_KDC_WRITE_REQUEST_FILE,
  OPTION_KDC_WRITE_RESPONSE_FILE,
  OPTION_KDC_READ_REQUEST_FILE,
  OPTION_KDC_READ_RESPONSE_FILE,
  OPTION_KDC_SHORT_NONCE,
  OPTION_KDC_SERVER,
  OPTION_KDC_CLIENT,
  OPTION_KDC_STRING_TO_KEY,
  OPTION_KDC_CLIENT_NAME,
  OPTION_KDC_KEY_VALUE,
  OPTION_KDC_REALM,
  OPTION_KDC_SERVER_NAME,
  OPTION_KDC_TICKET_GRANTER,
  OPTION_KDC_FORCE_AS,
  OPTION_KDC_FORCE_TGS,
  OPTION_AP_AUTHENTICATOR_READ_FILE,
  OPTION_AP_AUTHENTICATOR_WRITE_FILE,
  OPTION_AP_AUTHENTICATOR_DATA,
  OPTION_AP_AUTHENTICATOR_READ_DATA_FILE,
  OPTION_AP_REQUEST_READ_FILE,
  OPTION_AP_REQUEST_WRITE_FILE,
  OPTION_AP_REALM,
  OPTION_AP_SERVER_NAME,
  OPTION_CRYPTO_ENCRYPT,
  OPTION_CRYPTO_DECRYPT,
  OPTION_CRYPTO_ALGORITHM,
  OPTION_CRYPTO_KEY_FILE,
  OPTION_CRYPTO_KEY_VALUE,
  OPTION_CRYPTO_INPUT_FILE,
  OPTION_CRYPTO_OUTPUT_FILE,
  OPTION_CRYPTO_STRING_TO_KEY,
  OPTION_CRYPTO_REALM,
  OPTION_CRYPTO_CLIENT_NAME,
  OPTION_CRYPTO_DEBUG,
  OPTION_LIST_SERVER_NAME,
  OPTION_CLIENT_REALM,
  OPTION_CLIENT_SERVER_NAME,
  OPTION_CLIENT_AP_OPTIONS,
  OPTION_SERVER_REALM,
  OPTION_SERVER_CLIENT_NAME,
  OPTION_SERVER_SERVER_NAME,
  OPTION_SERVER_KEY_FILE,
  OPTION_SERVER_KEY_VALUE,
  OPTION_SERVER_STRING_TO_KEY,
  OPTION_AS_REALM,
  OPTION_AS_CLIENT_NAME,
  OPTION_AS_STRING_TO_KEY,
  OPTION_TGS_REALM,
  OPTION_TGS_TICKET_GRANTER,
  OPTION_TGS_CLIENT_NAME,
  OPTION_TGS_SERVER_NAME
};

#define TYPE_TEXT_NAME "text"
#define TYPE_DER_NAME "der"
#define TYPE_HEX_NAME "hex"
#define TYPE_BASE64_NAME "base64"
#define TYPE_BINARY_NAME "binary"

#define BASE_DIR "/.shishi"
#define TICKET_FILE "/.shishi/tickets"
#define USERCFG_FILE "/.shishi/config"

struct arguments
{
  int silent, verbose;
  char *etypes;
  char *lib_options;
  int command;
  char *ticketfile;
  char *ticketwritefile;
  char *realm;
  char *systemcfgfile;
  char *usercfgfile;
  /* kdc/as/tgs and ap */
  char *authenticatorwritefile;
  int authenticatorwritetype;
  char *apreqwritefile;
  int apreqwritetype;
  /* kdc/as/tgs */
  char *cname;
  char *sname;
  char *tgtname;
  int shortnonce_p;
  int forceas_p;
  int forcetgs_p;
  int request_p;
  int sendrecv_p;
  int response_p;
  char *kdcreqwritefile;
  int kdcreqwritetype;
  char *kdcreqreadfile;
  int kdcreqreadtype;
  char *kdcrepwritefile;
  int kdcrepwritetype;
  char *kdcrepreadfile;
  int kdcrepreadtype;
  /* ap */
  char *apreqreadfile;
  int apreqreadtype;
  char *servername;
  char *authenticatorreadfile;
  int authenticatorreadtype;
  char *authenticatordatareadfile;
  int authenticatordatareadtype;
  char *authenticatordata;
  /* crypto */
  int algorithm;
  int encrypt_p;
  int decrypt_p;
  char *stringtokey;
  char *keyvalue;
  char *inputfile;
  int inputtype;
  char *outputfile;
  int outputtype;
  /* client */
  int apoptions;
};

extern int ap (Shishi * handle, Shishi_ticketset * ticketset,
	       struct arguments arg);

extern int kdc (Shishi * handle, Shishi_ticketset * ticketset,
		struct arguments arg);

extern int list (Shishi * handle, Shishi_ticketset * ticketset,
		 struct arguments arg);

extern int client (Shishi * handle, Shishi_ticketset * ticketset,
		   struct arguments arg);

extern int server (Shishi * handle, Shishi_ticketset * ticketset,
		   struct arguments arg);

#endif
