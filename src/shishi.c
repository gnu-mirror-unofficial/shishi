/* shishi.c	command line interface to shishi
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

#include "data.h"

const char *argp_program_version = PACKAGE_STRING;
const char *argp_program_bug_address = PACKAGE_BUGREPORT;

static void
parse_filename (char *arg, int *type, char **var)
{
  if (strncasecmp (arg, TYPE_TEXT_NAME",", strlen(TYPE_TEXT_NAME",")) == 0)
    {
      (*type) = SHISHI_FILETYPE_TEXT;
      arg += strlen(TYPE_TEXT_NAME",");
    }
  else if (strncasecmp (arg, TYPE_DER_NAME",", strlen(TYPE_DER_NAME",")) == 0)
    {
      (*type) = SHISHI_FILETYPE_DER;
      arg += strlen(TYPE_DER_NAME",");
    }
  else if (strncasecmp (arg, TYPE_HEX_NAME",", strlen(TYPE_HEX_NAME",")) == 0)
    {
      (*type) = SHISHI_FILETYPE_HEX;
      arg += strlen(TYPE_HEX_NAME",");
    }
  else if (strncasecmp (arg, TYPE_BASE64_NAME",", 
			strlen(TYPE_BASE64_NAME",")) == 0)
    {
      (*type) = SHISHI_FILETYPE_BASE64;
      arg += strlen(TYPE_BASE64_NAME",");
    }
  else if (strncasecmp (arg, TYPE_BINARY_NAME",", 
			strlen(TYPE_BINARY_NAME",")) == 0)
    {
      (*type) = SHISHI_FILETYPE_BINARY;
      arg += strlen(TYPE_BINARY_NAME",");
    }
  else
    (*type) = 0;
  *var  = strdup (arg);
}

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  struct arguments *arguments = state->input;
  int res;

  switch (key)
    {
    case 'q':
      arguments->silent = 1;
      break;

    case 'v':
      arguments->verbose = 1;
      break;

    case 'o':
      arguments->lib_options = arg;
      break;

    case 'w':
      arguments->ticketwritefile = strdup(arg);
      break;

    case 'e':
      arguments->etypes = strdup(arg);
      break;

    case 's':
      arguments->systemcfgfile = strdup(arg);
      break;

    case 'c':
      arguments->usercfgfile = strdup(arg);
      break;

    case 't':
      arguments->ticketfile = strdup (arg);
      break;

      /* Client */

    case OPTION_CLIENT_AP_OPTIONS:
      {
	char *ptrptr;
	char *val;
	int i;

	arguments->apoptions = 0;
	for (i = 0; 
	     val = strtok_r(i == 0 ? arg : NULL, ", \t\n\r", &ptrptr); 
	     i++)
	  {
	    int option = shishi_ap_string2option(val);
	    if (option == 0)
	      fprintf(stderr, "Ignoring unknown AP option: `%s'\n", val);
	    arguments->apoptions |= option;
	  }
      }
      break;

      /* Crypto */

    case OPTION_CRYPTO_ALGORITHM:
      if (arguments->command != COMMAND_CRYPTO)
	argp_error (state, _("Option `%s' only valid with CRYPTO."),
		    state->argv[state->next - 1]);
      arguments->algorithm = shishi_etype_parse (arg);
      if (arguments->algorithm == -1)
	argp_error (state, _("Unknown encryption type in `%s'"),
		    state->argv[state->next - 1]);
      break;

    case OPTION_CRYPTO_ENCRYPT:
      if (arguments->command != COMMAND_CRYPTO)
	argp_error (state, _("Option `%s' only valid with CRYPTO."),
		    state->argv[state->next - 1]);
      if (arguments->decrypt_p)
	argp_error (state, _("Cannot both encrypt and decrypt."));
      arguments->encrypt_p = 1;
      break;

    case OPTION_CRYPTO_DECRYPT:
      if (arguments->command != COMMAND_CRYPTO)
	argp_error (state, _("Option `%s' only valid with CRYPTO."),
		    state->argv[state->next - 1]);
      if (arguments->encrypt_p)
	argp_error (state, _("Cannot both encrypt and decrypt."));
      arguments->decrypt_p = 1;
      break;

    case OPTION_AS_STRING_TO_KEY:
    case OPTION_CRYPTO_STRING_TO_KEY:
    case OPTION_KDC_STRING_TO_KEY:
    case OPTION_SERVER_STRING_TO_KEY:
      if (arguments->command != COMMAND_CRYPTO &&
	  arguments->command != COMMAND_AS &&
	  arguments->command != COMMAND_KDC &&
	  arguments->command != COMMAND_SERVER)
	argp_error 
	  (state,
	   _("Option `%s' only valid with CRYPTO, KDC/AS/TGS and SERVER."),
	   state->argv[state->next - 1]);
      arguments->stringtokey = strdup (arg);
      break;

    case OPTION_CRYPTO_INPUT_FILE:
      if (arguments->command != COMMAND_CRYPTO)
	argp_error (state, _("Option `%s' only valid with CRYPTO."),
		    state->argv[state->next - 1]);
      parse_filename(arg, &arguments->inputtype,
		     &arguments->inputfile);
      if (arguments->inputtype == SHISHI_FILETYPE_TEXT ||
	  arguments->inputtype == SHISHI_FILETYPE_DER)
	arguments->inputtype == SHISHI_FILETYPE_BINARY;
      break;

    case OPTION_CRYPTO_OUTPUT_FILE:
      if (arguments->command != COMMAND_CRYPTO)
	argp_error (state, _("Option `%s' only valid with CRYPTO."),
		    state->argv[state->next - 1]);
      parse_filename(arg, &arguments->outputtype,
		     &arguments->outputfile);
      if (arguments->outputtype == SHISHI_FILETYPE_TEXT ||
	  arguments->outputtype == SHISHI_FILETYPE_DER)
	arguments->outputtype == SHISHI_FILETYPE_BINARY;
      break;

      /* Authenticator */

    case OPTION_AP_AUTHENTICATOR_READ_FILE:
      if (arguments->command != COMMAND_AP)
	argp_error (state, _("Option `%s' only valid with AP."),
		    state->argv[state->next - 1]);
      parse_filename(arg, &arguments->authenticatorreadtype,
		     &arguments->authenticatorreadfile);
      break;

    case OPTION_AP_AUTHENTICATOR_DATA:
      if (arguments->command != COMMAND_AP)
	argp_error (state, _("Option `%s' only valid with AP."),
		    state->argv[state->next - 1]);
      arguments->authenticatordata = strdup (arg);
      break;

    case OPTION_AP_AUTHENTICATOR_READ_DATA_FILE:
      if (arguments->command != COMMAND_AP)
	argp_error (state, _("Option `%s' only valid with AP."),
		    state->argv[state->next - 1]);
      parse_filename(arg, &arguments->authenticatordatareadtype,
		     &arguments->authenticatordatareadfile);
      if (arguments->authenticatordatareadtype == SHISHI_FILETYPE_TEXT ||
	  arguments->authenticatordatareadtype == SHISHI_FILETYPE_DER)
	arguments->authenticatordatareadtype == SHISHI_FILETYPE_BINARY;
      break;

    case OPTION_AS_CLIENT_NAME:
    case OPTION_CRYPTO_CLIENT_NAME:
    case OPTION_KDC_CLIENT_NAME:
    case OPTION_SERVER_CLIENT_NAME:
      if (arguments->command != COMMAND_CRYPTO &&
	  arguments->command != COMMAND_AS &&
	  arguments->command != COMMAND_KDC &&
	  arguments->command != COMMAND_SERVER)
	argp_error (state,
	    _("Option `%s' only valid with CRYPTO, KDC/AS/TGS and SERVER."),
		    state->argv[state->next - 1]);
      arguments->cname = strdup (arg);
      break;

    case 'r':
    case OPTION_AP_REALM:
    case OPTION_AS_REALM:
    case OPTION_CLIENT_REALM:
    case OPTION_CRYPTO_REALM:
    case OPTION_KDC_REALM:
    case OPTION_TGS_REALM:
      if (arguments->command != COMMAND_AP &&
	  arguments->command != COMMAND_CLIENT &&
	  arguments->command != COMMAND_CRYPTO &&
	  arguments->command != COMMAND_AS &&
	  arguments->command != COMMAND_KDC &&
	  arguments->command != COMMAND_TGS)
	argp_error (state, _("Option `%s' only valid with AP, CLIENT, CRYPTO "
			     "and KDC/AS/TGS."),
		    state->argv[state->next - 1]);
      arguments->realm = strdup (arg);
      break;

    case OPTION_CRYPTO_KEY_VALUE:
    case OPTION_KDC_KEY_VALUE:
    case OPTION_SERVER_KEY_VALUE:
      if (arguments->command != COMMAND_CRYPTO &&
	  arguments->command != COMMAND_KDC &&
	  arguments->command != COMMAND_SERVER)
	argp_error (state,
		    _("Option `%s' only valid with CRYPTO and KDC/AS/TGS."),
		    state->argv[state->next - 1]);
      arguments->keyvalue = strdup (arg);
      break;

    case OPTION_AP_SERVER_NAME:
    case OPTION_CLIENT_SERVER_NAME:
    case OPTION_KDC_SERVER_NAME:
    case OPTION_LIST_SERVER_NAME:
    case OPTION_SERVER_SERVER_NAME:
      arguments->sname = strdup (arg);
      break;

    case OPTION_KDC_FORCE_AS:
      if (arguments->command != COMMAND_KDC)
	argp_error (state, _("Option `%s' only valid with KDC."),
		    state->argv[state->next - 1]);
      arguments->forceas_p = 1;
      break;

    case OPTION_KDC_FORCE_TGS:
      if (arguments->command != COMMAND_KDC)
	argp_error (state, _("Option `%s' only valid with KDC."),
		    state->argv[state->next - 1]);
      arguments->forcetgs_p = 1;
      break;

    case OPTION_KDC_TICKET_GRANTER:
    case OPTION_TGS_TICKET_GRANTER:
      if (arguments->command != COMMAND_KDC &&
	  arguments->command != COMMAND_TGS)
	argp_error (state, _("Option `%s' only valid with KDC/TGS."),
		    state->argv[state->next - 1]);
      arguments->tgtname = strdup (arg);
      break;

    case OPTION_KDC_REQUEST:
      if (arguments->command != COMMAND_KDC)
	argp_error (state, _("Option `%s' only valid with KDC/AS/TGS."),
		    state->argv[state->next - 1]);
      arguments->request_p = 1;
      break;

    case OPTION_AP_REQUEST_WRITE_FILE:
    case OPTION_KDC_WRITE_AP_REQUEST_FILE:
      if (arguments->command != COMMAND_KDC && 
	  arguments->command != COMMAND_AP)
	argp_error (state, _("Option `%s' only valid with AP and KDC/AS/TGS."),
		    state->argv[state->next - 1]);
      parse_filename(arg, &arguments->apreqwritetype,
		     &arguments->apreqwritefile);      
      break;

    case OPTION_AP_AUTHENTICATOR_WRITE_FILE:
    case OPTION_KDC_WRITE_AUTHENTICATOR_FILE:
      if (arguments->command != COMMAND_AP ||
	  arguments->command != COMMAND_KDC)
	argp_error (state, _("Option `%s' only valid with AP and KDC/AS/TGS."),
		    state->argv[state->next - 1]);
      parse_filename(arg, &arguments->authenticatorwritetype,
		     &arguments->authenticatorwritefile);
      break;

    case OPTION_KDC_WRITE_REQUEST_FILE:
      if (arguments->command != COMMAND_KDC)
	argp_error (state, _("Option `%s' only valid with KDC/AS/TGS."),
		    state->argv[state->next - 1]);
      parse_filename(arg, &arguments->kdcreqwritetype, 
		     &arguments->kdcreqwritefile);
      break;

    case OPTION_KDC_READ_REQUEST_FILE:
      if (arguments->command != COMMAND_KDC)
	argp_error (state, _("Option `%s' only valid with KDC/AS/TGS."),
		    state->argv[state->next - 1]);
      parse_filename(arg, &arguments->kdcreqreadtype, 
		     &arguments->kdcreqreadfile);
      break;

    case OPTION_KDC_WRITE_RESPONSE_FILE:
      if (arguments->command != COMMAND_KDC)
	argp_error (state, _("Option `%s' only valid with KDC/AS/TGS."),
		    state->argv[state->next - 1]);
      parse_filename(arg, &arguments->kdcrepwritetype, 
		     &arguments->kdcrepwritefile);
      break;

    case OPTION_KDC_READ_RESPONSE_FILE:
      if (arguments->command != COMMAND_KDC)
	argp_error (state, _("Option `%s' only valid with KDC/AS/TGS."),
		    state->argv[state->next - 1]);
      parse_filename(arg, &arguments->kdcrepreadtype, 
		     &arguments->kdcrepreadfile);
      break;

    case OPTION_KDC_SENDRECV:
      if (arguments->command != COMMAND_KDC)
	argp_error (state, _("Option `%s' only valid with KDC/AS/TGS."),
		    state->argv[state->next - 1]);
      arguments->sendrecv_p = 1;
      break;

    case OPTION_KDC_RESPONSE:
      if (arguments->command != COMMAND_KDC)
	argp_error (state, _("Option `%s' only valid with KDC/AS/TGS."),
		    state->argv[state->next - 1]);
      arguments->response_p = 1;
      break;

    case OPTION_KDC_SHORT_NONCE:
      if (arguments->command != COMMAND_KDC)
	argp_error (state, _("Option `%s' only valid with KDC/AS/TGS."),
		    state->argv[state->next - 1]);
      arguments->shortnonce_p = 1;
      break;

    case ARGP_KEY_ARG:
      if (state->arg_num != 0)
	argp_error (state, _("Too many arguments: `%s'"), arg);
      else
	{
	  if (strcmp (arg, "ap") == 0)
	    {
	      arguments->command = COMMAND_AP;
	    }
	  else if (strcmp (arg, "client") == 0)
	    {
	      arguments->command = COMMAND_CLIENT;
	    }
	  else if (strcmp (arg, "crypto") == 0)
	    {
	      arguments->command = COMMAND_CRYPTO;
	    }
	  else if (strcmp (arg, "kdc") == 0)
	    {
	      arguments->command = COMMAND_KDC;
	    }
	  else if (strcmp (arg, "as") == 0)
	    {
	      arguments->command = COMMAND_AS;
	    }
	  else if (strcmp (arg, "tgs") == 0)
	    {
	      arguments->command = COMMAND_TGS;
	    }
	  else if (strcmp (arg, "list") == 0)
	    {
	      arguments->command = COMMAND_LIST;
	    }
	  else if (strcmp (arg, "server") == 0)
	    {
	      arguments->command = COMMAND_SERVER;
	    }
	  else
	    {
	      argp_error (state, _("Unknown command: '%s'"), arg);
	    }
	  break;
	}
      break;

    case ARGP_KEY_END:
      if (state->arg_num < 1)
	/* Not enough arguments. */
	argp_usage (state);
      break;

    default:
      return ARGP_ERR_UNKNOWN;
    }

  return 0;
}

static struct argp_option options[] = {

  {0, 0, 0, 0, "Authentication commands:", 10},

  {"as", 0, 0, OPTION_DOC, 
   "Acquire ticket granting ticket using password and the Authentication "
   "Service (AS) exchange."},

  {"list", 0, 0, OPTION_DOC, 
   "List tickets."},

  {"tgs", 0, 0, OPTION_DOC,
   "Acquire ticket using the ticket granting ticket and the Ticket-Granting "
   "Service (TGS) exchange."},

  {0, 0, 0, 0, "Utility commands:", 20},

  {"client", 0, 0, OPTION_DOC, 
   "Kerberos client."},

  {"server", 0, 0, OPTION_DOC, 
   "Kerberos server."},

  {0, 0, 0, 0, "Low-level commands:", 30},

  {"ap", 0, 0, OPTION_DOC, 
   "Kerberos Client/Server Authentication (AP-REQ and AP-REP)."},

  {"crypto", 0, 0, OPTION_DOC, 
   "Cryptographic functions."},

  {"kdc", 0, 0, OPTION_DOC, 
   "Key Distribution Center Services; Authentication Service (AS) "
   "and Ticket-Granting Service (TGS)."},

  /************** AS */

  {0, 0, 0, 0, "Options for Authentication Service (AS-OPTIONS):", 100},
 
  {"client-name", OPTION_AS_CLIENT_NAME, "NAME", 0,
   "Client name. Default is login username."},

  {"encryption-type", 'e', "ETYPE,[ETYPE...]", 0,
   "Encryption types to use.  ETYPE is either registered name or integer."},

  {"realm", 'r', "REALM", 0,
   "Realm of client and server. Default is DNS domain of local host."},

  {"string-to-key", OPTION_AS_STRING_TO_KEY, "PASSWORD", 0,
   "Password to decrypt response (discouraged). Default is to prompt user."},

  /************** LIST */

  {0, 0, 0, 0, "Options for the List command (LIST-OPTIONS):", 200},

  {"server-name", OPTION_LIST_SERVER_NAME, "NAME", 0,
   "Restrict list to tickets for specified server."},

  /************** TGS */

  {0, 0, 0, 0, "Options for Ticket Granting Service (TGS-OPTIONS):", 300},
 
  {"encryption-type", 'e', "ETYPE,[ETYPE...]", 0,
   "Encryption types to use.  ETYPE is either registered name or integer."},

  {"ticket-granter", OPTION_KDC_TICKET_GRANTER, "NAME", 0,
   "Name of server field in the ticket to use as the ticket granter. "
   "Defaults to \"krbtgt/REALM@REALM\" where REALM is server "
   "realm (see --realm)."},

  {"realm", 'r', "REALM", 0,
   "Realm of server. Default is DNS domain of local host."},

 /************** CLIENT */

  {0, 0, 0, 0, "Options for Network Client (CLIENT-OPTIONS):", 400},

  {"options", OPTION_CLIENT_AP_OPTIONS, "OPTION[,OPTION...]", 0,
   "Indicate AP-OPTIONS separated by comma (,) or whitespace. "
   "Options are integers (ORed together) or the pre-defined strings "
   "\"use-session-key\" indicating that the ticket is encrypted in the "
   "server's TGT key rather than its own key (not implemented) or "
   "\"mutual-required\" indicating that mutual authentication is required."},

  {"realm", 'r', "REALM", 0,
   "Realm of server. Defaults to DNS domain of local host."},

  {"server-name", OPTION_CLIENT_SERVER_NAME, "NAME", 0,
   "Name of server. Defaults to \"sample/REALM\" where REALM "
   "is realm of server (see --realm)."},

  /************** SERVER */

  {0, 0, 0, 0, "Options for Network Server (SERVER-OPTIONS):", 500},

  {"client-name", OPTION_KDC_CLIENT_NAME, "NAME", 0,
   "Client name. Default is login username."},

  {"key-value", OPTION_SERVER_KEY_VALUE, "KEY", 0,
   "Cipher key of server."},

  {"realm", 'r', "REALM", 0,
   "Realm of server. Defaults to DNS domain of local host."},

  {"server-name", OPTION_SERVER_SERVER_NAME, "NAME", 0,
   "Name of server. Defaults to \"sample/REALM\" where REALM "
   "is realm of server (see --realm)."},

  {"string-to-key", OPTION_SERVER_STRING_TO_KEY, "PASSWORD", 0,
   "Password to decrypt response (discouraged)."},

  /************** AP */

  {0, 0, 0, 0, 
   "Options for low-level Client/Server Authentication (AP-OPTIONS):", 600},

  {"data", OPTION_AP_AUTHENTICATOR_DATA, "B64STRING", 0,
   "Base64 encoded data to checksum in generated authenticator. "
   "By default checksum is omitted (indicating no application payload)."},

  {"read-ap-request-file", OPTION_AP_REQUEST_READ_FILE, "[TYPE,]FILE", 0,
   "Read AP-REQ from FILE in format TYPE; TEXT (default) or DER. "
   "Default is to generate it."},

  {"read-data-file", OPTION_AP_AUTHENTICATOR_READ_DATA_FILE, "[TYPE,]FILE", 0,
   "Read data to checksum in generated authenticator from FILE in format "
   "TYPE, BASE64, HEX or BINARY (default). "
   "By default checksum is omitted (indicating no application payload)."},

  {"realm", 'r', "REALM", 0,
   "Realm of server. Defaults to DNS domain of local host. Used for "
   "locating the ticket to use."},

  {"server-name", OPTION_AP_SERVER_NAME, "NAME", 0,
   "Name of server. Defaults to \"krbtgt.DEFAULTREALM\" where DEFAULTREALM "
   "is realm of server. Used for locating the ticket to use."},

  {"write-authenticator-file", OPTION_AP_AUTHENTICATOR_WRITE_FILE, 
   "[TYPE,]FILE", 0,
   "Write authenticator to FILE in format TYPE; TEXT (default) or DER. "
   "Not written by default."},

  {"write-ap-request-file", OPTION_AP_REQUEST_WRITE_FILE, "[TYPE,]FILE", 0,
   "Write AP-REQ to FILE in format TYPE; TEXT (default) or DER.  "
   "Default is stdout."},

  /************** CRYPTO */

  {0, 0, 0, 0,
   "Options for low-level cryptography (CRYPTO-OPTIONS):", 700},

  {"algorithm", OPTION_CRYPTO_ALGORITHM, "ALGORITHM", 0,
   "Use ciphering algorithm, expressed either as the etype integer or "
   "the registered name."},

  {"client-name", OPTION_KDC_CLIENT_NAME, "NAME", 0,
   "Client name. Default is login username. Used for generating cipher key."},

  {"decrypt", OPTION_CRYPTO_DECRYPT, 0, 0,
   "Decrypt data"},

  {"encrypt", OPTION_CRYPTO_ENCRYPT, 0, 0,
   "Encrypt data"},

  {"input-file", OPTION_CRYPTO_INPUT_FILE, "[TYPE,]FILE", 0,
   "Read data from FILE in TYPE, BASE64, HEX or BINARY (default)."},

  {"key-file", OPTION_CRYPTO_KEY_FILE, "[TYPE,]FILE", 0,
   "Read/write cipher key from/to FILE in TYPE"},

  {"key-value", OPTION_CRYPTO_KEY_VALUE, "KEY", 0,
   "Specify cipher key directly (discouraged)"},

  {"output-file", OPTION_CRYPTO_OUTPUT_FILE, "[TYPE,]FILE", 0,
   "Write data to FILE in TYPE, BASE64, HEX or BINARY (default)."},

  {"realm", 'r', "REALM", 0,
   "Realm of principal. Defaults to DNS domain of local host. "
   "Used for generating cipher key."},

  {"string-to-key", OPTION_CRYPTO_STRING_TO_KEY, "PASSWORD", 0,
   "Convert password to key.  Client-name and realm also modify the key."},

  /************** KDC */

  {0, 0, 0, 0,
   "Options for low-level Key Distribution Services (KDC-OPTIONS):", 800},

  {"client-name", OPTION_KDC_CLIENT_NAME, "NAME", 0,
   "Client name. Default is login username. Only for AS."},

  {"encryption-type", 'e', "ETYPE,[ETYPE...]", 0,
   "Encryption types to use.  ETYPE is either registered name or integer."},

  {"force-as", OPTION_KDC_FORCE_AS, 0, 0,
   "Force AS mode. Default is to use TGS iff a TGT is found."},

  {"force-tgs", OPTION_KDC_FORCE_TGS, 0, 0,
   "Force TGS mode. Default is to use TGS iff a TGT is found."},

  {"realm", 'r', "REALM", 0,
   "Realm of server. Default is DNS domain of local host. For AS, this also indicates realm of client."},

  {"server", OPTION_KDC_SERVER, "HOST", 0,
   "Send request to HOST. Default uses address from configuration file."},

  {"server-name", OPTION_KDC_SERVER_NAME, "NAME", 0,
   "Server name. Default is \"krbtgt/REALM\" where REALM is server "
   "realm (see --realm)."},

  {"short-nonce", OPTION_KDC_SHORT_NONCE, 0, 0,
   "Use a 4 byte nonce. Required by some buggy servers."},

  {"ticket-granter", OPTION_KDC_TICKET_GRANTER, "NAME", 0,
   "Service name in ticket to use for authenticating request. Only for TGS. "
   "Defaults to \"krbtgt/REALM@REALM\" where REALM is server "
   "realm (see --realm)."},

  {"key-value", OPTION_KDC_KEY_VALUE, "KEY", 0,
   "Cipher key to decrypt response (discouraged)."},

  {"read-kdc-request-file", OPTION_KDC_READ_REQUEST_FILE, "[TYPE,]FILE", 0,
   "Read KDC-REQ from FILE in format TYPE; TEXT (default) or DER. "
   "Default is to generate it."},

  {"read-kdc-response-file", OPTION_KDC_READ_RESPONSE_FILE, "[TYPE,]FILE", 0,
   "Read KDC-REP from FILE in format TYPE; TEXT (default) or DER. "
   "Default is to receive it from server."},

  {"request", OPTION_KDC_REQUEST, 0, 0,
   "Only generate the request."},

  {"response", OPTION_KDC_RESPONSE, 0, 0,
   "Only parse request and response and output ticket."},

  {"sendrecv", OPTION_KDC_SENDRECV, 0, 0,
   "Only send request and receive response."},

  {"string-to-key", OPTION_CRYPTO_STRING_TO_KEY, "PASSWORD", 0,
   "Password to decrypt response (discouraged).  Only for AS."},

  {"write-ap-request-file", OPTION_KDC_WRITE_AP_REQUEST_FILE, "[TYPE,]FILE", 0,
   "Write AP-REQ to FILE in TYPE, either TEXT (default) or DER. "
   "Only for TGS. Not written by default."},

  {"write-authenticator-file", OPTION_KDC_WRITE_AUTHENTICATOR_FILE, 
   "[TYPE,]FILE", 0,
   "Write Authenticator to FILE in TYPE, either TEXT (default) or DER. "
   "Only for TGS. Not written by default."},

  {"write-kdc-request-file", OPTION_KDC_WRITE_REQUEST_FILE, "[TYPE,]FILE", 0,
   "Write KDC-REQ to FILE in format TYPE; TEXT (default) or DER. "
   "Not written by default."},

  {"write-kdc-response-file", OPTION_KDC_WRITE_RESPONSE_FILE, "[TYPE,]FILE", 0,
   "Write KDC-REP to FILE in format TYPE; TEXT (default) or DER. "
   "Not written by default."},

  /************** OTHER */

  {0, 0, 0, 0, "Other options:", 1000},

  {"verbose", 'v', 0, 0,
   "Produce verbose output.",},

  {"quiet", 'q', 0, 0,
   "Don't produce any output."},

  {"silent", 0, 0, OPTION_ALIAS},

  {"system-configuration-file", 's', "FILE", 0,
   "Read system wide configuration from file.  Default is " SYSTEMCFGFILE "."},

  {"configuration-file", 'c', "FILE", 0,
   "Read user configuration from file.  Default is ~/.shishi/config."},

  {"library-options", 'o', "STRING", 0,
   "Parse STRING as a configuration file statement."},

  {"ticket-file", 't', "FILE", 0,
   "Read tickets from FILE. Default is $HOME/.shishi/tickets."},

  {"ticket-write-file", 'w', "FILE", 0,
   "Write tickets to FILE.  Default is to write them back to ticket file."},

  /************** EXAMPLES */

  {0, 0, 0, 0, "Examples:", 2000},

  {"shishi as", 0, 0, OPTION_DOC,
   "Get a ticket granting ticket from the default KDC server for the "
   "default user and realm."},

  {"shishi tgs --server-name=imap", 0, 0, OPTION_DOC,
   "Get a ticket for the imap server."},

  {"shishi list --server-name=krbtgt/JOSEFSSON.ORG@JOSEFSSON.ORG",
   0, 0, OPTION_DOC,
   "List tickets for the Ticket Granting Service in the JOSEFSSON.ORG realm."},

  {0}
};

static struct argp argp = {
  options,
  parse_opt,
  "COMMAND [COMMAND-OPTION...]\n"
  "ap [AP-OPTION...]\n"
  "as [AS-OPTION...]\n"
  "client [CLIENT-OPTION...]\n"
  "crypto [CRYPTO-OPTION...]\n"
  "kdc [KDC-OPTION...]\n" 
  "list [LIST-OPTION...]\n"
  "server [SERVER-OPTION...]\n"
  "tgs [TGS-OPTION...]",
  "Shishi -- An implementation of Kerberos 5"
};

void
die(char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  vfprintf (stderr, fmt, ap);
  va_end(ap);
  exit(1);
}

int
main (int argc, char *argv[])
{
  struct arguments arg;
  char *home = getenv ("HOME");
  char *ticketfile;
  char *usercfgfile;
  Shishi *handle;
  Shishi_ticketset *ticketset;
  int rc;

  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);

  memset ((void *) &arg, 0, sizeof (arg));
  argp_parse (&argp, argc, argv, ARGP_IN_ORDER, 0, &arg);

  handle = shishi_init ();
  if (handle == NULL)
    die("Internal error: could not initialize shishi\n");

  if (home == NULL)
    home = "";

  if (arg.systemcfgfile == NULL)
    arg.systemcfgfile = SYSTEMCFGFILE;

  rc = shishi_cfg_from_file (handle, arg.systemcfgfile);
  if (rc != SHISHI_OK && rc != SHISHI_FOPEN_ERROR)
    die("Could not read system config: %s\n", shishi_strerror (rc));

  usercfgfile = malloc (strlen (home) + strlen (USERCFG_FILE) + 1);
  sprintf (usercfgfile, "%s%s", home, USERCFG_FILE);
  if (arg.usercfgfile == NULL)
    arg.usercfgfile = usercfgfile;

  rc = shishi_cfg_from_file (handle, arg.usercfgfile);
  if (rc != SHISHI_OK && rc != SHISHI_FOPEN_ERROR)
    die("Could not read user config: %s\n", shishi_strerror (rc));

  rc = shishi_cfg_clientkdcetype_set (handle, arg.etypes);
  if (rc != SHISHI_OK)
    die("Could not set encryption types: %s\n", shishi_strerror (rc));

  rc = shishi_cfg (handle, arg.lib_options);
  if (rc != SHISHI_OK)
    die("Could not read library options: %s\n", shishi_strerror (rc));

  rc = shishi_ticketset_init (handle, &ticketset);
  if (rc != SHISHI_OK)
    die("Could not initialize ticket set: %s\n", shishi_strerror (rc));

  ticketfile = malloc (strlen (home) + strlen (TICKET_FILE) + 1);
  sprintf (ticketfile, "%s%s", home, TICKET_FILE);
  if (arg.ticketfile == NULL)
    arg.ticketfile = ticketfile;

  rc = shishi_ticketset_from_file (handle, ticketset, arg.ticketfile);
  if (rc != SHISHI_OK && rc != SHISHI_FOPEN_ERROR)
    die("Could not read tickets: %s\n", shishi_strerror (rc));

  rc = 1;
  switch (arg.command)
    {
    case COMMAND_AP:
      rc = ap (handle, ticketset, arg);
      break;

    case COMMAND_AS:
      {
	Shishi_as * as;
	Shishi_ticket * tkt;
	char password[BUFSIZ];

	if (arg.cname != NULL)
	  shishi_principal_default_set (handle, arg.cname);

	if (arg.realm != NULL)
	  shishi_realm_default_set (handle, arg.realm);

	rc = shishi_as (handle, arg.stringtokey, &as);
	if (rc != SHISHI_OK)
	  {
	    printf ("AS exchange failed: %s\n%s\n", shishi_strerror (rc),
		    shishi_strerror_details (handle));
	    break;
	  }

	if (arg.verbose)
	  {
	    shishi_kdcreq_print (handle, stdout, shishi_as_get_asreq(as));
	    shishi_kdcrep_print (handle, stdout, shishi_as_get_asrep(as));
	  }

	tkt = shishi_as_get_ticket(as);

	if (!arg.silent)
	  shishi_ticket_print (handle, tkt, stdout);

	rc = shishi_ticketset_add (handle, ticketset, tkt);
	if (rc != SHISHI_OK)
	  printf ("Could not add ticket: %s", shishi_strerror (rc));
      }
      break;

    case COMMAND_CLIENT:
      rc = client (handle, ticketset, arg);
      break;

    case COMMAND_CRYPTO:
      rc = crypto (handle, arg);
      break;

    case COMMAND_KDC:
      rc = kdc (handle, ticketset, arg);
      break;

    case COMMAND_LIST:
      if (!arg.silent)
	printf (_("Tickets in `%s':\n"), arg.ticketfile);

      rc = shishi_ticketset_print_for_service (handle, ticketset, 
					       stdout, arg.sname);
      if (rc != SHISHI_OK)
	fprintf (stderr, "Could not list tickets: %s", shishi_strerror (rc));
      break;



    case COMMAND_SERVER:
      rc = server (handle, ticketset, arg);
      break;

    case COMMAND_TGS:
      {
	Shishi_tgs * tgs;
	Shishi_ticket * tgt;
	Shishi_ticket * tkt;

	if (arg.cname != NULL)
	  shishi_principal_default_set (handle, arg.cname);

	if (arg.realm != NULL)
	  shishi_realm_default_set (handle, arg.realm);

	if (arg.tgtname == NULL)
	  {
	    char *realm = shishi_realm_default_get (handle);
	    int len = strlen ("krbtgt/") +  strlen (realm) + 1;
	    arg.tgtname = malloc (len);
	    if (arg.tgtname == NULL)
	      return SHISHI_MALLOC_ERROR;
	    sprintf (arg.tgtname, "krbtgt/%s", realm);
	  }

	tgt = shishi_ticketset_find_ticket_for_clientserver
	  (handle,  ticketset, shishi_principal_default_get (handle),
	   arg.tgtname);
	if (tgt == NULL)
	  {
	    printf ("TGT not found.  Please use the AS command first.\n");
	    rc = !SHISHI_OK;
	    break;
	  }

	rc = shishi_tgs (handle, tgt, &tgs, arg.tgtname);
	if (rc != SHISHI_OK)
	  {
	    printf ("TGS exchange failed: %s\n%s\n", shishi_strerror (rc),
		    shishi_strerror_details (handle));
	    break;
	  }

	if (arg.verbose)
	  {
	    shishi_authenticator_print (handle, stdout, 
					shishi_tgs_get_authenticator(tgs));
	    shishi_apreq_print (handle, stdout, shishi_tgs_get_apreq(tgs));
	    shishi_kdcreq_print (handle, stdout, shishi_tgs_get_tgsreq(tgs));
	    shishi_kdcrep_print (handle, stdout, shishi_tgs_get_tgsrep(tgs));
	  }

	tkt = shishi_tgs_get_ticket(tgs);

	if (!arg.silent)
	  shishi_ticket_print (handle, tkt, stdout);

	rc = shishi_ticketset_add (handle, ticketset, tkt);
	if (rc != SHISHI_OK)
	  printf ("Could not add ticket: %s", shishi_strerror (rc));
      }
      break;

    default:
      die("Internal error: unknown command `%d'\n", arg.command);
      break;
    }

  if (rc == SHISHI_OK)
    {
      rc = shishi_ticketset_to_file (handle, ticketset, arg.ticketwritefile ? 
				     arg.ticketwritefile : arg.ticketfile);
      if (rc != SHISHI_OK)
	printf ("Could not write tickets: %s\n", shishi_strerror (rc));
    }

  shishi_ticketset_done(handle, ticketset);
  free (ticketfile);
  free (usercfgfile);
  shishi_done (handle);

  return rc;
}
