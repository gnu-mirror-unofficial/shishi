/* shishi.c	command line interface to shishi
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
#include <argp.h>

const char *program_name = PACKAGE;
const char *argp_program_version = PACKAGE_STRING;
const char *argp_program_bug_address = PACKAGE_BUGREPORT;

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

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  struct arguments *arguments = state->input;

  switch (key)
    {
    case 'q':
      arguments->silent = 1;
      break;

    case 'v':
      arguments->verbose = 1;
      break;

    case OPTION_VERBOSE_LIBRARY:
      arguments->verbose_library = 1;
      break;

    case 'o':
      arguments->lib_options = arg;
      break;

    case 'w':
      arguments->ticketwritefile = strdup (arg);
      break;

    case 'e':
      arguments->etypes = strdup (arg);
      break;

    case 's':
      arguments->systemcfgfile = strdup (arg);
      break;

    case 'c':
      arguments->usercfgfile = strdup (arg);
      break;

    case 't':
      arguments->ticketfile = strdup (arg);
      break;

      /* Crypto */

    case OPTION_CRYPTO_ALGORITHM:
      if (arguments->command != COMMAND_CRYPTO)
	argp_error (state, _("Option `%s' only valid with CRYPTO."),
		    state->argv[state->next - 1]);
      arguments->algorithm = shishi_cipher_parse (arg);
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

    case OPTION_CRYPTO_SALT:
      if (arguments->command != COMMAND_CRYPTO)
	argp_error (state, _("Option `%s' only valid with CRYPTO."),
		    state->argv[state->next - 1]);
      arguments->salt = strdup (arg);
      break;

    case OPTION_CRYPTO_PARAMETER:
      if (arguments->command != COMMAND_CRYPTO)
	argp_error (state, _("Option `%s' only valid with CRYPTO."),
		    state->argv[state->next - 1]);
      arguments->parameter = strdup (arg);
      break;

    case OPTION_CRYPTO_PASSWORD:
    case OPTION_GET_PASSWORD:
      if (arguments->command != COMMAND_CRYPTO &&
	  arguments->command != COMMAND_GET)
	argp_error
	  (state,
	   _("Option `%s' only valid with GET and CRYPTO."),
	   state->argv[state->next - 1]);
      arguments->password = strdup (arg);
      break;

    case OPTION_CRYPTO_RANDOM:
      if (arguments->command != COMMAND_CRYPTO)
	argp_error (state, _("Option `%s' only valid with CRYPTO."),
		    state->argv[state->next - 1]);
      arguments->random = 1;
      break;

    case OPTION_CRYPTO_READ_DATA_FILE:
      if (arguments->command != COMMAND_CRYPTO)
	argp_error (state, _("Option `%s' only valid with CRYPTO."),
		    state->argv[state->next - 1]);
      parse_filename (arg, &arguments->inputtype, &arguments->inputfile);
      if (arguments->inputtype == SHISHI_FILETYPE_TEXT ||
	  arguments->inputtype == SHISHI_FILETYPE_DER)
	arguments->inputtype = SHISHI_FILETYPE_BINARY;
      break;

    case OPTION_CRYPTO_WRITE_DATA_FILE:
      if (arguments->command != COMMAND_CRYPTO)
	argp_error (state, _("Option `%s' only valid with CRYPTO."),
		    state->argv[state->next - 1]);
      parse_filename (arg, &arguments->outputtype, &arguments->outputfile);
      if (arguments->outputtype == SHISHI_FILETYPE_TEXT ||
	  arguments->outputtype == SHISHI_FILETYPE_DER)
	arguments->outputtype = SHISHI_FILETYPE_BINARY;
      break;

    case OPTION_CRYPTO_READ_KEY_FILE:
      if (arguments->command != COMMAND_CRYPTO)
	argp_error (state, _("Option `%s' only valid with CRYPTO."),
		    state->argv[state->next - 1]);
      arguments->readkeyfile = strdup (arg);
      break;

    case OPTION_CRYPTO_WRITE_KEY_FILE:
      if (arguments->command != COMMAND_CRYPTO)
	argp_error (state, _("Option `%s' only valid with CRYPTO."),
		    state->argv[state->next - 1]);
      arguments->writekeyfile = strdup (arg);
      break;

      /* Authenticator */

    case OPTION_AP_AUTHENTICATOR_READ_FILE:
      if (arguments->command != COMMAND_AP)
	argp_error (state, _("Option `%s' only valid with AP."),
		    state->argv[state->next - 1]);
      parse_filename (arg, &arguments->authenticatorreadtype,
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
      parse_filename (arg, &arguments->authenticatordatareadtype,
		      &arguments->authenticatordatareadfile);
      if (arguments->authenticatordatareadtype == SHISHI_FILETYPE_TEXT ||
	  arguments->authenticatordatareadtype == SHISHI_FILETYPE_DER)
	arguments->authenticatordatareadtype = SHISHI_FILETYPE_BINARY;
      break;

    case OPTION_CRYPTO_CLIENT_NAME:
    case OPTION_GET_CLIENT_NAME:
      if (arguments->command != COMMAND_CRYPTO &&
	  arguments->command != COMMAND_GET)
	argp_error (state, _("Option `%s' only valid with CRYPTO and GET."),
		    state->argv[state->next - 1]);
      arguments->cname = strdup (arg);
      break;

    case 'r':
    case OPTION_AP_REALM:
    case OPTION_CRYPTO_REALM:
    case OPTION_GET_REALM:
      if (arguments->command != COMMAND_AP &&
	  arguments->command != COMMAND_CRYPTO &&
	  arguments->command != COMMAND_GET)
	argp_error (state, _("Option `%s' only valid with AP, CRYPTO and GET."),
		    state->argv[state->next - 1]);
      arguments->realm = strdup (arg);
      break;

    case OPTION_CRYPTO_KEY_VALUE:
    case OPTION_GET_KEY_VALUE:
      if (arguments->command != COMMAND_CRYPTO &&
	  arguments->command != COMMAND_GET)
	argp_error (state,
		    _("Option `%s' only valid with CRYPTO and GET."),
		    state->argv[state->next - 1]);
      arguments->keyvalue = strdup (arg);
      break;

    case OPTION_CRYPTO_KEY_USAGE:
      if (arguments->command != COMMAND_CRYPTO)
	argp_error (state, _("Option `%s' only valid with CRYPTO."),
		    state->argv[state->next - 1]);
      arguments->keyusage = atoi (arg);
      break;

    case OPTION_CRYPTO_KEY_VERSION:
      if (arguments->command != COMMAND_CRYPTO)
	argp_error (state, _("Option `%s' only valid with CRYPTO."),
		    state->argv[state->next - 1]);
      arguments->kvno = atoi (arg);
      break;

    case OPTION_AP_SERVER_NAME:
    case OPTION_LIST_SERVER_NAME:
    case OPTION_GET_SERVER_NAME:
      arguments->sname = strdup (arg);
      break;

    case OPTION_GET_FORCE_AS:
      if (arguments->command != COMMAND_GET)
	argp_error (state, _("Option `%s' only valid with GET."),
		    state->argv[state->next - 1]);
      arguments->forceas_p = 1;
      break;

    case OPTION_GET_FORCE_TGS:
      if (arguments->command != COMMAND_GET)
	argp_error (state, _("Option `%s' only valid with GET."),
		    state->argv[state->next - 1]);
      arguments->forcetgs_p = 1;
      break;

    case OPTION_GET_TICKET_GRANTER:
      if (arguments->command != COMMAND_GET)
	argp_error (state, _("Option `%s' only valid with GET."),
		    state->argv[state->next - 1]);
      arguments->tgtname = strdup (arg);
      break;

    case OPTION_GET_REQUEST:
      if (arguments->command != COMMAND_GET)
	argp_error (state, _("Option `%s' only valid with GET."),
		    state->argv[state->next - 1]);
      arguments->request_p = 1;
      break;

    case OPTION_AP_REQUEST_WRITE_FILE:
    case OPTION_GET_WRITE_AP_REQUEST_FILE:
      if (arguments->command != COMMAND_GET &&
	  arguments->command != COMMAND_AP)
	argp_error (state,
		    _("Option `%s' only valid with AP and GET."),
		    state->argv[state->next - 1]);
      parse_filename (arg, &arguments->apreqwritetype,
		      &arguments->apreqwritefile);
      break;

    case OPTION_AP_AUTHENTICATOR_WRITE_FILE:
    case OPTION_GET_WRITE_AUTHENTICATOR_FILE:
      if (arguments->command != COMMAND_AP ||
	  arguments->command != COMMAND_GET)
	argp_error (state,
		    _("Option `%s' only valid with AP and GET."),
		    state->argv[state->next - 1]);
      parse_filename (arg, &arguments->authenticatorwritetype,
		      &arguments->authenticatorwritefile);
      break;

    case OPTION_GET_WRITE_REQUEST_FILE:
      if (arguments->command != COMMAND_GET)
	argp_error (state, _("Option `%s' only valid with GET."),
		    state->argv[state->next - 1]);
      parse_filename (arg, &arguments->kdcreqwritetype,
		      &arguments->kdcreqwritefile);
      break;

    case OPTION_GET_READ_REQUEST_FILE:
      if (arguments->command != COMMAND_GET)
	argp_error (state, _("Option `%s' only valid with GET."),
		    state->argv[state->next - 1]);
      parse_filename (arg, &arguments->kdcreqreadtype,
		      &arguments->kdcreqreadfile);
      break;

    case OPTION_GET_WRITE_RESPONSE_FILE:
      if (arguments->command != COMMAND_GET)
	argp_error (state, _("Option `%s' only valid with GET."),
		    state->argv[state->next - 1]);
      parse_filename (arg, &arguments->kdcrepwritetype,
		      &arguments->kdcrepwritefile);
      break;

    case OPTION_GET_READ_RESPONSE_FILE:
      if (arguments->command != COMMAND_GET)
	argp_error (state, _("Option `%s' only valid with GET."),
		    state->argv[state->next - 1]);
      parse_filename (arg, &arguments->kdcrepreadtype,
		      &arguments->kdcrepreadfile);
      break;

    case OPTION_GET_SENDRECV:
      if (arguments->command != COMMAND_GET)
	argp_error (state, _("Option `%s' only valid with GET."),
		    state->argv[state->next - 1]);
      arguments->sendrecv_p = 1;
      break;

    case OPTION_GET_RESPONSE:
      if (arguments->command != COMMAND_GET)
	argp_error (state, _("Option `%s' only valid with GET."),
		    state->argv[state->next - 1]);
      arguments->response_p = 1;
      break;

    case ARGP_KEY_ARG:
      if (arguments->command && arguments->client)
	argp_error (state, _("Too many arguments: `%s'"), arg);
      else
	{
	  if (strcmp (arg, "get") == 0)
	    {
	      arguments->command = COMMAND_GET;
	    }
	  else if (strcmp (arg, "list") == 0)
	    {
	      arguments->command = COMMAND_LIST;
	    }
	  else if (strcmp (arg, "destroy") == 0)
	    {
	      arguments->command = COMMAND_DESTROY;
	    }
	  else if (strcmp (arg, "ap") == 0)
	    {
	      arguments->command = COMMAND_AP;
	    }
	  else if (strcmp (arg, "crypto") == 0)
	    {
	      arguments->command = COMMAND_CRYPTO;
	    }
	  else
	    {
	      if (!arguments->command)
		arguments->command = COMMAND_GET;
	      arguments->client = arg;
	    }
	  break;
	}
      break;

    default:
      return ARGP_ERR_UNKNOWN;
    }

  return 0;
}

static struct argp_option options[] = {

  {0, 0, 0, 0, "Ticket management:", 20},

  {"destroy", 0, 0, OPTION_DOC | OPTION_NO_USAGE,
   "Destroy tickets."},

  {"get", 0, 0, OPTION_DOC | OPTION_NO_USAGE,
   "Acquire tickets."},

  {"list", 0, 0, OPTION_DOC | OPTION_NO_USAGE,
   "List tickets."},

  {0, 0, 0, 0, "Low-level commands:", 40},

  {"ap", 0, 0, OPTION_DOC | OPTION_NO_USAGE,
   "Client/Server Authentication (AP-REQ and AP-REP)."},

  {"crypto", 0, 0, OPTION_DOC | OPTION_NO_USAGE,
   "Cryptographic functions."},

  {0, 0, 0, 0, "If no command is given, Shishi invokes the GET command "
   "if no ticket granting ticket is found for the default realm, otherwise "
   " the LIST command is invoked.", 50},

  /************** LIST */

  {0, 0, 0, 0, "Options for the List command (LIST-OPTIONS):", 300},

  {"server-name", OPTION_LIST_SERVER_NAME, "NAME", 0,
   "List tickets for specified server only."},

  /************** DESTROY */

  {0, 0, 0, 0, "Options for the Destroy command (DESTROY-OPTIONS):", 400},

  {"server-name", OPTION_DESTROY_SERVER_NAME, "NAME", 0,
   "Destroy tickets for specified server only."},

  /************** AP */

  {0, 0, 0, 0,
   "Options for low-level Client/Server Authentication (AP-OPTIONS):", 700},

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
   "Options for low-level cryptography (CRYPTO-OPTIONS):", 800},

  {"algorithm", OPTION_CRYPTO_ALGORITHM, "ALGORITHM", 0,
   "Cipher algorithm, expressed either as the etype integer or "
   "the registered name."},

  {"client-name", OPTION_GET_CLIENT_NAME, "NAME", 0,
   "Username. Default is login name."},

  {"decrypt", OPTION_CRYPTO_DECRYPT, 0, 0,
   "Decrypt data."},

  {"encrypt", OPTION_CRYPTO_ENCRYPT, 0, 0,
   "Encrypt data."},

  {"key-usage", OPTION_CRYPTO_KEY_USAGE, "KEYUSAGE", 0,
   "Encrypt or decrypt using specified key usage.  Default is 0, which means no "
   "key derivation are performed."},

  {"key-value", OPTION_CRYPTO_KEY_VALUE, "KEY", 0,
   "Base64 encoded key value."},

  {"key-version", OPTION_CRYPTO_KEY_VERSION, "INTEGER", 0,
   "Version number of key."},

  {"password", OPTION_CRYPTO_PASSWORD, "PASSWORD", 0,
   "Password used to generate key.  --client-name and --realm also modify "
   "the computed key value."},

  {"random", OPTION_CRYPTO_RANDOM, 0, 0,
   "Generate key from random data."},

  {"read-key-file", OPTION_CRYPTO_READ_KEY_FILE, "FILE", 0,
   "Read cipher key from FILE"},

  {"read-data-file", OPTION_CRYPTO_READ_DATA_FILE, "[TYPE,]FILE", 0,
   "Read data from FILE in TYPE, BASE64, HEX or BINARY (default)."},

  {"realm", 'r', "REALM", 0,
   "Realm of principal. Defaults to DNS domain of local host. "},

  {"salt", OPTION_CRYPTO_SALT, "SALT", 0,
   "Salt to use when --password is specified. Defaults to using the"
   "username (--client-name) and realm (--realm)."},

  {"parameter", OPTION_CRYPTO_PARAMETER, "STRING", 0,
   "String-to-key parameter to use when --password is specified. This data "
   "is specific for each encryption algorithm and rarely needed."},

  {"write-key-file", OPTION_CRYPTO_WRITE_KEY_FILE, "FILE", 0,
   "Append cipher key to FILE"},

  {"write-data-file", OPTION_CRYPTO_WRITE_DATA_FILE, "[TYPE,]FILE", 0,
   "Write data to FILE in TYPE, BASE64, HEX or BINARY (default)."},

  /************** GET */

  {0, 0, 0, 0,
   "Options for ticket acquisition (GET-OPTIONS):", 900},

  {"client-name", OPTION_GET_CLIENT_NAME, "NAME", 0,
   "Client name. Default is login username. Only for AS."},

  {"encryption-type", 'e', "ETYPE,[ETYPE...]", 0,
   "Encryption types to use.  ETYPE is either registered name or integer."},

  {"force-as", OPTION_GET_FORCE_AS, 0, 0,
   "Force AS mode. Default is to use TGS iff a TGT is found."},

  {"force-tgs", OPTION_GET_FORCE_TGS, 0, 0,
   "Force TGS mode. Default is to use TGS iff a TGT is found."},

  {"realm", 'r', "REALM", 0,
   "Realm of server. Default is DNS domain of local host. For AS, this also "
   "indicates realm of client."},

  {"server", OPTION_GET_SERVER, "HOST", 0,
   "Send request to HOST. Default uses address from configuration file."},

  {"server-name", OPTION_GET_SERVER_NAME, "NAME", 0,
   "Server name. Default is \"krbtgt/REALM\" where REALM is server "
   "realm (see --realm)."},

  {"ticket-granter", OPTION_GET_TICKET_GRANTER, "NAME", 0,
   "Service name in ticket to use for authenticating request. Only for TGS. "
   "Defaults to \"krbtgt/REALM@REALM\" where REALM is server "
   "realm (see --realm)."},

  {"key-value", OPTION_GET_KEY_VALUE, "KEY", 0,
   "Cipher key to decrypt response (discouraged)."},

  {"read-kdc-request-file", OPTION_GET_READ_REQUEST_FILE, "[TYPE,]FILE", 0,
   "Read KDC-REQ from FILE in format TYPE; TEXT (default) or DER. "
   "Default is to generate it."},

  {"read-kdc-response-file", OPTION_GET_READ_RESPONSE_FILE, "[TYPE,]FILE", 0,
   "Read KDC-REP from FILE in format TYPE; TEXT (default) or DER. "
   "Default is to receive it from server."},

  {"request", OPTION_GET_REQUEST, 0, 0,
   "Only generate the request."},

  {"response", OPTION_GET_RESPONSE, 0, 0,
   "Only parse request and response and output ticket."},

  {"sendrecv", OPTION_GET_SENDRECV, 0, 0,
   "Only send request and receive response."},

  {"password", OPTION_CRYPTO_PASSWORD, "PASSWORD", 0,
   "Password to decrypt response (discouraged).  Only for AS."},

  {"write-ap-request-file", OPTION_GET_WRITE_AP_REQUEST_FILE, "[TYPE,]FILE",
   0,
   "Write AP-REQ to FILE in TYPE, either TEXT (default) or DER. "
   "Only for TGS. Not written by default."},

  {"write-authenticator-file", OPTION_GET_WRITE_AUTHENTICATOR_FILE,
   "[TYPE,]FILE", 0,
   "Write Authenticator to FILE in TYPE, either TEXT (default) or DER. "
   "Only for TGS. Not written by default."},

  {"write-kdc-request-file", OPTION_GET_WRITE_REQUEST_FILE, "[TYPE,]FILE", 0,
   "Write KDC-REQ to FILE in format TYPE; TEXT (default) or DER. "
   "Not written by default."},

  {"write-kdc-response-file", OPTION_GET_WRITE_RESPONSE_FILE, "[TYPE,]FILE",
   0,
   "Write KDC-REP to FILE in format TYPE; TEXT (default) or DER. "
   "Not written by default."},

  /************** OTHER */

  {0, 0, 0, 0, "Other options:", 1000},

  {"verbose", 'v', 0, 0,
   "Produce verbose output.",},

  {"verbose-library", OPTION_VERBOSE_LIBRARY, 0, 0,
   "Produce verbose output in the library.",},

  {"quiet", 'q', 0, 0,
   "Don't produce any output."},

  {"silent", 0, 0, OPTION_ALIAS},

  {"system-configuration-file", 's', "FILE", 0,
   "Read system wide configuration from file.  Default is " SYSTEMCFGFILE
   "."},

  {"configuration-file", 'c', "FILE", 0,
   "Read user configuration from file.  Default is ~/.shishi/config."},

  {"library-options", 'o', "STRING", 0,
   "Parse STRING as a configuration file statement."},

  {"ticket-file", 't', "FILE", 0,
   "Read tickets from FILE. Default is $HOME/.shishi/tickets."},

  {"ticket-write-file", 'w', "FILE", 0,
   "Write tickets to FILE.  Default is to write them back to ticket file."},

  {"NAME", 0, 0, OPTION_DOC | OPTION_NO_USAGE,
   "Set client name and realm from NAME.  The --client-name and --realm can "
   "be used to override part of NAME."},

  /************** EXAMPLES */

  {0, 0, 0, 0, "Examples:", 2000},

  {"shishi", 0, 0, OPTION_DOC | OPTION_NO_USAGE,
   "Get a ticket granting ticket from the default KDC server for the "
   "default user and realm."},

  {"shishi jas/admin@ACCOUNTING", 0, 0, OPTION_DOC | OPTION_NO_USAGE,
   "Get a ticket for jas/admin in the ACCOUNTING realm."},

  {"shishi list --server-name=krbtgt/JOSEFSSON.ORG@JOSEFSSON.ORG",
   0, 0, OPTION_DOC | OPTION_NO_USAGE,
   "List tickets for the Ticket Granting Service in the JOSEFSSON.ORG realm."},

  {0}
};

static struct argp argp = {
  options,
  parse_opt,
  "[COMMAND] [NAME] [OPTION...]\n"
  "destroy [DESTROY-OPTION...]\n"
  "get [GET-OPTION...]\n"
  "list [LIST-OPTION...]\n"
  "ap [AP-OPTION...]\n"
  "crypto [CRYPTO-OPTION...]\n",
  "Shishi -- A Kerberos 5 implementation"
};

int
main (int argc, char *argv[])
{
  struct arguments arg;
  Shishi *handle;
  int rc;

  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);

  memset (&arg, 0, sizeof (arg));
  argp_parse (&argp, argc, argv, ARGP_IN_ORDER, 0, &arg);

  rc = shishi_init_with_paths (&handle, arg.ticketfile,
			       arg.systemcfgfile, arg.usercfgfile);
  if (rc == SHISHI_HANDLE_ERROR)
    error (1, 0, "Internal error: could not initialize shishi\n");

  rc = shishi_cfg_clientkdcetype_set (handle, arg.etypes);
  if (rc != SHISHI_OK)
    error (1, 0, "Could not set encryption types: %s\n", shishi_strerror (rc));

  if (arg.client)
    {
      rc = shishi_parse_name (handle, arg.client,
			      arg.cname ? NULL : &arg.cname,
			      arg.realm ? NULL : &arg.realm);

      if (rc != SHISHI_OK)
	error (1, 0, "Could not parse principal \"%s\": %s\n", arg.client,
	       shishi_strerror (rc));
    }

  rc = shishi_cfg (handle, arg.lib_options);
  if (rc != SHISHI_OK)
    error (1, 0, "Could not read library options: %s\n", shishi_strerror (rc));

  if (arg.verbose_library)
    {
      rc = shishi_cfg (handle, "verbose");
      if (rc != SHISHI_OK)
	error (1, 0, "Could not make library verbose: %s\n",
	       shishi_strerror (rc));
    }

  if (arg.cname != NULL)
    shishi_principal_default_set (handle, arg.cname);

  if (arg.realm != NULL)
    shishi_realm_default_set (handle, arg.realm);

  if (arg.tgtname == NULL)
    {
      asprintf (&arg.tgtname, "krbtgt/%s", shishi_realm_default (handle));
      if (arg.tgtname == NULL)
	error (1, 0, "Could not allocate TGT name.");
    }

  rc = 1;

  switch (arg.command)
    {
    case COMMAND_GET:
    default:
      {
	Shishi_tkt *tkt;
	Shishi_tkts_hint hint;

	memset (&hint, 0, sizeof (hint));
	hint.client = (char *) arg.cname;
	hint.server = (char *) arg.sname ? arg.sname : arg.tgtname;

	tkt = shishi_tkts_get (shishi_tkts_default (handle), &hint);
	if (!tkt)
	  {
	    printf ("Could not get ticket for `%s'.\n",
		    arg.tgtname ? arg.tgtname : arg.cname);
	    rc = !SHISHI_OK;
	  }
	else
	  {
	    rc = shishi_tkt_pretty_print (tkt, stdout);
	    if (rc != SHISHI_OK)
	      fprintf (stderr, "Pretty printing ticket failed:\n%s\n%s\n",
		       shishi_strerror (rc), shishi_strerror_details (handle));
	  }
      }
      break;

    case COMMAND_LIST:
      if (!arg.silent)
	printf (_("Tickets in `%s':\n"), shishi_tkts_default_file (handle));

      rc = shishi_tkts_print_for_service (shishi_tkts_default (handle),
					  stdout, arg.sname);
      if (rc != SHISHI_OK)
	fprintf (stderr, "Could not list tickets: %s", shishi_strerror (rc));
      break;

    case COMMAND_DESTROY:
      {
	int i, removed = 0;
	for (i = 0; i < shishi_tkts_size (shishi_tkts_default (handle)); i++)
	  {
	    if (arg.sname &&
		!shishi_tkt_server_p (shishi_tkts_nth
				      (shishi_tkts_default (handle),
				       i), arg.sname))
	      continue;

	    if (arg.verbose)
	      {
		printf ("Removing ticket:\n");
		shishi_tkt_pretty_print (shishi_tkts_nth
					 (shishi_tkts_default
					  (handle), i), stdout);
	      }

	    rc = shishi_tkts_remove (shishi_tkts_default (handle), i);
	    if (rc != SHISHI_OK)
	      fprintf (stderr, "Could not destroy ticket %d:\n%s\n", i,
		       shishi_strerror (rc));
	    i--;
	    removed++;
	  }
	if (removed == 0)
	  printf ("No tickets removed.\n");
	else if (removed == 1)
	  printf ("1 ticket removed.\n");
	else
	  printf ("%d tickets removed.\n", removed);
	rc = SHISHI_OK;
      }
      break;

    case COMMAND_AP:
      rc = ap (handle, arg);
      break;

    case COMMAND_CRYPTO:
      rc = crypto (handle, arg);
      if (rc != SHISHI_OK)
	fprintf (stderr, "Operation failed:\n%s\n%s\n",
		 shishi_strerror (rc), shishi_strerror_details (handle));
      break;
    }

  shishi_tkts_expire (shishi_tkts_default (handle));

  if (arg.ticketwritefile)
    shishi_tkts_default_file_set (handle, arg.ticketwritefile);

  shishi_done (handle);

  return rc == SHISHI_OK ? 0 : 1;
}
