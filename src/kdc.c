/* kdc.c --- Process AS and TGS requests.
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

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>

#ifdef HAVE_SYSLOG_H
# include <syslog.h>
#endif

/* Setup i18n. */
#ifdef HAVE_LOCALE_H
# include <locale.h>
#else
# define setlocale(Category, Locale) /* empty */
#endif
#include <gettext.h>
#define _(String) gettext (String)
#define gettext_noop(String) String
#define N_(String) gettext_noop (String)

/* Get xmalloc. */
#include "xalloc.h"

/* Get asprintf. */
#include "vasprintf.h"

/* Get program_name, etc. */
#include "progname.h"

/* Shishi and Shisa library. */
#include <shishi.h>
#include <shisa.h>

/* Command line parameter parser via gengetopt. */
#include "shishid_cmd.h"

extern Shishi * handle;
extern Shisa * dbh;
extern struct gengetopt_args_info arg;
extern char *fatal_krberror;
extern size_t fatal_krberror_len;

static int
asreq1 (Shishi_as * as)
{
  Shishi_tkt *tkt;
  Shishi_key *serverkey = NULL, *sessionkey = NULL, *userkey = NULL;
  Shisa_key *serverdbkey = NULL, *userdbkey = NULL;
  Shisa_key **serverkeys, **userkeys;
  size_t nserverkeys, nuserkeys;
  int err;
  char *username, *servername, *realm;
  Shisa_principal krbtgt;
  Shisa_principal user;
  uint32_t etype;
  int i;

  /* Find the server, e.g., krbtgt/JOSEFSSON.ORG@JOSEFSSON.ORG. */

  err = shishi_kdcreq_server (handle, shishi_as_req (as), &servername, NULL);
  if (err != SHISHI_OK)
    return err;
  printf ("servername %s\n", servername);

  err = shishi_kdcreq_realm (handle, shishi_as_req (as), &realm, NULL);
  if (err != SHISHI_OK)
    return err;
  printf ("client & server realm %s\n", realm);

  err = shisa_principal_find (dbh, realm, servername, &krbtgt);
  if (err != SHISA_OK)
    {
      printf ("server %s@%s not found\n", servername, realm);
      return SHISHI_INVALID_PRINCIPAL_NAME;
    }
  printf ("Found server %s@%s...\n", servername, realm);

  /* Find the user, e.g., simon@JOSEFSSON.ORG. */

  err = shishi_kdcreq_client (handle, shishi_as_req (as), &username, NULL);
  if (err != SHISHI_OK)
    return err;
  printf ("username %s\n", username);

  err = shisa_principal_find (dbh, realm, username, &user);
  if (err != SHISA_OK)
    {
      printf ("user %s@%s not found\n", username, realm);
      return SHISHI_INVALID_PRINCIPAL_NAME;
    }
  printf ("Found user %s@%s...\n", username, realm);

  /* Enumerate keys for user and server. */

  err = shisa_enumerate_keys (dbh, realm, servername,
			      &serverkeys, &nserverkeys);
  if (err != SHISA_OK)
    {
      printf ("Error getting keys for %s@%s\n", servername, realm);
      return SHISHI_INVALID_PRINCIPAL_NAME;
    }
  printf ("Found keys for server %s@%s...\n", servername, realm);

  err = shisa_enumerate_keys (dbh, realm, username,
			      &userkeys, &nuserkeys);
  if (err != SHISA_OK)
    {
      printf ("Error getting keys for %s@%s\n", username, realm);
      return SHISHI_INVALID_PRINCIPAL_NAME;
    }
  printf ("Found keys for user %s@%s...\n", username, realm);

  /* Select keys in database that match supplied encryption type. */

  for (i = 1; (err = shishi_kdcreq_etype (handle, shishi_as_req (as),
					  &etype, i)) == SHISHI_OK; i++)
    {
      size_t j;
      printf ("Trying etype %d...\n", etype);
      if (!shishi_cipher_supported_p (etype))
	continue;
      if (serverdbkey == NULL)
	for (j = 0; j < nserverkeys; j++)
	  {
	    printf ("Matching against server etype %d...\n",
		    serverkeys[j]->etype);
	    if (serverkeys[j]->etype == etype)
		serverdbkey = serverkeys[j];
	  }
      if (userdbkey == NULL)
	for (j = 0; j < nuserkeys; j++)
	  {
	    printf ("Matching against user etype %d...\n",
		    userkeys[j]->etype);
	    if (userkeys[j]->etype == etype)
	      userdbkey = userkeys[j];
	  }
    }

  if (userdbkey == NULL)
    {
      printf ("No key found for %s@%s\n", username, realm);
      return SHISHI_INVALID_PRINCIPAL_NAME;
    }

  if (serverdbkey == NULL)
    {
      printf ("No key found for %s@%s\n", servername, realm);
      return SHISHI_INVALID_PRINCIPAL_NAME;
    }

  err = shishi_key_from_value (handle, userdbkey->etype,
			       userdbkey->key, &userkey);
  if (err != SHISHI_OK)
    return err;

  err = shishi_key_from_value (handle, serverdbkey->etype,
			       serverdbkey->key, &serverkey);
  if (err != SHISHI_OK)
    return err;

  /* Generate session key of same key type as the selected long-term
     server key. */

  err = shishi_key_random (handle, shishi_key_type (serverkey), &sessionkey);
  if (err)
    return err;

  /* Build Ticket and AS-REP. */

  tkt = shishi_as_tkt (as);

  err = shishi_tkt_key_set (tkt, sessionkey);
  if (err)
    return err;

  err = shishi_tkt_clientrealm_set (tkt, realm, username);
  if (err)
    return err;

  err = shishi_tkt_serverrealm_set (tkt, realm, servername);
  if (err)
    return err;

  err = shishi_tkt_build (tkt, serverkey);
  if (err)
    return err;

  err = shishi_as_rep_build (as, userkey);
  if (err)
    return err;

  if (arg.verbose_flag)
    {
      shishi_kdcreq_print (handle, stderr, shishi_as_req (as));
      shishi_encticketpart_print (handle, stderr,
				  shishi_tkt_encticketpart (tkt));
      shishi_ticket_print (handle, stderr, shishi_tkt_ticket (tkt));
      shishi_enckdcreppart_print (handle, stderr,
				  shishi_tkt_enckdcreppart (tkt));
      shishi_kdcrep_print (handle, stderr, shishi_as_rep (as));
    }

  return SHISHI_OK;
}

static int
tgsreq1 (Shishi_tgs * tgs)
{
  int rc;
  Shishi_tkt *tkt;
  Shishi_key *newsessionkey, *oldsessionkey, *serverkey, *subkey, *tgkey;
  char *servername, *serverrealm, *tgname, *tgrealm, *client, *clientrealm;
  Shisa_principal krbtgt;
  Shishi_asn1 reqapticket;
  Shisa_key **tgkeys;
  size_t ntgkeys;
  Shisa_key **serverkeys;
  size_t nserverkeys;
  int i;

  /* Extract pa-data and populate tgs->ap. */
  rc = shishi_tgs_req_process (tgs);
  if (rc != SHISHI_OK)
    return rc;

  /* Get ticket used to authenticate request. */
  rc = shishi_apreq_get_ticket (handle, shishi_ap_req (shishi_tgs_ap (tgs)),
				&reqapticket);
  if (rc != SHISHI_OK)
    return rc;

  /* Find name of ticket granter, e.g., krbtgt/JOSEFSSON.ORG@JOSEFSSON.ORG. */

  rc = shishi_ticket_realm_get (handle, reqapticket, &tgrealm, NULL);
  if (rc != SHISHI_OK)
    return rc;
  printf ("tg realm %s\n", tgrealm);

  rc = shishi_ticket_server (handle, reqapticket, &tgname, NULL);
  if (rc != SHISHI_OK)
    return rc;
  printf ("Found ticket granter name %s@%s...\n", tgname, tgrealm);

  /* We need to decrypt the ticket granting ticket, get key. */

  rc = shisa_enumerate_keys (dbh, tgrealm, tgname, &tgkeys, &ntgkeys);
  if (rc != SHISA_OK)
    {
      printf ("Error getting keys for %s@%s\n", tgname, tgrealm);
      return SHISHI_INVALID_PRINCIPAL_NAME;
    }
  printf ("Found keys for ticket granter %s@%s...\n", tgname, tgrealm);

  /* XXX use etype/kvno to select key. */

  rc = shishi_key_from_value (handle, tgkeys[0]->etype,
			       tgkeys[0]->key, &tgkey);
  if (rc != SHISHI_OK)
    return rc;

  shishi_key_print (handle, stdout, tgkey);

  /* Find the server, e.g., host/latte.josefsson.org@JOSEFSSON.ORG. */

  rc = shishi_kdcreq_realm (handle, shishi_tgs_req (tgs), &serverrealm, NULL);
  if (rc != SHISHI_OK)
    return rc;
  printf ("server realm %s\n", serverrealm);

  rc = shishi_kdcreq_server (handle, shishi_tgs_req (tgs), &servername, NULL);
  if (rc != SHISHI_OK)
    return rc;
  printf ("servername %s\n", servername);

  rc = shisa_principal_find (dbh, serverrealm, servername, &krbtgt);
  if (rc != SHISA_OK)
    {
      printf ("server %s@%s not found\n", servername, serverrealm);
      return SHISHI_INVALID_PRINCIPAL_NAME;
    }
  printf ("Found server %s@%s...\n", servername, serverrealm);

  /* Get key for server, used to encrypt new ticket. */

  rc = shisa_enumerate_keys (dbh, serverrealm, servername,
			     &serverkeys, &nserverkeys);
  if (rc != SHISA_OK)
    {
      printf ("Error getting keys for %s@%s\n", servername, serverrealm);
      return SHISHI_INVALID_PRINCIPAL_NAME;
    }
  printf ("Found keys for server %s@%s...\n", servername, serverrealm);

  /* XXX select "best" available key (tgs-req etype list, highest
     kvno, best algorithm?) here. */

  rc = shishi_key_from_value (handle, serverkeys[0]->etype,
			       serverkeys[0]->key, &serverkey);
  if (rc != SHISHI_OK)
    return rc;

  shishi_key_print (handle, stdout, serverkey);

  /* Decrypt incoming ticket with our key, and decrypt authenticator
     using key stored in ticket. */
  rc = shishi_ap_req_process_keyusage
    (shishi_tgs_ap (tgs), tgkey, SHISHI_KEYUSAGE_TGSREQ_APREQ_AUTHENTICATOR);
  if (rc != SHISHI_OK)
    return rc;

  /* XXX check that checksum in authenticator match tgsreq.req-body */

  tkt = shishi_tgs_tkt (tgs);

  /* Generate session key for the newly generated ticket, of same key
     type as the selected long-term server key. */

  rc = shishi_key_random (handle, shishi_key_type (serverkey),
			   &newsessionkey);
  if (rc)
    return rc;

  rc = shishi_tkt_key_set (tkt, newsessionkey);
  if (rc)
    return rc;

  /* In the new ticket, store identity of the client, taken from the
     decrypted incoming ticket. */

  rc = shishi_encticketpart_crealm
    (handle, shishi_tkt_encticketpart (shishi_ap_tkt (shishi_tgs_ap (tgs))),
     &clientrealm, NULL);
  if (rc != SHISHI_OK)
    return rc;
  printf ("userrealm %s\n", clientrealm);

  rc = shishi_encticketpart_client
    (handle, shishi_tkt_encticketpart (shishi_ap_tkt (shishi_tgs_ap (tgs))),
     &client, NULL);
  if (rc != SHISHI_OK)
    return rc;
  printf ("username %s\n", client);

  rc = shishi_tkt_clientrealm_set (tkt, clientrealm, client);
  if (rc)
    return rc;

  rc = shishi_tkt_serverrealm_set (tkt, serverrealm, servername);
  if (rc)
    return rc;

  /* Build new key, using the server's key. */

  rc = shishi_tkt_build (tkt, serverkey);
  if (rc)
    return rc;

  /* The TGS-REP need to be encrypted, decide which key to use.
     Either it is the session key in the incoming ticket, or it is the
     sub-key in the authenticator. */

  rc = shishi_encticketpart_get_key
    (handle,
     shishi_tkt_encticketpart (shishi_ap_tkt (shishi_tgs_ap (tgs))),
     &oldsessionkey);
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_authenticator_get_subkey
    (handle, shishi_ap_authenticator (shishi_tgs_ap (tgs)), &subkey);
  if (rc != SHISHI_OK && rc != SHISHI_ASN1_NO_ELEMENT)
    return rc;

  /* Build TGS-REP. */

  if (rc == SHISHI_OK)
    rc = shishi_tgs_rep_build
      (tgs, SHISHI_KEYUSAGE_ENCTGSREPPART_AUTHENTICATOR_KEY, subkey);
  else
    rc = shishi_tgs_rep_build
      (tgs, SHISHI_KEYUSAGE_ENCTGSREPPART_SESSION_KEY, oldsessionkey);
  if (rc)
    return rc;

  if (arg.verbose_flag)
    {
      puts ("KDC-REQ in:");
      shishi_kdcreq_print (handle, stderr, shishi_tgs_req (tgs));
      puts ("AP-REQ in KDC-REQ:");
      shishi_apreq_print (handle, stderr,
			  shishi_ap_req (shishi_tgs_ap (tgs)));
      puts ("Authenticator in AP-REQ in KDC-REQ:");
      shishi_authenticator_print (handle, stderr, shishi_ap_authenticator
				  (shishi_tgs_ap (tgs)));
      puts ("Ticket in AP-REQ:");
      shishi_ticket_print (handle, stdout,
			   shishi_tkt_ticket
			   (shishi_ap_tkt (shishi_tgs_ap (tgs))));
      puts ("EncTicketPart in AP-REQ:");
      shishi_encticketpart_print (handle, stdout,
				  shishi_tkt_encticketpart
				  (shishi_ap_tkt (shishi_tgs_ap (tgs))));
      puts ("Ticket in TGS-REP:");
      shishi_ticket_print (handle, stdout, shishi_tkt_ticket (tkt));
      puts ("EncTicketPart in TGS-REP:");
      shishi_encticketpart_print (handle, stderr,
				  shishi_tkt_encticketpart (tkt));
      puts ("EncKDCRepPart in TGS-REP:");
      shishi_enckdcreppart_print (handle, stderr,
				  shishi_tkt_enckdcreppart (tkt));
      puts ("KDC-REP:");
      shishi_kdcrep_print (handle, stderr, shishi_tgs_rep (tgs));
    }

  return SHISHI_OK;
}

static int
asreq (Shishi_asn1 kdcreq, char **out, size_t * outlen)
{
  Shishi_as *as;
  int rc;

  rc = shishi_as (handle, &as);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR, "Cannot create AS: %s\n", shishi_strerror (rc));
      return rc;
    }

  shishi_as_req_set (as, kdcreq);

  rc = asreq1 (as);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_NOTICE, "Could not answer request: %s: %s\n",
	      shishi_strerror (rc),
	      shishi_krberror_message (handle, shishi_as_krberror (as)));
      rc = shishi_as_krberror_der (as, out, outlen);
    }
  else
    rc = shishi_as_rep_der (as, out, outlen);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR, "Cannot DER encode reply: %s\n", shishi_strerror (rc));
      return rc;
    }

  return SHISHI_OK;
}

static int
tgsreq (Shishi_asn1 kdcreq, char **out, size_t * outlen)
{
  Shishi_tgs *tgs;
  int rc;

  rc = shishi_tgs (handle, &tgs);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR, "Cannot create TGS: %s\n", shishi_strerror (rc));
      return rc;
    }

  shishi_tgs_req_set (tgs, kdcreq);

  rc = tgsreq1 (tgs);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_NOTICE, "Could not answer request: %s: %s\n",
	      shishi_strerror (rc),
	      shishi_krberror_message (handle, shishi_tgs_krberror (tgs)));
      rc = shishi_tgs_krberror_der (tgs, out, outlen);
    }
  else
    rc = shishi_tgs_rep_der (tgs, out, outlen);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR, "Cannot DER encode reply: %s\n", shishi_strerror (rc));
      return rc;
    }

  return SHISHI_OK;
}

static int
process_1 (char *in, size_t inlen, char **out, size_t * outlen)
{
  Shishi_asn1 node;
  Shishi_asn1 krberr;
  int rc;

  krberr = shishi_krberror (handle);
  if (!krberr)
    return SHISHI_MALLOC_ERROR;

  node = shishi_der2asn1 (handle, in, inlen);

  fprintf (stderr, "ASN.1 msg-type %d (0x%x)...\n",
	   shishi_asn1_msgtype (handle, node),
	   shishi_asn1_msgtype (handle, node));

  switch (shishi_asn1_msgtype (handle, node))
    {
    case SHISHI_MSGTYPE_AS_REQ:
      puts ("Processing AS-REQ...");
      rc = asreq (node, out, outlen);
      break;

    case SHISHI_MSGTYPE_TGS_REQ:
      puts ("Processing TGS-REQ...");
      rc = tgsreq (node, out, outlen);
      break;

    default:
      rc = !SHISHI_OK;
      break;
    }

  if (rc != SHISHI_OK)
    {
      rc = shishi_krberror_set_etext (handle, krberr, "General error");
      if (rc != SHISHI_OK)
	return rc;

      rc = shishi_krberror_set_realm (handle, krberr, "unknown");
      if (rc != SHISHI_OK)
	return rc;

      rc = shishi_krberror_der (handle, krberr, out, outlen);
      if (rc != SHISHI_OK)
	return rc;
    }

  return SHISHI_OK;
}

void
process (char *in, int inlen, char **out, size_t * outlen)
{
  int rc;

  *out = NULL;
  *outlen = 0;

  rc = process_1 (in, inlen, out, outlen);

  if (rc != SHISHI_OK || *out == NULL || *outlen == 0)
    {
      *out = fatal_krberror;
      *outlen = fatal_krberror_len;
    }
}
