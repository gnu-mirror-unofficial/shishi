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

/* Note: only use syslog to report errors in this file. */

/* Get Shishid stuff. */
#include "kdc.h"

static int
asreq1 (Shishi_as * as)
{
  Shishi_tkt *tkt;
  Shishi_key *serverkey = NULL, *sessionkey = NULL, *userkey = NULL;
  Shisa_key *serverdbkey = NULL, *userdbkey = NULL;
  Shisa_key **serverkeys, **userkeys;
  size_t nserverkeys, nuserkeys;
  int err;
  char *username = NULL, *servername = NULL, *realm = NULL;
  Shisa_principal krbtgt;
  Shisa_principal user;
  uint32_t etype;
  int i;

  /*
   * The authentication server looks up the client and server principals
   * named in the KRB_AS_REQ in its database, extracting their respective
   * keys. If the requested client principal named in the request is not
   * known because it doesn't exist in the KDC's principal database, then
   * an error message with a KDC_ERR_C_PRINCIPAL_UNKNOWN is returned.
   */

  err = shishi_kdcreq_realm (handle, shishi_as_req (as), &realm, NULL);
  if (err != SHISHI_OK)
    {
      syslog (LOG_ERR, "shishi_kdcreq_realm failed (%d): %s",
	      err, shishi_strerror (err));
      goto fatal;
    }

  err = shishi_kdcreq_client (handle, shishi_as_req (as), &username, NULL);
  if (err != SHISHI_OK)
    {
      syslog (LOG_ERR, "shishi_kdcreq_client failed (%d): %s",
	      err, shishi_strerror (err));
      goto fatal;
    }

  err = shishi_kdcreq_server (handle, shishi_as_req (as), &servername, NULL);
  if (err != SHISHI_OK)
    {
      syslog (LOG_ERR, "shishi_kdcreq_server failed (%d): %s",
	      err, shishi_strerror (err));
      goto fatal;
    }

  /* Find the client, e.g., simon@JOSEFSSON.ORG. */

  err = shisa_principal_find (dbh, realm, username, &user);
  if (err != SHISA_OK && err != SHISA_NO_PRINCIPAL)
    {
      syslog (LOG_ERR, "shisa_principal_find failed (%d): %s",
	      err, shisa_strerror (err));
      goto fatal;
    }
  if (err == SHISA_NO_PRINCIPAL)
    {
      syslog (LOG_NOTICE, "AS-REQ from %s@%s for %s@%s failed: no such user",
	      username, realm, servername, realm);
      err = shishi_krberror_errorcode_set (handle, shishi_as_krberror (as),
					   SHISHI_KDC_ERR_C_PRINCIPAL_UNKNOWN);
      if (err != SHISHI_OK)
	goto fatal;
      return SHISHI_INVALID_PRINCIPAL_NAME;
    }

  /* Find the server, e.g., krbtgt/JOSEFSSON.ORG@JOSEFSSON.ORG. */

  err = shisa_principal_find (dbh, realm, servername, &krbtgt);
  if (err != SHISA_OK && err != SHISA_NO_PRINCIPAL)
    {
      syslog (LOG_ERR, "shisa_principal_find failed (%d): %s",
	      err, shisa_strerror (err));
      goto fatal;
    }
  if (err == SHISA_NO_PRINCIPAL)
    {
      syslog (LOG_NOTICE, "AS-REQ from %s@%s for %s@%s failed: no such server",
	      username, realm, servername, realm);
      err = shishi_krberror_errorcode_set (handle, shishi_as_krberror (as),
					   SHISHI_KDC_ERR_S_PRINCIPAL_UNKNOWN);
      if (err != SHISHI_OK)
	goto fatal;
      return SHISHI_INVALID_PRINCIPAL_NAME;
    }

  syslog (LOG_INFO, "AS-REQ from %s@%s for %s@%s", username, realm,
	  servername, realm);

  /* Enumerate keys for user and server. */

  err = shisa_keys_find (dbh, realm, servername, NULL,
			 &serverkeys, &nserverkeys);
  if (err != SHISA_OK)
    {
      printf ("Error getting keys for %s@%s\n", servername, realm);
      return SHISHI_INVALID_PRINCIPAL_NAME;
    }
  printf ("Found keys for server %s@%s...\n", servername, realm);

  err = shisa_keys_find (dbh, realm, username, NULL, &userkeys, &nuserkeys);
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

  err = SHISHI_OK;

 fatal:
  if (realm)
    free (realm);
  if (username)
    free (username);
  if (servername)
    free (servername);

  return err;
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

  rc = shisa_keys_find (dbh, tgrealm, tgname, NULL, &tgkeys, &ntgkeys);
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

  rc = shisa_keys_find (dbh, serverrealm, servername, NULL,
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

ssize_t
process (char *in, int inlen, char **out)
{
  size_t outlen;
  int rc;

  *out = NULL;

  rc = process_1 (in, inlen, out, &outlen);
  if (rc != SHISHI_OK)
    return -1;

  return outlen;
}
