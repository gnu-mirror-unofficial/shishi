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
  Shisa_key **serverkeys = NULL, **userkeys = NULL;
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

  err = shisa_keys_find (dbh, realm, username, NULL, &userkeys, &nuserkeys);
  if (err != SHISA_OK)
    {
      syslog (LOG_ERR, "shisa_keys_find(%s@%s) failed (%d): %s",
	      username, realm, err, shisa_strerror (err));
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

  err = shisa_keys_find (dbh, realm, servername, NULL,
			 &serverkeys, &nserverkeys);
  if (err != SHISA_OK)
    {
      syslog (LOG_ERR, "shisa_keys_find(%s@%s) failed (%d): %s",
	      servername, realm, err, shisa_strerror (err));
      err = shishi_krberror_errorcode_set (handle, shishi_as_krberror (as),
					   SHISHI_KDC_ERR_S_PRINCIPAL_UNKNOWN);
      if (err != SHISHI_OK)
	goto fatal;
      return SHISHI_INVALID_PRINCIPAL_NAME;
    }

  syslog (LOG_INFO, "AS-REQ from %s@%s for %s@%s", username, realm,
	  servername, realm);

  /*
   * If required, the server pre-authenticates the request, and if the
   * pre-authentication check fails, an error message with the code
   * KDC_ERR_PREAUTH_FAILED is returned. If pre-authentication is
   * required, but was not present in the request, an error message with
   * the code KDC_ERR_PREAUTH_REQUIRED is returned and a METHOD-DATA
   * object will be stored in the e-data field of the KRB-ERROR message to
   * specify which pre-authentication mechanisms are acceptable.  Usually
   * this will include PA-ETYPE-INFO and/or PA-ETYPE-INFO2 elements as
   * described below. If the server cannot accommodate any encryption type
   * requested by the client, an error message with code
   * KDC_ERR_ETYPE_NOSUPP is returned. Otherwise the KDC generates a
   *  'random' session key[7].
   */

  /* XXX support pre-auth. */

  /*
   * When responding to an AS request, if there are multiple encryption
   * keys registered for a client in the Kerberos database, then the etype
   * field from the AS request is used by the KDC to select the encryption
   * method to be used to protect the encrypted part of the KRB_AS_REP
   * message which is sent to the client. If there is more than one
   * supported strong encryption type in the etype list, the KDC SHOULD
   * use the first valid strong etype for which an encryption key is
   * available.
   *
   * When the user's key is generated from a password or pass phrase, the
   * string-to-key function for the particular encryption key type is
   * used, as specified in [@KCRYPTO]. The salt value and additional
   * parameters for the string-to-key function have default values
   * (specified by section 4 and by the encryption mechanism
   * specification, respectively) that may be overridden by pre-
   * authentication data (PA-PW-SALT, PA-AFS3-SALT, PA-ETYPE-INFO, PA-
   * ETYPE-INFO2, etc). Since the KDC is presumed to store a copy of the
   * resulting key only, these values should not be changed for password-
   * based keys except when changing the principal's key.
   *
   * When the AS server is to include pre-authentication data in a KRB-
   * ERROR or in an AS-REP, it MUST use PA-ETYPE-INFO2, not PA-ETYPE-INFO,
   * if the etype field of the client's AS-REQ lists at least one "newer"
   * encryption type.  Otherwise (when the etype field of the client's AS-
   * REQ does not list any "newer" encryption types) it MUST send both,
   * PA-ETYPE-INFO2 and PA-ETYPE-INFO (both with an entry for each
   * enctype).  A "newer" enctype is any enctype first officially
   * specified concurrently with or subsequent to the issue of this RFC.
   * The enctypes DES, 3DES or RC4 and any defined in [RFC1510] are not
   * newer enctypes.
   *
   * It is not possible to reliably generate a user's key given a pass
   * phrase without contacting the KDC, since it will not be known whether
   * alternate salt or parameter values are required.
   *
   */

  for (i = 1; (err = shishi_kdcreq_etype (handle, shishi_as_req (as),
					  &etype, i)) == SHISHI_OK; i++)
    {
      size_t j;

      if (!shishi_cipher_supported_p (etype))
	continue;

      if (serverdbkey == NULL)
	for (j = 0; j < nserverkeys; j++)
	  {
	    syslog (LOG_DEBUG,
		    "Matching client etype %d against server key etype %d",
		    etype, serverkeys[j]->etype);
	    if (serverkeys[j]->etype == etype)
	      serverdbkey = serverkeys[j];
	  }

      if (userdbkey == NULL)
	for (j = 0; j < nuserkeys; j++)
	  {
	    syslog (LOG_DEBUG,
		    "Matching client etype %d against user key etype %d",
		    etype, userkeys[j]->etype);
	    if (userkeys[j]->etype == etype)
	      userdbkey = userkeys[j];
	  }
    }

  if (userdbkey == NULL)
    {
      syslog (LOG_NOTICE, "No matching client keys for %s@%s",
	      username, realm);
      err = shishi_krberror_errorcode_set (handle, shishi_as_krberror (as),
					   SHISHI_KDC_ERR_ETYPE_NOSUPP);
      if (err != SHISHI_OK)
	goto fatal;
      return SHISHI_INVALID_PRINCIPAL_NAME;
    }

  if (serverdbkey == NULL)
    {
      syslog (LOG_NOTICE, "No matching server keys for %s@%s",
	      servername, realm);
      err = shishi_krberror_errorcode_set (handle, shishi_as_krberror (as),
					   SHISHI_KDC_ERR_ETYPE_NOSUPP);
      if (err != SHISHI_OK)
	goto fatal;
      return SHISHI_INVALID_PRINCIPAL_NAME;
    }

  err = shishi_key_from_value (handle, userdbkey->etype,
			       userdbkey->key, &userkey);
  if (err != SHISHI_OK)
    {
      syslog (LOG_ERR, "shishi_key_from_value (user) failed (%d): %s",
	      err, shishi_strerror (err));
      goto fatal;
    }

  err = shishi_key_from_value (handle, serverdbkey->etype,
			       serverdbkey->key, &serverkey);
  if (err != SHISHI_OK)
    {
      syslog (LOG_ERR, "shishi_key_from_value (server) failed (%d): %s",
	      err, shishi_strerror (err));
      goto fatal;
    }

  /*
   * The KDC will attempt to assign the type of the random session key
   * from the list of methods in the etype field. The KDC will select the
   * appropriate type using the list of methods provided together with
   * information from the Kerberos database indicating acceptable
   * encryption methods for the application server. The KDC will not issue
   * tickets with a weak session key encryption type.
   */

  err = shishi_key_random (handle, shishi_key_type (serverkey), &sessionkey);
  if (err != SHISHI_OK)
    {
      syslog (LOG_ERR, "shishi_key_random (session key) failed (%d): %s",
	      err, shishi_strerror (err));
      goto fatal;
    }

  /*
   * If the requested start time is absent, indicates a time in the past,
   * or is within the window of acceptable clock skew for the KDC and the
   * POSTDATE option has not been specified, then the start time of the
   * ticket is set to the authentication server's current time. If it
   * indicates a time in the future beyond the acceptable clock skew, but
   * the POSTDATED option has not been specified then the error
   * KDC_ERR_CANNOT_POSTDATE is returned. Otherwise the requested start
   * time is checked against the policy of the local realm (the
   * administrator might decide to prohibit certain types or ranges of
   * postdated tickets), and if acceptable, the ticket's start time is set
   * as requested and the INVALID flag is set in the new ticket. The
   * postdated ticket MUST be validated before use by presenting it to the
   * KDC after the start time has been reached.
   *
   * The expiration time of the ticket will be set to the earlier of the
   * requested endtime and a time determined by local policy, possibly
   * determined using realm or principal specific factors. For example,
   * the expiration time MAY be set to the earliest of the following:
   *
   *   * The expiration time (endtime) requested in the KRB_AS_REQ
   * message.
   *
   *   * The ticket's start time plus the maximum allowable lifetime
   * associated with the client principal from the authentication
   * server's database.
   *
   *   * The ticket's start time plus the maximum allowable lifetime
   * associated with the server principal.
   *
   *   * The ticket's start time plus the maximum lifetime set by the
   * policy of the local realm.
   *
   * If the requested expiration time minus the start time (as determined
   * above) is less than a site-determined minimum lifetime, an error
   * message with code KDC_ERR_NEVER_VALID is returned. If the requested
   * expiration time for the ticket exceeds what was determined as above,
   * and if the 'RENEWABLE-OK' option was requested, then the 'RENEWABLE'
   * flag is set in the new ticket, and the renew-till value is set as if
   * the 'RENEWABLE' option were requested (the field and option names are
   * described fully in section 5.4.1).
   *
   * If the RENEWABLE option has been requested or if the RENEWABLE-OK
   * option has been set and a renewable ticket is to be issued, then the
   * renew-till field MAY be set to the earliest of:
   *
   *   * Its requested value.
   *
   *   * The start time of the ticket plus the minimum of the two
   * maximum renewable lifetimes associated with the principals'
   * database entries.
   *
   *   * The start time of the ticket plus the maximum renewable
   * lifetime set by the policy of the local realm.
   *
   * The flags field of the new ticket will have the following options set
   * if they have been requested and if the policy of the local realm
   * allows: FORWARDABLE, MAY-POSTDATE, POSTDATED, PROXIABLE, RENEWABLE.
   * If the new ticket is postdated (the start time is in the future), its
   * INVALID flag will also be set.
   */

  tkt = shishi_as_tkt (as);

  /* XXX */

  /*
   * If all of the above succeed, the server will encrypt the ciphertext
   * part of the ticket using the encryption key extracted from the server
   * principal's record in the Kerberos database using the encryption type
   * associated with the server principal's key (this choice is NOT
   * affected by the etype field in the request). It then formats a
   * KRB_AS_REP message (see section 5.4.2), copying the addresses in the
   * request into the caddr of the response, placing any required pre-
   * authentication data into the padata of the response, and encrypts the
   * ciphertext part in the client's key using an acceptable encryption
   * method requested in the etype field of the request, or in some key
   * specified by pre-authentication mechanisms being used.
   */

  err = shishi_tkt_key_set (tkt, sessionkey);
  if (err)
    return err;

  err = shishi_tkt_clientrealm_set (tkt, realm, username);
  if (err)
    return err;

  err = shishi_tkt_serverrealm_set (tkt, realm, servername);
  if (err)
    return err;

  /* XXX Use "best" server key, not the one chosen by client (see above). */
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
  if (err != SHISHI_OK)
    syslog (LOG_ERR, "AS-REQ failed (%d): %s", err, shishi_strerror (err));
  if (realm)
    free (realm);
  if (username)
    free (username);
  if (servername)
    free (servername);
  if (userkeys)
    shisa_keys_free (dbh, userkeys, nuserkeys);
  if (serverkeys)
    shisa_keys_free (dbh, serverkeys, nserverkeys);
  if (userkey)
    shishi_key_done (userkey);
  if (serverkey)
    shishi_key_done (serverkey);
  if (sessionkey)
    shishi_key_done (sessionkey);

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

  puts ("Processing TGS-REQ...");

  /*
   * The KRB_TGS_REQ message is processed in a manner similar to the
   * KRB_AS_REQ message, but there are many additional checks to be
   * performed. First, the Kerberos server MUST determine which server the
   * accompanying ticket is for and it MUST select the appropriate key to
   * decrypt it. For a normal KRB_TGS_REQ message, it will be for the
   * ticket granting service, and the TGS's key will be used. If the TGT
   * was issued by another realm, then the appropriate inter-realm key
   * MUST be used. If the accompanying ticket is not a ticket-granting
   * ticket for the current realm, but is for an application server in the
   * current realm, the RENEW, VALIDATE, or PROXY options are specified in
   * the request, and the server for which a ticket is requested is the
   * server named in the accompanying ticket, then the KDC will decrypt
   * the ticket in the authentication header using the key of the server
   * for which it was issued. If no ticket can be found in the padata
   * field, the KDC_ERR_PADATA_TYPE_NOSUPP error is returned.
   */

  rc = shishi_tgs_req_process (tgs);
  if (rc != SHISHI_OK)
    return rc;

  /* Get ticket used to authenticate request. */
  reqapticket = shishi_tkt_ticket (shishi_ap_tkt (shishi_tgs_ap (tgs)));

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
      syslog (LOG_ERR, "shishi_as failed (%d): %s", rc, shishi_strerror (rc));
      return rc;
    }

  shishi_as_req_set (as, kdcreq);

  rc = asreq1 (as);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_NOTICE, "AS-REQ failing with KRB-ERROR: %s",
	      shishi_krberror_message (handle, shishi_as_krberror (as)));
      rc = shishi_as_krberror_der (as, out, outlen);
    }
  else
    rc = shishi_as_rep_der (as, out, outlen);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR, "shishi_as_rep_der failed (%d): %s",
	      rc, shishi_strerror (rc));
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
      syslog (LOG_ERR, "shishi_tgs failed (%d): %s", rc, shishi_strerror (rc));
      return rc;
    }

  shishi_tgs_req_set (tgs, kdcreq);

  rc = tgsreq1 (tgs);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_NOTICE, "TGS-REQ failing with KRB-ERROR: %s",
	      shishi_krberror_message (handle, shishi_tgs_krberror (tgs)));
      rc = shishi_tgs_krberror_der (tgs, out, outlen);
    }
  else
    rc = shishi_tgs_rep_der (tgs, out, outlen);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR, "shishi_tgs_rep_der failed (%d): %s",
	      rc, shishi_strerror (rc));
      return rc;
    }

  return SHISHI_OK;
}

ssize_t
process (const char *in, size_t inlen, char **out)
{
  Shishi_asn1 node;
  size_t outlen;
  int rc;

  node = shishi_der2asn1 (handle, in, inlen);
  if (node == NULL)
    {
      syslog (LOG_ERR, "Received %d bytes of non-Kerberos 5 data", inlen);
      return -1;
    }

  switch (shishi_asn1_msgtype (handle, node))
    {
    case SHISHI_MSGTYPE_AS_REQ:
      rc = asreq (node, out, &outlen);
      break;

    case SHISHI_MSGTYPE_TGS_REQ:
      rc = tgsreq (node, out, &outlen);
      break;

    default:
      syslog (LOG_ERR, "Unsupported KDC message type %d (0x%x)",
	      shishi_asn1_msgtype (handle, node),
	      shishi_asn1_msgtype (handle, node));
      rc = SHISHI_ASN1_ERROR;
      break;
    }

  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR, "Fatal error answering request (%d): %s",
	      rc, shishi_strerror (rc));
      return -1;
    }

  return outlen;
}
