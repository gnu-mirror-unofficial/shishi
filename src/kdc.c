/* kdc.c --- Process AS and TGS requests.
 * Copyright (C) 2002, 2003, 2004, 2005, 2007, 2008  Simon Josefsson
 *
 * This file is part of Shishi.
 *
 * Shishi is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * Shishi is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Shishi; if not, see http://www.gnu.org/licenses or write
 * to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
 * Floor, Boston, MA 02110-1301, USA
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
  Shisa_key *userdbkey = NULL;
  Shisa_key **serverkeys = NULL, **userkeys = NULL;
  size_t nserverkeys, nuserkeys;
  int rc;
  char *username = NULL, *servername = NULL, *realm = NULL;
  Shisa_principal server, user;
  int32_t sessionkeytype = -1;
  int32_t etype;
  int i;

  /*
   * The authentication server looks up the client and server principals
   * named in the KRB_AS_REQ in its database, extracting their respective
   * keys. If the requested client principal named in the request is not
   * known because it doesn't exist in the KDC's principal database, then
   * an error message with a KDC_ERR_C_PRINCIPAL_UNKNOWN is returned.
   */

  rc = shishi_kdcreq_realm (handle, shishi_as_req (as), &realm, NULL);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR, "shishi_kdcreq_realm failed (%d): %s",
	      rc, shishi_strerror (rc));
      goto fatal;
    }

  rc = shishi_kdcreq_client (handle, shishi_as_req (as), &username, NULL);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR, "shishi_kdcreq_client failed (%d): %s",
	      rc, shishi_strerror (rc));
      goto fatal;
    }

  rc = shishi_kdcreq_server (handle, shishi_as_req (as), &servername, NULL);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR, "shishi_kdcreq_server failed (%d): %s",
	      rc, shishi_strerror (rc));
      goto fatal;
    }

  /* Find the client, e.g., simon@JOSEFSSON.ORG. */

  rc = shisa_principal_find (dbh, realm, username, &user);
  if (rc != SHISA_OK && rc != SHISA_NO_PRINCIPAL)
    {
      syslog (LOG_ERR, "shisa_principal_find failed (%d): %s",
	      rc, shisa_strerror (rc));
      rc = SHISHI_INVALID_PRINCIPAL_NAME;
      goto fatal;
    }
  if (rc == SHISA_NO_PRINCIPAL)
    {
      syslog (LOG_NOTICE, "AS-REQ from %s@%s for %s@%s failed: no such user",
	      username, realm, servername, realm);
      rc = shishi_krberror_errorcode_set (handle, shishi_as_krberror (as),
					  SHISHI_KDC_ERR_C_PRINCIPAL_UNKNOWN);
      if (rc != SHISHI_OK)
	goto fatal;
      rc = SHISHI_INVALID_PRINCIPAL_NAME;
      goto fatal;
    }

  rc = shisa_keys_find (dbh, realm, username, NULL, &userkeys, &nuserkeys);
  if (rc != SHISA_OK || nuserkeys == 0)
    {
      syslog (LOG_ERR, "shisa_keys_find(%s@%s) failed (%d): %s",
	      username, realm, rc, shisa_strerror (rc));
      rc = SHISHI_INVALID_PRINCIPAL_NAME;
      goto fatal;
    }

  /* Find the server, e.g., krbtgt/JOSEFSSON.ORG@JOSEFSSON.ORG. */

  rc = shisa_principal_find (dbh, realm, servername, &server);
  if (rc != SHISA_OK && rc != SHISA_NO_PRINCIPAL)
    {
      syslog (LOG_ERR, "shisa_principal_find failed (%d): %s",
	      rc, shisa_strerror (rc));
      rc = SHISHI_INVALID_PRINCIPAL_NAME;
      goto fatal;
    }
  if (rc == SHISA_NO_PRINCIPAL)
    {
      syslog (LOG_NOTICE,
	      "AS-REQ from %s@%s for %s@%s failed: no such server", username,
	      realm, servername, realm);
      rc =
	shishi_krberror_errorcode_set (handle, shishi_as_krberror (as),
				       SHISHI_KDC_ERR_S_PRINCIPAL_UNKNOWN);
      if (rc != SHISHI_OK)
	goto fatal;
      rc = SHISHI_INVALID_PRINCIPAL_NAME;
      goto fatal;
    }

  rc = shisa_keys_find (dbh, realm, servername, NULL,
			&serverkeys, &nserverkeys);
  if (rc != SHISA_OK || nserverkeys == 0)
    {
      syslog (LOG_ERR, "shisa_keys_find(%s@%s) failed (%d): %s",
	      servername, realm, rc, shisa_strerror (rc));
      rc = SHISHI_INVALID_PRINCIPAL_NAME;
      goto fatal;
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
   */

  for (i = 1; (rc = shishi_kdcreq_etype (handle, shishi_as_req (as),
					 &etype, i)) == SHISHI_OK; i++)
    {
      size_t j;

      if (!shishi_cipher_supported_p (etype))
	continue;

      if (sessionkeytype == -1)
	for (j = 0; j < nserverkeys; j++)
	  if (serverkeys[j]->etype == etype)
	    sessionkeytype = serverkeys[j]->etype;

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
      rc = shishi_krberror_errorcode_set (handle, shishi_as_krberror (as),
					  SHISHI_KDC_ERR_ETYPE_NOSUPP);
      if (rc != SHISHI_OK)
	goto fatal;
      rc = SHISHI_INVALID_PRINCIPAL_NAME;
      goto fatal;
    }


  rc = shishi_key_from_value (handle, userdbkey->etype,
			      userdbkey->key, &userkey);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR, "shishi_key_from_value (user) failed (%d): %s",
	      rc, shishi_strerror (rc));
      goto fatal;
    }

  /* XXX Select "best" available key (highest kvno, best algorithm?)
     here. The client etype should not influence this. */
  rc = shishi_key_from_value (handle, serverkeys[0]->etype,
			      serverkeys[0]->key, &serverkey);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR, "shishi_key_from_value (server) failed (%d): %s",
	      rc, shishi_strerror (rc));
      goto fatal;
    }
  /*
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

  /* XXX support pre-auth. */

  /*
   * The KDC will attempt to assign the type of the random session key
   * from the list of methods in the etype field. The KDC will select the
   * appropriate type using the list of methods provided together with
   * information from the Kerberos database indicating acceptable
   * encryption methods for the application server. The KDC will not issue
   * tickets with a weak session key encryption type.
   */

  if (sessionkeytype == -1)
    sessionkeytype = shishi_cfg_clientkdcetype_fast (handle);

  rc = shishi_key_random (handle, sessionkeytype, &sessionkey);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR, "shishi_key_random (session key) failed (%d): %s",
	      rc, shishi_strerror (rc));
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
   */

  tkt = shishi_as_tkt (as);
  if (tkt == NULL)
    {
      syslog (LOG_ERR, "shishi_as_tkt failed");
      goto fatal;
    }

  {
    char *till;
    size_t tilllen;

    rc = shishi_kdcreq_till (handle, shishi_as_req (as), &till, &tilllen);
    if (rc != SHISHI_OK)
      {
	syslog (LOG_ERR, "shishi_kdcreq_till failed (%d): %s",
		rc, shishi_strerror (rc));
	goto fatal;
      }

    if (tilllen != 16 || strlen (till) != 15)
      {
	syslog (LOG_ERR, "Invalid 'till' field in request (%d): %s", tilllen,
		till);
	goto fatal;
      }

    rc = shishi_encticketpart_endtime_set (handle,
					   shishi_tkt_encticketpart (tkt),
					   till);

    free (till);
  }

  /* XXX Do the time stuff above. */

  /*
   * The flags field of the new ticket will have the following options set
   * if they have been requested and if the policy of the local realm
   * allows: FORWARDABLE, MAY-POSTDATE, POSTDATED, PROXIABLE, RENEWABLE.
   * If the new ticket is postdated (the start time is in the future), its
   * INVALID flag will also be set.
   */

  if (shishi_kdcreq_forwardable_p (handle, shishi_as_req (as)))
    shishi_tkt_flags_add (tkt, SHISHI_TICKETFLAGS_FORWARDABLE);

  if (shishi_kdcreq_allow_postdate_p (handle, shishi_as_req (as)))
    shishi_tkt_flags_add (tkt, SHISHI_TICKETFLAGS_MAY_POSTDATE);

  if (shishi_kdcreq_postdated_p (handle, shishi_as_req (as)))
    {
      /* XXX policy check from time. */
      shishi_tkt_flags_add (tkt, SHISHI_TICKETFLAGS_POSTDATED);
      shishi_tkt_flags_add (tkt, SHISHI_TICKETFLAGS_INVALID);
      /* XXX set starttime to from */
    }

  if (shishi_kdcreq_proxiable_p (handle, shishi_as_req (as)))
    shishi_tkt_flags_add (tkt, SHISHI_TICKETFLAGS_PROXIABLE);

  if (shishi_kdcreq_renewable_p (handle, shishi_as_req (as)))
    {
      shishi_tkt_flags_add (tkt, SHISHI_TICKETFLAGS_RENEWABLE);
      /* XXX set renew-till from rtime */
    }

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

  rc = shishi_tkt_key_set (tkt, sessionkey);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR, "shishi_tkt_key_set failed (%d): %s",
	      rc, shishi_strerror (rc));
      goto fatal;
    }

  rc = shishi_tkt_clientrealm_set (tkt, realm, username);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR, "shishi_tkt_clientrealm_set failed (%d): %s",
	      rc, shishi_strerror (rc));
      goto fatal;
    }

  rc = shishi_tkt_serverrealm_set (tkt, realm, servername);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR, "shishi_tkt_serverrealm_set failed (%d): %s",
	      rc, shishi_strerror (rc));
      goto fatal;
    }

  rc = shishi_tkt_build (tkt, serverkey);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR, "shishi_tkt_build failed (%d): %s",
	      rc, shishi_strerror (rc));
      goto fatal;
    }

  rc = shishi_as_rep_build (as, userkey);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR, "shishi_as_rep_build failed (%d): %s",
	      rc, shishi_strerror (rc));
      goto fatal;
    }

  if (arg.verbose_given)
    {
      shishi_kdcreq_print (handle, stderr, shishi_as_req (as));
      shishi_encticketpart_print (handle, stderr,
				  shishi_tkt_encticketpart (tkt));
      shishi_ticket_print (handle, stderr, shishi_tkt_ticket (tkt));
      shishi_enckdcreppart_print (handle, stderr,
				  shishi_tkt_enckdcreppart (tkt));
      shishi_kdcrep_print (handle, stderr, shishi_as_rep (as));
    }

  rc = SHISHI_OK;

fatal:
  if (rc != SHISHI_OK)
    syslog (LOG_ERR, "AS-REQ failed (%d): %s", rc, shishi_strerror (rc));
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

  return rc;
}

static int
tgsreq1 (Shishi_tgs * tgs)
{
  int rc;
  Shishi_tkt *tkt;
  Shishi_key *newsessionkey = NULL, *oldsessionkey = NULL;
  Shishi_key *serverkey = NULL, *subkey = NULL, *tgkey = NULL;
  char *servername = NULL, *serverrealm = NULL;
  char *tgname = NULL, *tgrealm = NULL;
  char *clientname = NULL, *clientrealm = NULL;
  Shisa_principal krbtgt, server;
  Shisa_key **tgkeys = NULL, **serverkeys = NULL;
  size_t ntgkeys, nserverkeys;

  rc = shishi_tgs_req_process (tgs);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR, "shishi_tgs_req_process failed (%d): %s",
	      rc, shishi_strerror (rc));
      goto fatal;
    }

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

  /* Find name of ticket granter, e.g., krbtgt/JOSEFSSON.ORG@JOSEFSSON.ORG. */

  rc = shishi_tkt_realm (shishi_ap_tkt (shishi_tgs_ap (tgs)), &tgrealm, NULL);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR, "shishi_tkt_realm failed (%d): %s",
	      rc, shishi_strerror (rc));
      goto fatal;
    }

  rc = shishi_tkt_server (shishi_ap_tkt (shishi_tgs_ap (tgs)), &tgname, NULL);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR, "shishi_tkt_server failed (%d): %s",
	      rc, shishi_strerror (rc));
      goto fatal;
    }

  syslog (LOG_DEBUG, "TGS-REQ uses ticket granter %s@%s", tgname, tgrealm);

  rc = shisa_principal_find (dbh, tgrealm, tgname, &krbtgt);
  if (rc != SHISA_OK && rc != SHISA_NO_PRINCIPAL)
    {
      syslog (LOG_ERR, "shisa_principal_find(%s@%s) failed (%d): %s",
	      tgname, tgrealm, rc, shisa_strerror (rc));
      rc = SHISHI_INVALID_PRINCIPAL_NAME;
      goto fatal;
    }
  if (rc == SHISA_NO_PRINCIPAL)
    {
      syslog (LOG_NOTICE, "TGS-REQ using %s@%s failed: no such tgt",
	      tgname, tgrealm);
      rc = shishi_krberror_errorcode_set (handle, shishi_tgs_krberror (tgs),
					  SHISHI_KRB_AP_ERR_NOT_US);
      if (rc != SHISHI_OK)
	goto fatal;
      rc = SHISHI_INVALID_PRINCIPAL_NAME;
      goto fatal;
    }

  rc = shisa_keys_find (dbh, tgrealm, tgname, NULL, &tgkeys, &ntgkeys);
  if (rc != SHISA_OK || ntgkeys == 0)
    {
      syslog (LOG_ERR, "shisa_keys_find(%s@%s) failed (%d): %s",
	      tgname, tgrealm, rc, shisa_strerror (rc));
      rc = SHISHI_INVALID_PRINCIPAL_NAME;
      goto fatal;
    }

  /* XXX use etype/kvno to select key. */

  rc = shishi_key_from_value (handle, tgkeys[0]->etype,
			      tgkeys[0]->key, &tgkey);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR, "shishi_key_from_value (tgt) failed (%d): %s",
	      rc, shishi_strerror (rc));
      goto fatal;
    }

  rc = shishi_ap_req_process_keyusage
    (shishi_tgs_ap (tgs), tgkey, SHISHI_KEYUSAGE_TGSREQ_APREQ_AUTHENTICATOR);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR, "shishi_ap_req_process_keyusage failed (%d): %s",
	      rc, shishi_strerror (rc));
      goto fatal;
    }

  /*
   * 3.3.3.1. Checking for revoked tickets
   *
   * Whenever a request is made to the ticket-granting server, the
   * presented ticket(s) is(are) checked against a hot-list of tickets
   * which have been canceled. This hot-list might be implemented by
   * storing a range of issue timestamps for 'suspect tickets'; if a
   * presented ticket had an authtime in that range, it would be rejected.
   * In this way, a stolen ticket-granting ticket or renewable ticket
   * cannot be used to gain additional tickets (renewals or otherwise)
   * once the theft has been reported to the KDC for the realm in which
   * the server resides. Any normal ticket obtained before it was reported
   * stolen will still be valid (because they require no interaction with
   * the KDC), but only until their normal expiration time. If TGT's have
   * been issued for cross-realm authentication, use of the cross-realm
   * TGT will not be affected unless the hot-list is propagated to the
   * KDCs for the realms for which such cross-realm tickets were issued.
   */

  /* XXX Check if tgname@tgrealm is a valid TGT. */

  /*
   * Once the accompanying ticket has been decrypted, the user-supplied
   * checksum in the Authenticator MUST be verified against the contents
   * of the request, and the message rejected if the checksums do not
   * match (with an error code of KRB_AP_ERR_MODIFIED) or if the checksum
   * is not collision-proof (with an error code of
   * KRB_AP_ERR_INAPP_CKSUM). If the checksum type is not supported, the
   * KDC_ERR_SUMTYPE_NOSUPP error is returned. If the authorization-data
   * are present, they are decrypted using the sub-session key from the
   * Authenticator.
   *
   * If any of the decryptions indicate failed integrity checks, the
   * KRB_AP_ERR_BAD_INTEGRITY error is returned.
   */

  /* XXX check that checksum in authenticator match tgsreq.req-body */

  syslog (LOG_DEBUG, "TGS-REQ authentication OK using %s@%s", tgname,
	  tgrealm);

  /*
   * As discussed in section 3.1.2, the KDC MUST send a valid KRB_TGS_REP
   * message if it receives a KRB_TGS_REQ message identical to one it has
   * recently processed. However, if the authenticator is a replay, but
   * the rest of the request is not identical, then the KDC SHOULD return
   * KRB_AP_ERR_REPEAT.
   */

  /* XXX Do replay stuff. */

  /*
   * The response will include a ticket for the requested server or for a
   * ticket granting server of an intermediate KDC to be contacted to
   * obtain the requested ticket. The Kerberos database is queried to
   * retrieve the record for the appropriate server (including the key
   * with which the ticket will be encrypted). If the request is for a
   * ticket-granting ticket for a remote realm, and if no key is shared
   * with the requested realm, then the Kerberos server will select the
   * realm 'closest' to the requested realm with which it does share a
   * key, and use that realm instead.  Thss is theonly cases where the
   * response for the KDC will be for a different server than that
   * requested by the client.
   */

  rc = shishi_kdcreq_realm (handle, shishi_tgs_req (tgs), &serverrealm, NULL);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR, "shishi_kdcreq_realm failed (%d): %s",
	      rc, shishi_strerror (rc));
      goto fatal;
    }

  /* XXX Do cross-realm handling. */

  rc = shishi_kdcreq_server (handle, shishi_tgs_req (tgs), &servername, NULL);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR, "shishi_kdcreq_server failed (%d): %s",
	      rc, shishi_strerror (rc));
      goto fatal;
    }

  rc = shisa_principal_find (dbh, serverrealm, servername, &server);
  if (rc != SHISA_OK && rc != SHISA_NO_PRINCIPAL)
    {
      syslog (LOG_ERR, "shisa_principal_find(%s@%s) failed (%d): %s",
	      servername, serverrealm, rc, shisa_strerror (rc));
      rc = SHISHI_INVALID_PRINCIPAL_NAME;
      goto fatal;
    }
  if (rc == SHISA_NO_PRINCIPAL)
    {
      syslog (LOG_NOTICE, "TGS-REQ for %s@%s failed: no such server",
	      servername, serverrealm);
      rc = shishi_krberror_errorcode_set (handle, shishi_tgs_krberror (tgs),
					  SHISHI_KDC_ERR_S_PRINCIPAL_UNKNOWN);
      if (rc != SHISHI_OK)
	goto fatal;
      rc = SHISHI_INVALID_PRINCIPAL_NAME;
      goto fatal;
    }

  rc = shisa_keys_find (dbh, serverrealm, servername, NULL,
			&serverkeys, &nserverkeys);
  if (rc != SHISA_OK || nserverkeys == 0)
    {
      syslog (LOG_ERR, "shisa_keys_find(%s@%s) failed (%d): %s",
	      servername, serverrealm, rc, shisa_strerror (rc));
      rc = SHISHI_INVALID_PRINCIPAL_NAME;
      goto fatal;
    }

  /* XXX Select "best" available key (highest kvno, best algorithm?)
     here. The client etype should not influence this. */
  rc = shishi_key_from_value (handle, serverkeys[0]->etype,
			      serverkeys[0]->key, &serverkey);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR, "shisa_key_from_value (server) failed (%d): %s",
	      rc, shishi_strerror (rc));
      goto fatal;
    }

  /* Generate session key for the newly generated ticket, of same key
     type as the selected long-term server key.  XXX let the client
     influence the etype? think of AES only server and RFC 1510
     client. if client etype is not used here, the client cannot talk
     to the server. perhaps just as good though. */

  rc = shishi_key_random (handle, shishi_key_type (serverkey),
			  &newsessionkey);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR, "shishi_key_random failed (%d): %s",
	      rc, shishi_strerror (rc));
      goto fatal;
    }

  /*
   * By default, the address field, the client's name and realm, the list
   * of transited realms, the time of initial authentication, the
   * expiration time, and the authorization data of the newly-issued
   * ticket will be copied from the ticket-granting ticket (TGT) or
   * renewable ticket. If the transited field needs to be updated, but the
   * transited type is not supported, the KDC_ERR_TRTYPE_NOSUPP error is
   * returned.
   */

  tkt = shishi_tgs_tkt (tgs);
  if (tkt == NULL)
    {
      syslog (LOG_ERR, "shishi_tgs_tkt failed");
      goto fatal;
    }

  rc = shishi_encticketpart_crealm
    (handle, shishi_tkt_encticketpart (shishi_ap_tkt (shishi_tgs_ap (tgs))),
     &clientrealm, NULL);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR, "shishi_encticketpart_crealm failed (%d): %s",
	      rc, shishi_strerror (rc));
      goto fatal;
    }

  rc = shishi_encticketpart_client
    (handle, shishi_tkt_encticketpart (shishi_ap_tkt (shishi_tgs_ap (tgs))),
     &clientname, NULL);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR, "shishi_encticketpart_client failed (%d): %s",
	      rc, shishi_strerror (rc));
      goto fatal;
    }

  rc = shishi_tkt_clientrealm_set (tkt, clientrealm, clientname);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR, "shishi_tkt_clientrealm_set failed (%d): %s",
	      rc, shishi_strerror (rc));
      goto fatal;
    }

  /* XXX Copy more fields.  Move copying into lib/? */

  rc = shishi_encticketpart_endtime_set
    (handle, shishi_tkt_encticketpart (tkt),
     shishi_generalize_time (handle,
			     shishi_kdcreq_tillc (handle,
						  shishi_tgs_req (tgs))));
  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR, "shishi_encticketpart_endtime_set failed (%d): %s",
	      rc, shishi_strerror (rc));
      goto fatal;
    }

  rc = shishi_tkt_key_set (tkt, newsessionkey);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR, "shishi_tkt_key_set failed (%d): %s",
	      rc, shishi_strerror (rc));
      goto fatal;
    }

  rc = shishi_tkt_serverrealm_set (tkt, serverrealm, servername);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR, "shishi_tkt_serverrealm_set failed (%d): %s",
	      rc, shishi_strerror (rc));
      goto fatal;
    }

  syslog (LOG_DEBUG, "TGS-REQ from %s@%s for %s@%s",
	  clientname, clientrealm, servername, serverrealm);

  /*
   * If the request specifies an endtime, then the endtime of the new
   * ticket is set to the minimum of (a) that request, (b) the endtime
   * from the TGT, and (c) the starttime of the TGT plus the minimum of
   * the maximum life for the application server and the maximum life for
   * the local realm (the maximum life for the requesting principal was
   * already applied when the TGT was issued). If the new ticket is to be
   * a renewal, then the endtime above is replaced by the minimum of (a)
   * the value of the renew_till field of the ticket and (b) the starttime
   * for the new ticket plus the life (endtime-starttime) of the old
   * ticket.
   *
   * If the FORWARDED option has been requested, then the resulting ticket
   * will contain the addresses specified by the client. This option will
   * only be honored if the FORWARDABLE flag is set in the TGT. The PROXY
   * option is similar; the resulting ticket will contain the addresses
   * specified by the client. It will be honored only if the PROXIABLE
   * flag in the TGT is set. The PROXY option will not be honored on
   * requests for additional ticket-granting tickets.
   *
   * If the requested start time is absent, indicates a time in the past,
   * or is within the window of acceptable clock skew for the KDC and the
   * POSTDATE option has not been specified, then the start time of the
   * ticket is set to the authentication server's current time. If it
   * indicates a time in the future beyond the acceptable clock skew, but
   * the POSTDATED option has not been specified or the MAY-POSTDATE flag
   * is not set in the TGT, then the error KDC_ERR_CANNOT_POSTDATE is
   * returned. Otherwise, if the ticket-granting ticket has the MAY-
   * POSTDATE flag set, then the resulting ticket will be postdated and
   * the requested starttime is checked against the policy of the local
   * realm. If acceptable, the ticket's start time is set as requested,
   * and the INVALID flag is set. The postdated ticket MUST be validated
   * before use by presenting it to the KDC after the starttime has been
   * reached. However, in no case may the starttime, endtime, or renew-
   * till time of a newly-issued postdated ticket extend beyond the renew-
   * till time of the ticket-granting ticket.
   *
   * If the ENC-TKT-IN-SKEY option has been specified and an additional
   * ticket has been included in the request, it indicates that the client
   * is using user- to-user authentication to prove its identity to a
   * server that does not have access to a persistent key. Section 3.7
   * describes the affect of this option on the entire Kerberos protocol.
   * When generating the KRB_TGS_REP message, this option in the
   * KRB_TGS_REQ message tells the KDC to decrypt the additional ticket
   * using the key for the server to which the additional ticket was
   * issued and verify that it is a ticket-granting ticket. If the name of
   * the requested server is missing from the request, the name of the
   * client in the additional ticket will be used. Otherwise the name of
   * the requested server will be compared to the name of the client in
   * the additional ticket and if different, the request will be rejected.
   * If the request succeeds, the session key from the additional ticket
   * will be used to encrypt the new ticket that is issued instead of
   * using the key of the server for which the new ticket will be used.
   *
   * If the name of the server in the ticket that is presented to the KDC
   * as part of the authentication header is not that of the ticket-
   * granting server itself, the server is registered in the realm of the
   * KDC, and the RENEW option is requested, then the KDC will verify that
   * the RENEWABLE flag is set in the ticket, that the INVALID flag is not
   * set in the ticket, and that the renew_till time is still in the
   * future. If the VALIDATE option is requested, the KDC will check that
   * the starttime has passed and the INVALID flag is set. If the PROXY
   * option is requested, then the KDC will check that the PROXIABLE flag
   * is set in the ticket. If the tests succeed, and the ticket passes the
   * hotlist check described in the next section, the KDC will issue the
   * appropriate new ticket.
   */

  /* XXX Set more things in ticket, as described above. */

  rc = shishi_tkt_build (tkt, serverkey);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR, "shishi_tkt_build failed (%d): %s",
	      rc, shishi_strerror (rc));
      goto fatal;
    }

  /*
   * The ciphertext part of the response in the KRB_TGS_REP message is
   * encrypted in the sub-session key from the Authenticator, if present,
   * or the session key from the ticket-granting ticket. It is not
   * encrypted using the client's secret key. Furthermore, the client's
   * key's expiration date and the key version number fields are left out
   * since these values are stored along with the client's database
   * record, and that record is not needed to satisfy a request based on a
   * ticket-granting ticket.
   */

  rc = shishi_encticketpart_get_key
    (handle, shishi_tkt_encticketpart (shishi_ap_tkt (shishi_tgs_ap (tgs))),
     &oldsessionkey);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR, "shishi_encticketpart_get_key failed (%d): %s",
	      rc, shishi_strerror (rc));
      goto fatal;
    }

  rc = shishi_authenticator_get_subkey
    (handle, shishi_ap_authenticator (shishi_tgs_ap (tgs)), &subkey);
  if (rc != SHISHI_OK && rc != SHISHI_ASN1_NO_ELEMENT)
    {
      syslog (LOG_ERR, "shishi_authenticator_get_subkey failed (%d): %s",
	      rc, shishi_strerror (rc));
      goto fatal;
    }

  if (rc == SHISHI_OK)
    rc = shishi_tgs_rep_build
      (tgs, SHISHI_KEYUSAGE_ENCTGSREPPART_AUTHENTICATOR_KEY, subkey);
  else
    rc = shishi_tgs_rep_build
      (tgs, SHISHI_KEYUSAGE_ENCTGSREPPART_SESSION_KEY, oldsessionkey);
  if (rc != SHISHI_OK)
    {
      syslog (LOG_ERR, "shishi_tgs_rep_build failed (%d): %s",
	      rc, shishi_strerror (rc));
      goto fatal;
    }

  if (arg.verbose_given)
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

  rc = SHISHI_OK;

fatal:
  if (tgrealm)
    free (tgrealm);
  if (tgname)
    free (tgname);
  if (servername)
    free (servername);
  if (serverrealm)
    free (serverrealm);
  if (clientname)
    free (clientname);
  if (clientrealm)
    free (clientrealm);
  if (tgkeys)
    shisa_keys_free (dbh, tgkeys, ntgkeys);
  if (serverkeys)
    shisa_keys_free (dbh, serverkeys, nserverkeys);
  if (tgkey)
    shishi_key_done (tgkey);
  if (serverkey)
    shishi_key_done (serverkey);
  if (newsessionkey)
    shishi_key_done (newsessionkey);
  if (oldsessionkey)
    shishi_key_done (oldsessionkey);
  if (subkey)
    shishi_key_done (subkey);

  return rc;
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
      syslog (LOG_ERR, "shishi_tgs failed (%d): %s", rc,
	      shishi_strerror (rc));
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
      syslog (LOG_ERR, "Received %d bytes of unknown data", inlen);
      return -1;
    }

  switch (shishi_asn1_msgtype (handle, node))
    {
    case SHISHI_MSGTYPE_AS_REQ:
      syslog (LOG_ERR, "Trying AS-REQ");
      rc = asreq (node, out, &outlen);
      break;

    case SHISHI_MSGTYPE_TGS_REQ:
      syslog (LOG_ERR, "Trying TGS-REQ");
      rc = tgsreq (node, out, &outlen);
      break;

    case SHISHI_MSGTYPE_AS_REP:
    case SHISHI_MSGTYPE_TGS_REP:
    case SHISHI_MSGTYPE_AP_REQ:
    case SHISHI_MSGTYPE_AP_REP:
    case SHISHI_MSGTYPE_RESERVED16:
    case SHISHI_MSGTYPE_RESERVED17:
    case SHISHI_MSGTYPE_SAFE:
    case SHISHI_MSGTYPE_PRIV:
    case SHISHI_MSGTYPE_CRED:
    case SHISHI_MSGTYPE_ERROR:
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
