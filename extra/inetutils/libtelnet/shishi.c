/* Copyright (C) 2002 Simon Josefsson

   This file is not part of GNU Inetutils, but the same permissions apply.

   GNU Inetutils is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   GNU Inetutils is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with GNU Inetutils; see the file COPYING.  If not, write to
   the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA. */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef SHISHI
#include <stdlib.h>
#include <stdio.h>
#include <arpa/telnet.h>
#include <shishi.h>
#include <assert.h>

#include <netdb.h>
#include <ctype.h>
#include <syslog.h>
#ifdef  HAVE_STRING_H
# include <string.h>
#else
# include <strings.h>
#endif

#include "auth.h"
#include "misc.h"

#ifdef  ENCRYPTION
#include "encrypt.h"
#endif

static unsigned char str_data[2048] = { IAC, SB, TELOPT_AUTHENTICATION, 0,
					AUTHTYPE_KERBEROS_V5, };

#define KRB_AUTH             0       /* Authentication data follows */
#define KRB_REJECT           1       /* Rejected (reason might follow) */
#define KRB_ACCEPT           2       /* Accepted */
#define KRB_RESPONSE         3       /* Response for mutual auth. */

Shishi *shishi_handle = 0;
Shishi_ap *auth_handle;

char *telnet_srvtab = NULL;
char *telnet_krb5_realm = NULL;

#define DEBUG(c) if (auth_debug_mode) printf c

static int
Data (Authenticator *ap, int type, unsigned char *d, int c)
{
  unsigned char *p = str_data + 4;
  unsigned char *cd = (unsigned char *) d;

  if (c == -1)
    c = strlen (cd);

  if (auth_debug_mode)
    {
      printf ("%s:%d: [%d] (%d)",
	      str_data[3] == TELQUAL_IS ? ">>>IS" : ">>>REPLY",
	      str_data[3],
	      type, c);
      printd (d, c);
      printf ("\r\n");
    }

  *p++ = ap->type;
  *p++ = ap->way;
  *p++ = type;

  while (c-- > 0) {
    if ((*p++ = *cd++) == IAC)
      *p++ = IAC;
  }
  *p++ = IAC;
  *p++ = SE;
  if (str_data[3] == TELQUAL_IS)
    printsub ('>', &str_data[2], p - &str_data[2]);
  return (net_write (str_data, p - str_data));
}

/* FIXME: Reverse return code! */
int
krb5shishi_init (Authenticator *ap, int server)
{
  str_data[3] = server ? TELQUAL_REPLY : TELQUAL_IS;
  if (shishi_handle == 0 && shishi_init(&shishi_handle))
    return 0;
  return 1;
}

void
krb5shishi_cleanup ()
{
  if (shishi_handle == 0)
    return;

  shishi_done(shishi_handle);
  shishi_handle = 0;
}

#ifdef  FOOOOOOOOOENCRYPTION

void
encryption_init (krb5_creds *creds)
{
  krb5_keyblock *newkey = 0;
  
  krb5_auth_con_getlocalsubkey (telnet_context, auth_context, &newkey);
  if (session_key)
    {
      krb5_free_keyblock (telnet_context, session_key);
      session_key = 0;
    }

  if (newkey)
    {
      switch (newkey->enctype)
	{
	case ENCTYPE_DES_CBC_CRC:
	case ENCTYPE_DES_CBC_MD5:
	  krb5_copy_keyblock (telnet_context, newkey, &session_key);
	  break;

	default:
	  switch (creds->keyblock.enctype)
	    {
	    case ENCTYPE_DES_CBC_CRC:
	    case ENCTYPE_DES_CBC_MD5:
	      krb5_copy_keyblock (telnet_context, &creds->keyblock,
				  &session_key);
	      break;

	    default:
	      DEBUG(("can't determine which keyblock to use"));
	      /*FIXME: abort?*/
	    }
	}

      krb5_free_keyblock(telnet_context, newkey);
    }
}

#else
# define encryption_init(c)
#endif

int
krb5shishi_send (Authenticator *ap)
{
  int ap_opts;
  char type_check[2];
  Shishi_ticket *tkt;
  int rc;
  char *tmp;
  char apreq[4096];
  int apreq_len;

  tmp = malloc(strlen("host/") + strlen(RemoteHostName) + 1);
  sprintf(tmp, "host/%s", RemoteHostName);
  tkt = shishi_ticketset_find_ticket_for_server
    (shishi_handle, NULL, tmp);
  free(tmp);
  if (!tkt)
    {
      DEBUG(("telnet: Kerberos V5: no shishi ticket for server\r\n"));
      return 0;
    }

  if (!UserNameRequested)
    {
      DEBUG(("telnet: Kerberos V5: no user name supplied\r\n"));
      return 0;
    }

  // creds.keyblock.enctype = ENCTYPE_DES_CBC_CRC;

  if ((ap->way & AUTH_HOW_MASK) == AUTH_HOW_MUTUAL)
    ap_opts = SHISHI_APOPTIONS_MUTUAL_REQUIRED;
  else
    ap_opts = 0;

#if 0
  // ENCRYPTION
  ap_opts |= SHISHI_APOPTIONS_USE_SESSION_KEY;
#endif 

  //krb5_auth_con_setflags (telnet_context, auth_context,
  // KRB5_AUTH_CONTEXT_RET_TIME);

  type_check[0] = ap->type;
  type_check[1] = ap->way;

  if (tkt)
    {
      rc = shishi_ap_data (shishi_handle, tkt, (char *) &type_check, 2, 
			   &auth_handle);
      if (rc != SHISHI_OK)
	{
	  DEBUG(("telnet: Kerberos V5: Could not make AP-REQ (%s)\r\n",
		 shishi_strerror (rc)));
	  return 0;
	}

      rc = shishi_apreq_options_add (shishi_handle, 
				     shishi_ap_get_apreq (auth_handle), 
				     ap_opts);
      if (rc != SHISHI_OK)
	{
	  DEBUG(("telnet: Kerberos V5: could not set AP-Options (%s)\r\n",
		 shishi_strerror (rc)));
	  return 0;
	}

      if (auth_debug_mode)
	{
	  shishi_authenticator_print
	    (shishi_handle, stdout, shishi_ap_get_authenticator (auth_handle));
	  shishi_apreq_print (shishi_handle, stdout, 
			      shishi_ap_get_apreq (auth_handle));
	}

      apreq_len = sizeof(apreq);
      rc = shishi_ap_request_get_der (shishi_handle, auth_handle, 
				      apreq, &apreq_len);
      if (rc != ASN1_SUCCESS)
	{
	  DEBUG(("telnet: Kerberos V5: could not DER encode (%s)\r\n",
		 shishi_strerror (rc)));
	  return 0;
	}
     }

  //encryption_init (new_creds);

  if (!auth_sendname (UserNameRequested, strlen (UserNameRequested)))
    {
      DEBUG(("telnet: Not enough room for user name\r\n"));
      return 0;
    }

  if (!Data (ap, KRB_AUTH, apreq, apreq_len))
    {
      DEBUG(("telnet: Not enough room for authentication data\r\n"));
      return 0;
    }

  DEBUG(("telnet: Sent Kerberos V5 credentials to server\r\n"));

  return 1;
}

#ifdef FOOOOOOOOOENCRYPTION
void
telnet_encrypt_key (Session_Key *skey)
{
  if (session_key)
    {
      skey->type = SK_DES;
      skey->length = 8;
      skey->data = session_key->contents;
      encrypt_session_key (skey, 0);
    }
}
#else
# define telnet_encrypt_key(s)
#endif

void
krb5shishi_reply (Authenticator *ap, unsigned char *data, int cnt)
{
#ifdef ENCRYPTION
  Session_Key skey;
#endif
  static int mutual_complete = 0;

  if (cnt-- < 1)
    return;
  
  switch (*data++)
    {
    case KRB_REJECT:
      if (cnt > 0) 
	printf ("[ Kerberos V5 refuses authentication because %.*s ]\r\n",
	       cnt, data);
      else
	printf ("[ Kerberos V5 refuses authentication ]\r\n");
      auth_send_retry();
      return;

    case KRB_ACCEPT:
      if (!mutual_complete)
	{
	  if ((ap->way & AUTH_HOW_MASK) == AUTH_HOW_MUTUAL)
	    {
	      printf ("[ Kerberos V5 accepted you, but didn't provide mutual authentication! ]\r\n");
	      auth_send_retry ();
	      break;
	    }
	}

      if (cnt)
	printf ("[ Kerberos V5 accepts you as ``%.*s''%s ]\r\n", cnt, data,
		mutual_complete ?
		" (server authenticated)" : 
		" (server NOT authenticated)");
      else
	printf ("[ Kerberos V5 accepts you ]\r\n");
      auth_finished(ap, AUTH_USER);
      break;

    case KRB_RESPONSE:
      if ((ap->way & AUTH_HOW_MASK) == AUTH_HOW_MUTUAL)
	{
	  if (shishi_ap_reply_verify_der (shishi_handle, auth_handle, 
					  data, cnt) != SHISHI_OK)
	    {
	      printf ("[ Mutual authentication failed ]\r\n");
	      auth_send_retry ();
	      break;
	    }

	  if (auth_debug_mode)
	    {
	      shishi_aprep_print (shishi_handle, stdout, 
				  shishi_ap_get_aprep (auth_handle));
	      shishi_encapreppart_print (shishi_handle, stdout, 
					 shishi_ap_get_encapreppart
					 (auth_handle));
	    }

#ifdef ENCRYPTION
	  //telnet_encrypt_key (&skey);
#endif
	  mutual_complete = 1;
	}
      break;

    default:
      DEBUG(("Unknown Kerberos option %d\r\n", data[-1]));
    }
}

int
krb5shishi_status (Authenticator *ap, char *name, int level)
{
  puts("krb5shishi_status");

  if (level < AUTH_USER)
    return level;

#if 0
  if (UserNameRequested
      && krb5_kuserok (telnet_context, ticket->enc_part2->client,
		       UserNameRequested))
    {
      /* FIXME: Check buffer length */
      strcpy (name, UserNameRequested);
      return AUTH_VALID;
    } 
#endif

  return AUTH_USER;
}

int
krb5shishi_is_auth (Authenticator *ap, unsigned char *data, int cnt,
		    char *errbuf, int errbuflen)
{
#if 0
  int r = 0;
  krb5_keytab keytabid = 0;
  krb5_authenticator *authenticator;
  char *name;
  krb5_data outbuf;
  krb5_keyblock *newkey = NULL;
  krb5_principal server;
  
#ifdef ENCRYPTION
  Session_Key skey;
#endif
  
  puts("krb5shishi_is_auth");

  auth.data = (char *)data;
  auth.length = cnt;

  if (!r && !auth_context)
    r = krb5_auth_con_init (telnet_context, &auth_context);
  if (!r)
    {
      krb5_rcache rcache;
    
      r = krb5_auth_con_getrcache (telnet_context, auth_context,
				   &rcache);
      if (!r && !rcache)
	{
	  r = krb5_sname_to_principal(telnet_context, 0, 0,
				      KRB5_NT_SRV_HST, &server);
	  if (!r)
	    {
	      r = krb5_get_server_rcache(telnet_context,
					 krb5_princ_component (telnet_context,
							       server, 0),
					 &rcache);
	      krb5_free_principal (telnet_context, server);
	    }
	}
      if (!r)
	r = krb5_auth_con_setrcache (telnet_context,
				     auth_context, rcache);
    }
  
  if (!r && telnet_srvtab)
    r = krb5_kt_resolve (telnet_context, telnet_srvtab, &keytabid);
  if (!r)
    r = krb5_rd_req (telnet_context, &auth_context, &auth,
		     NULL, keytabid, NULL, &ticket);
  if (r)
    {
      snprintf (errbuf, errbuflen, "krb5_rd_req failed: %s",
		error_message (r));
      return r;
    }

  /* 256 bytes should be much larger than any reasonable
     first component of a service name especially since
     the default is of length 4. */
  if (krb5_princ_component (telnet_context,ticket->server,0)->length < 256)
    {
      char princ[256];
      strncpy (princ,
	       krb5_princ_component (telnet_context, ticket->server,0)->data,
	       krb5_princ_component (telnet_context, ticket->server,0)->length);
      princ[krb5_princ_component (telnet_context,
				  ticket->server,0)->length] = '\0';
      if (strcmp ("host", princ))
	{
	  snprintf(errbuf, errbuflen,
		   "incorrect service name: \"%s\" != \"host\"",
		   princ);
	  return 1;
	}
    }
  else
    {
      strncpy (errbuf, "service name too long", errbuflen);
      return 1;
    }

  r = krb5_auth_con_getauthenticator (telnet_context,
				      auth_context,
				      &authenticator);
  if (r)
    {
      snprintf (errbuf, errbuflen,
		"krb5_auth_con_getauthenticator failed: %s",
		error_message (r));
      return 1;
    }

#ifdef AUTH_ENCRYPT_MASK
  if ((ap->way & AUTH_ENCRYPT_MASK) == AUTH_ENCRYPT_ON
      &&  !authenticator->checksum)
    {
      snprintf (errbuf, errbuflen,
		"authenticator is missing required checksum");
      return 1;
    }
#endif
  
  if (authenticator->checksum)
    {
      char type_check[2];
      krb5_checksum *cksum = authenticator->checksum;
      krb5_keyblock *key;

      type_check[0] = ap->type;
      type_check[1] = ap->way;

      r = krb5_auth_con_getkey (telnet_context, auth_context,
				&key);
      if (r)
	{
	  snprintf (errbuf, errbuflen,
		    "krb5_auth_con_getkey failed: %s",
		    error_message (r));
	  return 1;
	}
      
      r = krb5_verify_checksum (telnet_context,
				cksum->checksum_type, cksum,
				&type_check, 2, key->contents,
				key->length);
      
      if (r)
	{
	  snprintf (errbuf, errbuflen, 
		    "checksum verification failed: %s",
		    error_message (r));
	  return 1;
	}
      krb5_free_keyblock (telnet_context, key);
    }
  
  krb5_free_authenticator (telnet_context, authenticator);
  if ((ap->way & AUTH_HOW_MASK) == AUTH_HOW_MUTUAL)
    {
      if ((r = krb5_mk_rep (telnet_context, auth_context,
			    &outbuf)))
	{
	  snprintf (errbuf, errbuflen, "Make reply failed: %s",
		    error_message(r));
	  return 1;
	}

      Data (ap, KRB_RESPONSE, outbuf.data, outbuf.length);
    }
  
  if (krb5_unparse_name (telnet_context, ticket->enc_part2 ->client, &name))
    name = 0;
  
  Data (ap, KRB_ACCEPT, name, name ? -1 : 0);
  DEBUG(("telnetd: Kerberos5 identifies him as ``%s''\r\n",
	 name ? name : ""));
  auth_finished (ap, AUTH_USER);

  if (name)
    free (name);
  krb5_auth_con_getremotesubkey (telnet_context, auth_context, &newkey);
  
  if (session_key)
    {
      krb5_free_keyblock (telnet_context, session_key);
      session_key = 0;
    }
  
  if (newkey)
    {
      krb5_copy_keyblock (telnet_context, newkey, &session_key);
      krb5_free_keyblock (telnet_context, newkey);
    }
  else
    {
      krb5_copy_keyblock (telnet_context, ticket->enc_part2->session,
			  &session_key);
    }
  telnet_encrypt_key (&skey);
#endif
  return 0;
}
    
void
krb5shishi_is (Authenticator *ap, unsigned char *data, int cnt)
{
  int r = 0;
  char errbuf[512];
    
  puts("krb5shishi_is");

  if (cnt-- < 1)
    return;
  errbuf[0] = 0;
  switch (*data++)
    {
    case KRB_AUTH:
      r = krb5shishi_is_auth (ap, data, cnt, errbuf, sizeof errbuf);
      break;

    default:
      DEBUG(("Unknown Kerberos option %d\r\n",
	     data[-1]));
      Data(ap, KRB_REJECT, 0, 0);
      break;
    }

  if (r)
    {
      if (!errbuf[0])
	snprintf (errbuf, sizeof errbuf,
		  "kerberos_is: error");
      Data (ap, KRB_REJECT, errbuf, -1);
      DEBUG(("%s\r\n", errbuf));
      syslog (LOG_ERR, "%s", errbuf);
    }
}
    
static char *
req_type_str (int type)
{
  switch (type)
    {
    case KRB_REJECT:
      return "REJECT";
      
    case KRB_ACCEPT:
      return "ACCEPT";

    case KRB_AUTH:
      return "AUTH";

    case KRB_RESPONSE:
      return "RESPONSE";

    }
  return NULL;
}
     
#define ADDC(p,l,c) if ((l) > 0) {*(p)++ = (c); --(l);}

void
krb5shishi_printsub (unsigned char *data, int cnt,
		     unsigned char *buf,  int buflen)
{
  char *p;
  int i;

  puts("krb5shishi_printsub");

  buf[buflen-1] = '\0';           /* make sure its NULL terminated */
  buflen -= 1;

  p = req_type_str (data[3]);
  if (!p)
    {
      int l = snprintf (buf, buflen, " %d (unknown)", data[3]);
      buf += l;
      buflen -= l;
    }
  else
    {
      while (buflen > 0 && (*buf++ = *p++) != 0)
	buflen--;
    }
      
  switch (data[3])
    {
    case KRB_REJECT:  /* Rejected (reason might follow) */
    case KRB_ACCEPT:  /* Accepted (username might follow) */
      if (cnt <= 4)
	break;
      ADDC(buf, buflen, '"');
      for (i = 4; i < cnt; i++)
	ADDC(buf, buflen, data[i]);
      ADDC(buf, buflen, '"');
      ADDC(buf, buflen, '\0');
      break;

    case KRB_AUTH:
    case KRB_RESPONSE:
      for (i = 4; buflen > 0 && i < cnt; i++)
	{
	  int l = snprintf (buf, buflen, " %d", data[i]);
	  buf += l;
	  buflen -= l;
      }
    }
}
     
#endif /* SHISHI */
