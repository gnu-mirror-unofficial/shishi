/* internal.h	internal header file for shishi
 * Copyright (C) 2002  Simon Josefsson
 *
 * This file is part of shishi.
 *
 * Shishi is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * Shishi is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with shishi; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifndef _INTERNAL_H
#define _INTERNAL_H

#if HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef STDC_HEADERS
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#endif

#include <unistd.h>
#include <ctype.h>

#include <netdb.h>
extern int h_errno;
#include <pwd.h>
#include <sys/types.h>

#include <sys/select.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <errno.h>

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

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

#include "libtasn1.h"

#include "gettext.h"
#include "shishi.h"

#ifdef ENABLE_NLS
extern char *_shishi_gettext (const char *str);
#define _(String) _shishi_gettext (String)
#define _N(S1, S2, N) ngettext (S1, S2, N)
#define gettext_noop(String) String
#define N_(String) gettext_noop (String)
#endif

typedef enum {
  /* 1. AS-REQ PA-ENC-TIMESTAMP padata timestamp, encrypted with the
     client key */
  SHISHI_KEYUSAGE_ASREQ_PA_ENC_TIMESTAMP = 1,
  /* 2. AS-REP Ticket and TGS-REP Ticket (includes TGS session key or 
     application session key), encrypted with the service key  */
  SHISHI_KEYUSAGE_ASREP_TICKET = 2,
  /* 3. AS-REP encrypted part (includes TGS session key or application
     session key), encrypted with the client key */
  SHISHI_KEYUSAGE_ENCASREPPART = 3,
  /* 4. TGS-REQ KDC-REQ-BODY AuthorizationData, encrypted with the TGS
     session key  */
  SHISHI_KEYUSAGE_TGSREQ_AUTHORIZATIONDATA_TGS_SESSION_KEY = 4,
  /* 5. TGS-REQ KDC-REQ-BODY AuthorizationData, encrypted with the TGS
     authenticator subkey (section 5.4.1) */
  SHISHI_KEYUSAGE_TGSREQ_AUTHORIZATIONDATA_TGS_AUTHENTICATOR_KEY = 5,
  /* 6. TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator cksum, keyed with the
     TGS session key  */
  SHISHI_KEYUSAGE_TGSREQ_APREQ_AUTHENTICATOR_CKSUM = 6,
  /* 7. TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator (includes TGS
     authenticator subkey), encrypted with the TGS session key */
  SHISHI_KEYUSAGE_TGSREQ_APREQ_AUTHENTICATOR = 7,
  /* 8. TGS-REP encrypted part (includes application session key), encrypted
     with the TGS session key */
  SHISHI_KEYUSAGE_ENCTGSREPPART_SESSION_KEY = 8,
  /* 9. TGS-REP encrypted part (includes application session key), encrypted
     with the TGS authenticator subkey */
  SHISHI_KEYUSAGE_ENCTGSREPPART_AUTHENTICATOR_KEY = 9,
  /* 10. AP-REQ Authenticator cksum, keyed with the application
     session key */
  SHISHI_KEYUSAGE_APREQ_AUTHENTICATOR_CKSUM = 10,
  /* 11. AP-REQ Authenticator (includes application authenticator subkey),
     encrypted with the application session key */
  SHISHI_KEYUSAGE_APREQ_AUTHENTICATOR = 11,
  /* 12. AP-REP encrypted part (includes application session subkey),
     encrypted with the application session key */
  SHISHI_KEYUSAGE_ENCAPREPPART = 12,
  /* 13. KRB-PRIV encrypted part, encrypted with a key chosen by the
     application */
  SHISHI_KEYUSAGE_KRB_PRIV = 13,
  /* 14. KRB-CRED encrypted part, encrypted with a key chosen by the
     application */
  SHISHI_KEYUSAGE_KRB_CRED = 14,
  /* 15. KRB-SAFE cksum, keyed with a key chosen by the application */
  SHISHI_KEYUSAGE_KRB_SAFE = 15,
  /* 18. KRB-ERROR checksum (e-cksum) */
  SHISHI_KEYUSAGE_KRB_ERROR = 18,
  /* 19. AD-KDCIssued checksum (ad-checksum) */
  SHISHI_KEYUSAGE_AD_KDCISSUED = 19,
  /* 20. Checksum for Mandatory Ticket Extensions */
  SHISHI_KEYUSAGE_TICKET_EXTENSION = 20,
  /* 21. Checksum in Authorization Data in Ticket Extensions */
  SHISHI_KEYUSAGE_TICKET_EXTENSION_AUTHORIZATION = 21,
  /* 22-24. Reserved for use in GSSAPI mechanisms derived from RFC 1964.
     (raeburn/MIT) */
  /* 25-511. Reserved for future use in Kerberos and related protocols. */
  /* 512-1023. Reserved for uses internal to a Kerberos implementation. */
} Shishi_keyusage;

#define GENERALIZEDTIME_TIME_LEN 15

struct Shishi_ticket
{
  char *principal;
  ASN1_TYPE ticket;
  ASN1_TYPE enckdcreppart;
};

struct Shishi_ticketset
{
  Shishi_ticket **tickets;
  int ntickets;
};

struct Shishi_kdcinfo
{
  char *name;
  struct sockaddr sockaddress;
};

struct Shishi_realminfo
{
  char *name;
  struct Shishi_kdcinfo *kdcaddresses;
  int nkdcaddresses;
};

#define SHISHI_DEBUG_CRYPTO (1<<1)
#define SHISHI_DEBUG_ASN1   (1<<2)

#define KRBTGT "krbtgt"
#define PRINCIPAL_DELIMITER "/"

#define DEBUGASN1(h) (h->debugmask & SHISHI_DEBUG_ASN1)
#define DEBUGCRYPTO(h) (h->debugmask & SHISHI_DEBUG_CRYPTO)
#define DEBUG(h) (h->debugmask & ~SHISHI_DEBUG_ASN1 & ~SHISHI_DEBUG_CRYPTO)

#define SILENT(h) (h->silent)

struct Shishi_as
{
  ASN1_TYPE asreq;
  ASN1_TYPE asrep;
  Shishi_ticket * ticket;
};

struct Shishi_tgs
{
  ASN1_TYPE tgsreq;
  Shishi_ticket * tgticket;
  ASN1_TYPE authenticator;
  ASN1_TYPE apreq;
  ASN1_TYPE tgsrep;
  Shishi_ticket * ticket;
};

struct Shishi
{
  ASN1_TYPE asn1;
  int debugmask;
  int silent;
  char *default_realm;
  char *default_principal;
  int kdctimeout;
  int kdcretries;
  int *clientkdcetypes;
  int nclientkdcetypes;
  struct Shishi_realminfo *realminfos;
  int nrealminfos;
  char *kdc;
  char error[1024];
  char *gztime_buf[40];
  int shortnonceworkaround;
  ASN1_TYPE lastauthenticator;
  ASN1_TYPE lastapreq;
  ASN1_TYPE lastaprep;
  ASN1_TYPE lastencapreppart;
};

/* asn1.c */
int
_shishi_asn1_field (Shishi * handle,
		    ASN1_TYPE node, char *data, int *datalen, char *field);
int
_shishi_asn1_optional_field (Shishi * handle,
			     ASN1_TYPE node,
			     char *data, int *datalen, char *field);
extern ASN1_TYPE
shishi_der2asn1_ticket (ASN1_TYPE definitions,
			char *der, int der_len, char *errorDescription);

int
shishi_format_principal_name (Shishi * handle,
			      ASN1_TYPE namenode,
			      char *namefield,
			      ASN1_TYPE realmnode,
			      char *realmfield, char *out, int *outlen);

ASN1_TYPE
shishi_der2asn1_authenticator (ASN1_TYPE definitions,
			       char *der,
			       int der_len, char *errorDescription);
int
_shishi_print_armored_data (Shishi * handle,
			    FILE * fh,
			    ASN1_TYPE asn1, char *asn1type, char *headers);
int
_shishi_save_data (Shishi * handle, FILE * fh, ASN1_TYPE asn1,
		   char *asn1type);

int
_shishi_authenticator_input (Shishi * handle,
			     FILE * fh, ASN1_TYPE * authenticator, int type);

int
_shishi_apreq_input (Shishi * handle, FILE * fh, ASN1_TYPE * apreq, int type);
int
_shishi_kdcreq_input (Shishi * handle,
		      FILE * fh, ASN1_TYPE * asreq, int type);
int
_shishi_kdcrep_input (Shishi * handle,
		      FILE * fh, ASN1_TYPE * asrep, int type);

#endif /* _INTERNAL_H */
