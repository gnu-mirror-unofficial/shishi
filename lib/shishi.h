/* shishi.h --- Header file for Shishi library.                       -*- c -*-
 * Copyright (C) 2002, 2003, 2004, 2006, 2007, 2008, 2009  Simon Josefsson
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

#ifndef SHISHI_H
#define SHISHI_H

#include <stddef.h>		/* size_t */
#include <stdio.h>		/* FILE */
#include <stdarg.h>		/* va_list */
#include <time.h>		/* time_t */
#include <shishi-int.h>		/* uint32_t */

#define SHISHI_VERSION "0.0.39"

# ifdef __cplusplus
extern "C" {
# endif

#ifndef __attribute__
/* This feature is available in gcc versions 2.5 and later.  */
# if __GNUC__ < 2 || (__GNUC__ == 2 && __GNUC_MINOR__ < 5)
#  define __attribute__(Spec)	/* empty */
# endif
#endif

/* Error codes */
typedef enum
{
  SHISHI_OK = 0,
  SHISHI_ASN1_ERROR = 1,
  SHISHI_FOPEN_ERROR = 2,
  SHISHI_IO_ERROR = 3,
  SHISHI_MALLOC_ERROR = 4,
  SHISHI_BASE64_ERROR = 5,
  SHISHI_REALM_MISMATCH = 6,
  SHISHI_CNAME_MISMATCH = 7,
  SHISHI_NONCE_MISMATCH = 8,
  SHISHI_TGSREP_BAD_KEYTYPE = 9,
  SHISHI_KDCREP_BAD_KEYTYPE = 10,
  SHISHI_APREP_BAD_KEYTYPE = 11,
  SHISHI_APREP_VERIFY_FAILED = 12,
  SHISHI_APREQ_BAD_KEYTYPE = 13,
  SHISHI_TOO_SMALL_BUFFER = 14,
  SHISHI_DERIVEDKEY_TOO_SMALL = 15,
  SHISHI_KEY_TOO_LARGE = 16,
  SHISHI_CRYPTO_ERROR = 17,
  SHISHI_CRYPTO_INTERNAL_ERROR = 18,
  SHISHI_SOCKET_ERROR = 19,
  SHISHI_BIND_ERROR = 20,
  SHISHI_SENDTO_ERROR = 21,
  SHISHI_RECVFROM_ERROR = 22,
  SHISHI_CLOSE_ERROR = 23,
  SHISHI_KDC_TIMEOUT = 24,
  SHISHI_KDC_NOT_KNOWN_FOR_REALM = 25,
  SHISHI_TTY_ERROR = 26,
  SHISHI_GOT_KRBERROR = 27,
  SHISHI_HANDLE_ERROR = 28,
  SHISHI_INVALID_TKTS = 29,
  SHISHI_TICKET_BAD_KEYTYPE = 30,
  SHISHI_INVALID_KEY = 31,
  SHISHI_APREQ_DECRYPT_FAILED = 32,
  SHISHI_TICKET_DECRYPT_FAILED = 33,
  SHISHI_INVALID_TICKET = 34,
  SHISHI_OUT_OF_RANGE = 35,
  SHISHI_ASN1_NO_ELEMENT = 36,
  SHISHI_SAFE_BAD_KEYTYPE = 37,
  SHISHI_SAFE_VERIFY_FAILED = 38,
  SHISHI_PKCS5_INVALID_PRF = 39,
  SHISHI_PKCS5_INVALID_ITERATION_COUNT = 40,
  SHISHI_PKCS5_INVALID_DERIVED_KEY_LENGTH = 41,
  SHISHI_PKCS5_DERIVED_KEY_TOO_LONG = 42,
  SHISHI_INVALID_PRINCIPAL_NAME = 43,
  SHISHI_INVALID_ARGUMENT = 44,
  SHISHI_ASN1_NO_VALUE = 45,
  SHISHI_CONNECT_ERROR = 46,
  SHISHI_VERIFY_FAILED = 47,
  SHISHI_PRIV_BAD_KEYTYPE = 48,
  SHISHI_FILE_ERROR = 49,
  SHISHI_ENCAPREPPART_BAD_KEYTYPE = 50,
  SHISHI_GETTIMEOFDAY_ERROR = 51,
  SHISHI_KEYTAB_ERROR = 52,
  SHISHI_CCACHE_ERROR = 53,
  SHISHI_LAST_ERROR = 53
}
Shishi_rc;

typedef enum
{
  /* Name type not known */
  SHISHI_NT_UNKNOWN = 0,
  /* Just the name of the principal as in DCE, or for users */
  SHISHI_NT_PRINCIPAL = 1,
  /* Service and other unique instance (krbtgt) */
  SHISHI_NT_SRV_INST = 2,
  /* Service with host name as instance (telnet, rcommands) */
  SHISHI_NT_SRV_HST = 3,
  /* Service with host as remaining components */
  SHISHI_NT_SRV_XHST = 4,
  /* Unique ID */
  SHISHI_NT_UID = 5,
  /* Encoded X.509 Distingished name [RFC 2253] */
  SHISHI_NT_X500_PRINCIPAL = 6,
  /* Name in form of SMTP email name (e.g. user@foo.com) */
  SHISHI_NT_SMTP_NAME = 7,
  /*  Enterprise name - may be mapped to principal name */
  SHISHI_NT_ENTERPRISE = 10
}
Shishi_name_type;

typedef enum
{
  SHISHI_PA_TGS_REQ = 1,
  SHISHI_PA_ENC_TIMESTAMP = 2,
  SHISHI_PA_PW_SALT = 3,
  SHISHI_PA_RESERVED = 4,
  SHISHI_PA_ENC_UNIX_TIME = 5,	/* (deprecated) */
  SHISHI_PA_SANDIA_SECUREID = 6,
  SHISHI_PA_SESAME = 7,
  SHISHI_PA_OSF_DCE = 8,
  SHISHI_PA_CYBERSAFE_SECUREID = 9,
  SHISHI_PA_AFS3_SALT = 10,
  SHISHI_PA_ETYPE_INFO = 11,
  SHISHI_PA_SAM_CHALLENGE = 12,	/* (sam/otp) */
  SHISHI_PA_SAM_RESPONSE = 13,	/* (sam/otp) */
  SHISHI_PA_PK_AS_REQ = 14,	/* (pkinit) */
  SHISHI_PA_PK_AS_REP = 15,	/* (pkinit) */
  SHISHI_PA_ETYPE_INFO2 = 19,	/* (replaces pa_etype_info) */
  SHISHI_PA_USE_SPECIFIED_KVNO = 20,
  SHISHI_PA_SAM_REDIRECT = 21,	/* (sam/otp) */
  SHISHI_PA_GET_FROM_TYPED_DATA = 22,	/* (embedded in typed data) */
  SHISHI_TD_PADATA = 22,	/* (embeds padata) */
  SHISHI_PA_SAM_ETYPE_INFO = 23,	/* (sam/otp) */
  SHISHI_PA_ALT_PRINC = 24,	/* (crawdad@fnal.gov) */
  SHISHI_PA_SAM_CHALLENGE2 = 30,	/* (kenh@pobox.com) */
  SHISHI_PA_SAM_RESPONSE2 = 31,	/* (kenh@pobox.com) */
  SHISHI_PA_EXTRA_TGT = 41,	/* Reserved extra TGT */
  SHISHI_TD_PKINIT_CMS_CERTIFICATES = 101,	/* CertificateSet from CMS */
  SHISHI_TD_KRB_PRINCIPAL = 102,	/* PrincipalName */
  SHISHI_TD_KRB_REALM = 103,	/* Realm */
  SHISHI_TD_TRUSTED_CERTIFIERS = 104,	/* from PKINIT */
  SHISHI_TD_CERTIFICATE_INDEX = 105,	/* from PKINIT */
  SHISHI_TD_APP_DEFINED_ERROR = 106,	/* application specific */
  SHISHI_TD_REQ_NONCE = 107,	/* INTEGER */
  SHISHI_TD_REQ_SEQ = 108,	/* INTEGER */
  SHISHI_PA_PAC_REQUEST = 128	/* (jbrezak@exchange.microsoft.com) */
}
Shishi_padata_type;

typedef enum
{
  SHISHI_TR_DOMAIN_X500_COMPRESS = 1
}
Shishi_tr_type;

typedef enum
{
  SHISHI_APOPTIONS_RESERVED = 0x1,	/* bit 0 */
  SHISHI_APOPTIONS_USE_SESSION_KEY = 0x2,	/* bit 1 */
  SHISHI_APOPTIONS_MUTUAL_REQUIRED = 0x4	/* bit 2 */
}
Shishi_apoptions;

typedef enum
{
  SHISHI_TICKETFLAGS_RESERVED = 0x1,	/* bit 0 */
  SHISHI_TICKETFLAGS_FORWARDABLE = 0x2,	/* bit 1 */
  SHISHI_TICKETFLAGS_FORWARDED = 0x4,	/* bit 2 */
  SHISHI_TICKETFLAGS_PROXIABLE = 0x8,	/* bit 3 */
  SHISHI_TICKETFLAGS_PROXY = 0x10,	/* bit 4 */
  SHISHI_TICKETFLAGS_MAY_POSTDATE = 0x20,	/* bit 5 */
  SHISHI_TICKETFLAGS_POSTDATED = 0x40,	/* bit 6 */
  SHISHI_TICKETFLAGS_INVALID = 0x80,	/* bit 7 */
  SHISHI_TICKETFLAGS_RENEWABLE = 0x100,	/* bit 8 */
  SHISHI_TICKETFLAGS_INITIAL = 0x200,	/* bit 9 */
  SHISHI_TICKETFLAGS_PRE_AUTHENT = 0x400,	/* bit 10 */
  SHISHI_TICKETFLAGS_HW_AUTHENT = 0x800,	/* bit 11 */
  SHISHI_TICKETFLAGS_TRANSITED_POLICY_CHECKED = 0x1000,	/* bit 12 */
  SHISHI_TICKETFLAGS_OK_AS_DELEGATE = 0x2000	/* bit 13 */
}
Shishi_ticketflags;

typedef enum
{
  SHISHI_KDCOPTIONS_RESERVED = 0x1,	/* bit 0 */
  SHISHI_KDCOPTIONS_FORWARDABLE = 0x2,	/* bit 1 */
  SHISHI_KDCOPTIONS_FORWARDED = 0x4,	/* bit 2 */
  SHISHI_KDCOPTIONS_PROXIABLE = 0x8,	/* bit 3 */
  SHISHI_KDCOPTIONS_PROXY = 0x10,	/* bit 4 */
  SHISHI_KDCOPTIONS_ALLOW_POSTDATE = 0x20,	/* bit 5 */
  SHISHI_KDCOPTIONS_POSTDATED = 0x40,	/* bit 6 */
  SHISHI_KDCOPTIONS_UNUSED7 = 0x80,	/* bit 7 */
  SHISHI_KDCOPTIONS_RENEWABLE = 0x100,	/* bit 8 */
  SHISHI_KDCOPTIONS_UNUSED9 = 0x200,	/* bit 9 */
  SHISHI_KDCOPTIONS_UNUSED10 = 0x400,	/* bit 10 */
  SHISHI_KDCOPTIONS_UNUSED11 = 0x800	/* bit 11 */
#define SHISHI_KDCOPTIONS_DISABLE_TRANSITED_CHECK 0x4000000	/* bit 26 */
#define SHISHI_KDCOPTIONS_RENEWABLE_OK		  0x8000000	/* bit 27 */
#define SHISHI_KDCOPTIONS_ENC_TKT_IN_SKEY	  0x10000000	/* bit 28 */
#define SHISHI_KDCOPTIONS_RENEW			  0x40000000	/* bit 30 */
#define SHISHI_KDCOPTIONS_VALIDATE		  0x80000000	/* bit 31 */
}
Shishi_KDCOptions;

typedef enum
{
  /* 0                             unused */
  /* 1              Ticket         PDU */
  /* 2              Authenticator  non-PDU */
  /* 3              EncTicketPart  non-PDU */
  /* 4-9                           unused */
  /* Request for initial authentication */
  SHISHI_MSGTYPE_AS_REQ = 10,
  /* Response to SHISHI_MSGTYPE_AS_REQ request */
  SHISHI_MSGTYPE_AS_REP = 11,
  /* Request for authentication based on TGT */
  SHISHI_MSGTYPE_TGS_REQ = 12,
  /* Response to SHISHI_MSGTYPE_TGS_REQ request */
  SHISHI_MSGTYPE_TGS_REP = 13,
  /* application request to server */
  SHISHI_MSGTYPE_AP_REQ = 14,
  /* Response to SHISHI_MSGTYPE_AP_REQ_MUTUAL */
  SHISHI_MSGTYPE_AP_REP = 15,
  /* Reserved for user-to-user krb_tgt_request */
  SHISHI_MSGTYPE_RESERVED16 = 16,
  /* Reserved for user-to-user krb_tgt_reply */
  SHISHI_MSGTYPE_RESERVED17 = 17,
  /* 18-19                         unused */
  /* Safe (checksummed) application message */
  SHISHI_MSGTYPE_SAFE = 20,
  /* Private (encrypted) application message */
  SHISHI_MSGTYPE_PRIV = 21,
  /* Private (encrypted) message to forward credentials */
  SHISHI_MSGTYPE_CRED = 22,
  /* 23-24                         unused */
  /* 25             EncASRepPart   non-PDU */
  /* 26             EncTGSRepPart  non-PDU */
  /* 27             EncApRepPart   non-PDU */
  /* 28             EncKrbPrivPart non-PDU */
  /* 29             EncKrbCredPart non-PDU */
  /* Error response */
  SHISHI_MSGTYPE_ERROR = 30
}
Shishi_msgtype;

typedef enum
{
  SHISHI_LRTYPE_LAST_INITIAL_TGT_REQUEST = 1,
  SHISHI_LRTYPE_LAST_INITIAL_REQUEST = 2,
  SHISHI_LRTYPE_NEWEST_TGT_ISSUE = 3,
  SHISHI_LRTYPE_LAST_RENEWAL = 4,
  SHISHI_LRTYPE_LAST_REQUEST = 5
}
Shishi_lrtype;

typedef enum
{
  SHISHI_NULL = 0,
  SHISHI_DES_CBC_CRC = 1,
  SHISHI_DES_CBC_MD4 = 2,
  SHISHI_DES_CBC_MD5 = 3,
  SHISHI_DES_CBC_NONE = 4,
  SHISHI_DES3_CBC_NONE = 6,
  SHISHI_DES3_CBC_HMAC_SHA1_KD = 16,
  SHISHI_AES128_CTS_HMAC_SHA1_96 = 17,
  SHISHI_AES256_CTS_HMAC_SHA1_96 = 18,
  SHISHI_ARCFOUR_HMAC = 23,
  SHISHI_ARCFOUR_HMAC_EXP = 24
}
Shishi_etype;

typedef enum
{
  SHISHI_CRC32 = 1,
  SHISHI_RSA_MD4 = 2,
  SHISHI_RSA_MD4_DES = 3,
  SHISHI_DES_MAC = 4,
  SHISHI_DES_MAC_K = 5,
  SHISHI_RSA_MD4_DES_K = 6,
  SHISHI_RSA_MD5 = 7,
  SHISHI_RSA_MD5_DES = 8,
  SHISHI_RSA_MD5_DES_GSS = 9,	/* XXX */
  SHISHI_HMAC_SHA1_DES3_KD = 12,
  SHISHI_HMAC_SHA1_96_AES128 = 15,
  SHISHI_HMAC_SHA1_96_AES256 = 16,
  SHISHI_ARCFOUR_HMAC_MD5 = -138,
  SHISHI_KRB5_GSSAPI_CKSUM = 8003,
  SHISHI_NO_CKSUMTYPE = -1
}
Shishi_cksumtype;

typedef enum
{
  SHISHI_FILETYPE_TEXT = 0,
  SHISHI_FILETYPE_DER,
  SHISHI_FILETYPE_HEX,
  SHISHI_FILETYPE_BASE64,
  SHISHI_FILETYPE_BINARY
}
Shishi_filetype;

typedef enum
{
  SHISHI_OUTPUTTYPE_NULL = 0,
  SHISHI_OUTPUTTYPE_STDERR,
  SHISHI_OUTPUTTYPE_SYSLOG
}
Shishi_outputtype;

typedef enum
{
  SHISHI_AUTHORIZATION_BASIC = 0,
  SHISHI_AUTHORIZATION_K5LOGIN
}
Shishi_authorization;

typedef enum
{
  /* 1. AS-REQ PA-ENC-TIMESTAMP padata timestamp, encrypted with the
     client key */
  SHISHI_KEYUSAGE_ASREQ_PA_ENC_TIMESTAMP = 1,
  /* 2. AS-REP Ticket and TGS-REP Ticket (includes TGS session key or
     application session key), encrypted with the service key  */
  SHISHI_KEYUSAGE_ENCTICKETPART = 2,
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
  SHISHI_KEYUSAGE_GSS_R1 = 22,
  SHISHI_KEYUSAGE_GSS_R2 = 23,
  SHISHI_KEYUSAGE_GSS_R3 = 24,
  /* draft-ietf-krb-wg-gssapi-cfx */
  SHISHI_KEYUSAGE_ACCEPTOR_SEAL = 22,
  SHISHI_KEYUSAGE_ACCEPTOR_SIGN = 23,
  SHISHI_KEYUSAGE_INITIATOR_SEAL = 24,
  SHISHI_KEYUSAGE_INITIATOR_SIGN = 25,
  /* 16-18,20-21,25-511. Reserved for future use. */
  /* 512-1023.  Reserved for uses internal implementations. */
  /* 1024.         Encryption for application use in protocols that
     do not specify key usage values */
  /* 1025.         Checksums for application use in protocols that
     do not specify key usage values */
  /* 1026-2047.      Reserved for application use.
     1026,1028,1030,1032,1034 used in KCMD protocol */
  SHISHI_KEYUSAGE_KCMD_DES = 1026,
  SHISHI_KEYUSAGE_KCMD_INPUT = 1028,
  SHISHI_KEYUSAGE_KCMD_OUTPUT = 1030,
  SHISHI_KEYUSAGE_KCMD_STDERR_INPUT = 1032,
  SHISHI_KEYUSAGE_KCMD_STDERR_OUTPUT = 1034
}
Shishi_keyusage;

typedef enum
{
  /* No error */
  SHISHI_KDC_ERR_NONE = 0,
  /* Client's entry in database has expired */
  SHISHI_KDC_ERR_NAME_EXP = 1,
  /* Server's entry in database has expired */
  SHISHI_KDC_ERR_SERVICE_EXP = 2,
  /* Requested protocol version number  - not supported */
  SHISHI_KDC_ERR_BAD_PVNO = 3,
  /* Client's key encrypted in old master key */
  SHISHI_KDC_ERR_C_OLD_MAST_KVNO = 4,
  /* Server's key encrypted in old master key */
  SHISHI_KDC_ERR_S_OLD_MAST_KVNO = 5,
  /* Client not found in database */
  SHISHI_KDC_ERR_C_PRINCIPAL_UNKNOWN = 6,
  /* Server not found in database */
  SHISHI_KDC_ERR_S_PRINCIPAL_UNKNOWN = 7,
  /* Multiple principal entries in database */
  SHISHI_KDC_ERR_PRINCIPAL_NOT_UNIQUE = 8,
  /* The client or server has a null key */
  SHISHI_KDC_ERR_NULL_KEY = 9,
  /* Ticket not eligible for postdating */
  SHISHI_KDC_ERR_CANNOT_POSTDATE = 10,
  /* Requested start time is later than end time */
  SHISHI_KDC_ERR_NEVER_VALID = 11,
  /* KDC policy rejects request */
  SHISHI_KDC_ERR_POLICY = 12,
  /* KDC cannot accommodate requested option */
  SHISHI_KDC_ERR_BADOPTION = 13,
  /* KDC has no support for encryption type */
  SHISHI_KDC_ERR_ETYPE_NOSUPP = 14,
  /* KDC has no support for checksum type */
  SHISHI_KDC_ERR_SUMTYPE_NOSUPP = 15,
  /* KDC has no support for padata type */
  SHISHI_KDC_ERR_PADATA_TYPE_NOSUPP = 16,
  /* KDC has no support for transited type */
  SHISHI_KDC_ERR_TRTYPE_NOSUPP = 17,
  /* Clients credentials have been revoked */
  SHISHI_KDC_ERR_CLIENT_REVOKED = 18,
  /* Credentials for server have been revoked */
  SHISHI_KDC_ERR_SERVICE_REVOKED = 19,
  /* TGT has been revoked */
  SHISHI_KDC_ERR_TGT_REVOKED = 20,
  /* Client not yet valid - try again later */
  SHISHI_KDC_ERR_CLIENT_NOTYET = 21,
  /* Server not yet valid - try again later */
  SHISHI_KDC_ERR_SERVICE_NOTYET = 22,
  /* Password has expired - change password to reset */
  SHISHI_KDC_ERR_KEY_EXPIRED = 23,
  /* Pre-authentication information was invalid */
  SHISHI_KDC_ERR_PREAUTH_FAILED = 24,
  /* Additional pre-authenticationrequired */
  SHISHI_KDC_ERR_PREAUTH_REQUIRED = 25,
  /* Requested server and ticket don't match */
  SHISHI_KDC_ERR_SERVER_NOMATCH = 26,
  /* Server principal valid for user = 2,user only */
  SHISHI_KDC_ERR_MUST_USE_USER2USER = 27,
  /* KDC Policy rejects transited path */
  SHISHI_KDC_ERR_PATH_NOT_ACCPETED = 28,
  /* A service is not available */
  SHISHI_KDC_ERR_SVC_UNAVAILABLE = 29,
  /* Integrity check on decrypted field failed */
  SHISHI_KRB_AP_ERR_BAD_INTEGRITY = 31,
  /* Ticket expired */
  SHISHI_KRB_AP_ERR_TKT_EXPIRED = 32,
  /* Ticket not yet valid */
  SHISHI_KRB_AP_ERR_TKT_NYV = 33,
  /* Request is a replay */
  SHISHI_KRB_AP_ERR_REPEAT = 34,
  /* The ticket isn't for us */
  SHISHI_KRB_AP_ERR_NOT_US = 35,
  /* Ticket and authenticator don't match */
  SHISHI_KRB_AP_ERR_BADMATCH = 36,
  /* Clock skew too great */
  SHISHI_KRB_AP_ERR_SKEW = 37,
  /* Incorrect net address */
  SHISHI_KRB_AP_ERR_BADADDR = 38,
  /* Protocol version mismatch */
  SHISHI_KRB_AP_ERR_BADVERSION = 39,
  /* Invalid msg type */
  SHISHI_KRB_AP_ERR_MSG_TYPE = 40,
  /* Message stream modified */
  SHISHI_KRB_AP_ERR_MODIFIED = 41,
  /* Message out of order */
  SHISHI_KRB_AP_ERR_BADORDER = 42,
  /* Specified version of key is not available */
  SHISHI_KRB_AP_ERR_BADKEYVER = 44,
  /* Service key not available */
  SHISHI_KRB_AP_ERR_NOKEY = 45,
  /* Mutual authentication failed */
  SHISHI_KRB_AP_ERR_MUT_FAIL = 46,
  /* Incorrect message direction */
  SHISHI_KRB_AP_ERR_BADDIRECTION = 47,
  /* Alternative authentication method required */
  SHISHI_KRB_AP_ERR_METHOD = 48,
  /* Incorrect sequence number in message */
  SHISHI_KRB_AP_ERR_BADSEQ = 49,
  /* Inappropriate type of checksum in message */
  SHISHI_KRB_AP_ERR_INAPP_CKSUM = 50,
  /* Policy rejects transited path */
  SHISHI_KRB_AP_PATH_NOT_ACCEPTED = 51,
  /* Response too big for UDP, retry with TCP */
  SHISHI_KRB_ERR_RESPONSE_TOO_BIG = 52,
  /* Generic error (description in e-text) */
  SHISHI_KRB_ERR_GENERIC = 60,
  /* Field is too long for this implementation */
  SHISHI_KRB_ERR_FIELD_TOOLONG = 61,
  /* Reserved for PKINIT */
  SHISHI_KDC_ERROR_CLIENT_NOT_TRUSTED = 62,
  /* Reserved for PKINIT */
  SHISHI_KDC_ERROR_KDC_NOT_TRUSTED = 63,
  /* Reserved for PKINIT */
  SHISHI_KDC_ERROR_INVALID_SIG = 64,
  /* Reserved for PKINIT */
  SHISHI_KDC_ERR_KEY_TOO_WEAK = 65,
  /* Reserved for PKINIT */
  SHISHI_KDC_ERR_CERTIFICATE_MISMATCH = 66,
  /* No TGT available to validate USER-TO-USER */
  SHISHI_KRB_AP_ERR_NO_TGT = 67,
  /* USER-TO-USER TGT issued different KDC */
  SHISHI_KDC_ERR_WRONG_REALM = 68,
  /* Ticket must be for USER-TO-USER */
  SHISHI_KRB_AP_ERR_USER_TO_USER_REQUIRED = 69,
  /* Reserved for PKINIT */
  SHISHI_KDC_ERR_CANT_VERIFY_CERTIFICATE = 70,
  /* Reserved for PKINIT */
  SHISHI_KDC_ERR_INVALID_CERTIFICATE = 71,
  /* Reserved for PKINIT */
  SHISHI_KDC_ERR_REVOKED_CERTIFICATE = 72,
  /* Reserved for PKINIT */
  SHISHI_KDC_ERR_REVOCATION_STATUS_UNKNOWN = 73,
  /* Reserved for PKINIT */
  SHISHI_KDC_ERR_REVOCATION_STATUS_UNAVAILABLE = 74,
  /* Reserved for PKINIT */
  SHISHI_KDC_ERR_CLIENT_NAME_MISMATCH = 75,
  /* Reserved for PKINIT */
  SHISHI_KDC_ERR_KDC_NAME_MISMATCH = 76,
  SHISHI_LAST_ERROR_CODE = 76
}
Shishi_krb_error;

typedef enum
{
  SHISHI_TKTSHINTFLAGS_ACCEPT_EXPIRED = 1,
  SHISHI_TKTSHINTFLAGS_NON_INTERACTIVE = 2
}
Shishi_tkts_hintflags;

struct Shishi_tkts_hint
{
  int startpos;
  char *server;
  char *serverrealm;
  char *client;
  char *clientrealm;
  int flags;
  Shishi_ticketflags tktflags;
  Shishi_KDCOptions kdcoptions;
  int32_t etype;
  char *passwd;
  time_t starttime;
  time_t endtime;
  time_t renew_till;
  int32_t preauthetype;
  char *preauthsalt;
  size_t preauthsaltlen;
  char *preauths2kparams;
  size_t preauths2kparamslen;
};
typedef struct Shishi_tkts_hint Shishi_tkts_hint;

/* resolv.c */
#define SHISHI_DNS_IN 1
#define SHISHI_DNS_TXT 16
#define SHISHI_DNS_SRV 33

struct Shishi_dns_st
{
  struct Shishi_dns_st *next;

  uint16_t class;
  uint16_t type;
  uint32_t ttl;

  void *rr;
};
typedef struct Shishi_dns_st *Shishi_dns;

struct Shishi_dns_srv_st
{
  uint16_t priority;
  uint16_t weight;
  uint16_t port;

  char name[256];
};
typedef struct Shishi_dns_srv_st *Shishi_dns_srv;

typedef struct Shishi Shishi;
typedef struct Shishi_tkt Shishi_tkt;
typedef struct Shishi_tkts Shishi_tkts;
typedef struct Shishi_as Shishi_as;
typedef struct Shishi_tgs Shishi_tgs;
typedef struct Shishi_ap Shishi_ap;
typedef struct Shishi_key Shishi_key;
typedef struct Shishi_keys Shishi_keys;
typedef struct Shishi_safe Shishi_safe;
typedef struct Shishi_priv Shishi_priv;
#ifdef LIBTASN1_H
typedef ASN1_TYPE Shishi_asn1;
#else
typedef void *Shishi_asn1;
#endif
typedef struct Shishi_crypto Shishi_crypto;

#define SHISHI_GENERALIZEDTIME_LENGTH 15
#define SHISHI_GENERALIZEDTIMEZ_LENGTH (SHISHI_GENERALIZEDTIME_LENGTH + 1)

/* If non-NULL, call this function when memory is exhausted. */
extern void (*shishi_alloc_fail_function) (void);

/* init.c */
extern Shishi *shishi (void);
extern Shishi *shishi_server (void);
extern void shishi_done (Shishi * handle);
extern int shishi_init (Shishi ** handle);
extern int shishi_init_with_paths (Shishi ** handle,
				   const char *tktsfile,
				   const char *systemcfgfile,
				   const char *usercfgfile);
extern int shishi_init_server (Shishi ** handle);
extern int shishi_init_server_with_paths (Shishi ** handle,
					  const char *systemcfgfile);

/* cfg.c */
extern int shishi_cfg (Shishi * handle, const char *option);
extern int shishi_cfg_from_file (Shishi * handle, const char *cfg);
extern int shishi_cfg_print (Shishi * handle, FILE * fh);
extern const char *shishi_cfg_default_systemfile (Shishi * handle);
extern const char *shishi_cfg_default_userdirectory (Shishi * handle);
extern const char *shishi_cfg_default_userfile (Shishi * handle);
extern char *shishi_cfg_userdirectory_file (Shishi * handle,
					    const char *file);
extern int shishi_cfg_clientkdcetype (Shishi * handle, int32_t ** etypes);
extern int32_t shishi_cfg_clientkdcetype_fast (Shishi * handle);
extern int shishi_cfg_clientkdcetype_set (Shishi * handle, char *value);
extern int shishi_cfg_authorizationtype_set (Shishi * handle, char *value);

/* error.c */
extern const char *shishi_strerror (int err);
extern const char *shishi_error (Shishi * handle);
extern void shishi_error_clear (Shishi * handle);
extern void shishi_error_set (Shishi * handle, const char *errstr);
extern void shishi_error_printf (Shishi * handle, const char *format, ...)
  __attribute__ ((format (printf, 2, 3)));
extern int shishi_error_outputtype (Shishi * handle);
extern void shishi_error_set_outputtype (Shishi * handle, int type);
extern void shishi_info (Shishi * handle, const char *format, ...)
  __attribute__ ((format (printf, 2, 3)));
extern void shishi_warn (Shishi * handle, const char *format, ...)
  __attribute__ ((format (printf, 2, 3)));
extern void shishi_verbose (Shishi * handle, const char *format, ...)
  __attribute__ ((format (printf, 2, 3)));

/* realm.c */
extern char *shishi_realm_default_guess (void);
extern const char *shishi_realm_default (Shishi * handle);
extern void shishi_realm_default_set (Shishi * handle, const char *realm);
extern char *shishi_realm_for_server_file (Shishi * handle, char *server);
extern char *shishi_realm_for_server_dns (Shishi * handle, char *server);
extern char *shishi_realm_for_server (Shishi * handle, char *server);

/* principal.c */
extern char *shishi_principal_default_guess (void);
extern const char *shishi_principal_default (Shishi * handle);
extern void shishi_principal_default_set (Shishi * handle,
					  const char *principal);
extern int shishi_principal_name (Shishi * handle,
				  Shishi_asn1 namenode,
				  const char *namefield,
				  char **out, size_t * outlen);
extern int shishi_principal_name_realm (Shishi * handle,
					Shishi_asn1 namenode,
					const char *namefield,
					Shishi_asn1 realmnode,
					const char *realmfield,
					char **out, size_t * outlen);
extern int shishi_principal_name_set (Shishi * handle,
				      Shishi_asn1 namenode,
				      const char *namefield,
				      Shishi_name_type name_type,
				      const char *name[]);
extern int shishi_principal_set (Shishi * handle,
				 Shishi_asn1 namenode,
				 const char *namefield, const char *name);
extern int shishi_parse_name (Shishi * handle, const char *name,
			      char **principal, char **realm);
extern int shishi_derive_default_salt (Shishi * handle,
				       const char *name,
				       char **salt);
extern char *shishi_server_for_local_service (Shishi * handle,
					      const char *service);

/* ticket.c */
extern Shishi_asn1 shishi_ticket (Shishi * handle);
extern int shishi_ticket_server (Shishi * handle, Shishi_asn1 ticket,
				 char **server, size_t * serverlen);
extern int shishi_ticket_sname_set (Shishi * handle,
				    Shishi_asn1 ticket,
				    Shishi_name_type name_type,
				    char *sname[]);
extern int shishi_ticket_srealmserver_set (Shishi * handle,
					   Shishi_asn1 ticket,
					   const char *realm,
					   const char *server);
extern int shishi_ticket_set_server (Shishi * handle, Shishi_asn1 ticket,
				     const char *server);
extern int shishi_ticket_realm_get (Shishi * handle,
				    Shishi_asn1 ticket,
				    char **realm, size_t * realmlen);
extern int shishi_ticket_realm_set (Shishi * handle, Shishi_asn1 ticket,
				    const char *realm);
extern int shishi_ticket_get_enc_part_etype (Shishi * handle,
					     Shishi_asn1 ticket,
					     int32_t * etype);
extern int shishi_ticket_set_enc_part (Shishi * handle, Shishi_asn1 ticket,
				       int32_t etype, uint32_t kvno,
				       const char *buf, size_t buflen);
extern int shishi_ticket_add_enc_part (Shishi * handle, Shishi_asn1 ticket,
				       Shishi_key * key,
				       Shishi_asn1 encticketpart);
extern int shishi_ticket_decrypt (Shishi * handle, Shishi_asn1 ticket,
				  Shishi_key * key,
				  Shishi_asn1 * encticketpart);

/* tkt.c */
extern Shishi_asn1 shishi_tkt_ticket (Shishi_tkt * tkt);
extern void shishi_tkt_ticket_set (Shishi_tkt * tkt, Shishi_asn1 ticket);
extern Shishi_asn1 shishi_tkt_kdcrep (Shishi_tkt * tkt);
extern Shishi_asn1 shishi_tkt_enckdcreppart (Shishi_tkt * tkt);
extern void shishi_tkt_enckdcreppart_set (Shishi_tkt * tkt,
					  Shishi_asn1 enckdcreppart);
extern Shishi_asn1 shishi_tkt_encticketpart (Shishi_tkt * tkt);
extern void shishi_tkt_encticketpart_set (Shishi_tkt * tkt,
					  Shishi_asn1 encticketpart);
extern Shishi_key *shishi_tkt_key (Shishi_tkt * tkt);
extern int shishi_tkt_key_set (Shishi_tkt * tkt, Shishi_key * key);
extern int shishi_tkt (Shishi * handle, Shishi_tkt ** tkt);
extern Shishi_tkt *shishi_tkt2 (Shishi * handle,
				Shishi_asn1 ticket,
				Shishi_asn1 enckdcreppart,
				Shishi_asn1 kdcrep);
extern void shishi_tkt_pretty_print (Shishi_tkt * tkt, FILE * fh);
extern int shishi_tkt_realm (Shishi_tkt * tkt, char **realm,
			     size_t * realmlen);
extern int shishi_tkt_client (Shishi_tkt * tkt,
			      char **client, size_t * clientlen);
extern int shishi_tkt_client_p (Shishi_tkt * tkt, const char *client);
extern int shishi_tkt_clientrealm (Shishi_tkt * tkt,
				   char **client, size_t *clientlen);
extern int shishi_tkt_clientrealm_p (Shishi_tkt * tkt, const char *client);
extern int shishi_tkt_clientrealm_set (Shishi_tkt * tkt,
				       const char *realm, const char *client);
extern int shishi_tkt_serverrealm_set (Shishi_tkt * tkt,
				       const char *realm, const char *server);
extern int shishi_tkt_build (Shishi_tkt * tkt, Shishi_key * key);
extern int shishi_tkt_lastreq (Shishi_tkt * tkt,
			       char **lrtime, size_t * lrtimelen,
			       int32_t lrtype);
extern time_t shishi_tkt_lastreqc (Shishi_tkt * tkt, Shishi_lrtype lrtype);
extern void shishi_tkt_lastreq_pretty_print (Shishi_tkt * tkt, FILE * fh);
extern int shishi_tkt_authtime (Shishi_tkt * tkt,
				char **authtime, size_t * authtimelen);
extern time_t shishi_tkt_authctime (Shishi_tkt * tkt);
extern int shishi_tkt_starttime (Shishi_tkt * tkt,
				 char **starttime, size_t * starttimelen);
extern time_t shishi_tkt_startctime (Shishi_tkt * tkt);
extern int shishi_tkt_endtime (Shishi_tkt * tkt,
			       char **endtime, size_t * endtimelen);
extern time_t shishi_tkt_endctime (Shishi_tkt * tkt);
extern int shishi_tkt_renew_till (Shishi_tkt * tkt,
				  char **renewtilltime,
				  size_t * renewtilllen);
extern time_t shishi_tkt_renew_tillc (Shishi_tkt * tkt);
extern int shishi_tkt_keytype (Shishi_tkt * tkt, int32_t * etype);
extern int32_t shishi_tkt_keytype_fast (Shishi_tkt * tkt);
extern int shishi_tkt_keytype_p (Shishi_tkt * tkt, int32_t etype);
extern int shishi_tkt_server (Shishi_tkt * tkt,
			      char **server, size_t * serverlen);
extern int shishi_tkt_server_p (Shishi_tkt * tkt, const char *server);
extern int shishi_tkt_valid_at_time_p (Shishi_tkt * tkt, time_t now);
extern int shishi_tkt_valid_now_p (Shishi_tkt * tkt);
extern int shishi_tkt_expired_p (Shishi_tkt * tkt);
extern int shishi_tkt_decrypt (Shishi_tkt * tkt, Shishi_key * key);
extern void shishi_tkt_done (Shishi_tkt * tkt);
extern int shishi_tkt_flags (Shishi_tkt * tkt, uint32_t * flags);
extern int shishi_tkt_flags_set (Shishi_tkt * tkt, uint32_t flags);
extern int shishi_tkt_flags_add (Shishi_tkt * tkt, uint32_t flag);
extern int shishi_tkt_forwardable_p (Shishi_tkt * tkt);
extern int shishi_tkt_forwarded_p (Shishi_tkt * tkt);
extern int shishi_tkt_proxiable_p (Shishi_tkt * tkt);
extern int shishi_tkt_proxy_p (Shishi_tkt * tkt);
extern int shishi_tkt_may_postdate_p (Shishi_tkt * tkt);
extern int shishi_tkt_postdated_p (Shishi_tkt * tkt);
extern int shishi_tkt_invalid_p (Shishi_tkt * tkt);
extern int shishi_tkt_renewable_p (Shishi_tkt * tkt);
extern int shishi_tkt_initial_p (Shishi_tkt * tkt);
extern int shishi_tkt_pre_authent_p (Shishi_tkt * tkt);
extern int shishi_tkt_hw_authent_p (Shishi_tkt * tkt);
extern int shishi_tkt_transited_policy_checked_p (Shishi_tkt * tkt);
extern int shishi_tkt_ok_as_delegate_p (Shishi_tkt * tkt);

/* tkts.c */
extern char *shishi_tkts_default_file_guess (Shishi * handle);
extern const char *shishi_tkts_default_file (Shishi * handle);
extern void shishi_tkts_default_file_set (Shishi * handle,
					  const char *tktsfile);
extern Shishi_tkts *shishi_tkts_default (Shishi * handle);
extern int shishi_tkts_default_to_file (Shishi_tkts * tkts);
extern int shishi_tkts (Shishi * handle, Shishi_tkts ** tkts);
extern Shishi_tkt *shishi_tkts_nth (Shishi_tkts * tkts, int ticketno);
extern int shishi_tkts_size (Shishi_tkts * tkts);
extern int shishi_tkts_add (Shishi_tkts * tkts, Shishi_tkt * tkt);
extern int shishi_tkts_new (Shishi_tkts * tkts,
			    Shishi_asn1 ticket,
			    Shishi_asn1 enckdcreppart, Shishi_asn1 kdcrep);
extern int shishi_tkts_remove (Shishi_tkts * tkts, int ticketno);
extern int shishi_tkts_expire (Shishi_tkts * tkts);
extern int shishi_tkts_print_for_service (Shishi_tkts * tkts,
					  FILE * fh, const char *service);
extern int shishi_tkts_print (Shishi_tkts * tkts, FILE * fh);
extern int shishi_tkts_write (Shishi_tkts * tkts, FILE * fh);
extern int shishi_tkts_to_file (Shishi_tkts * tkts, const char *filename);
extern int shishi_tkts_read (Shishi_tkts * tkts, FILE * fh);
extern int shishi_tkts_from_file (Shishi_tkts * tkts, const char *filename);
extern void shishi_tkts_done (Shishi_tkts ** tkts);
extern int shishi_tkt_match_p (Shishi_tkt * tkt, Shishi_tkts_hint * hint);
extern Shishi_tkt *shishi_tkts_find (Shishi_tkts * tkts,
				     Shishi_tkts_hint * hint);
extern Shishi_tkt *shishi_tkts_find_for_clientserver (Shishi_tkts * tkts,
						      const char *client,
						      const char *server);
extern Shishi_tkt *shishi_tkts_find_for_server (Shishi_tkts * tkts,
						const char *server);
extern Shishi_tkt *shishi_tkts_get (Shishi_tkts * tkts,
				    Shishi_tkts_hint * hint);
extern Shishi_tkt *shishi_tkts_get_tgt (Shishi_tkts * tkts,
					Shishi_tkts_hint * hint);
extern Shishi_tkt *shishi_tkts_get_tgs (Shishi_tkts * tkts,
					Shishi_tkts_hint * hint,
					Shishi_tkt * tgt);
extern Shishi_tkt *shishi_tkts_get_for_clientserver (Shishi_tkts * tkts,
						     const char *client,
						     const char *server);
extern Shishi_tkt *shishi_tkts_get_for_server (Shishi_tkts * tkts,
					       const char *server);
extern Shishi_tkt *shishi_tkts_get_for_localservicepasswd (Shishi_tkts * tkts,
							   const char
							   *service,
							   const char
							   *passwd);

/* tktccache.c */
extern char *shishi_tkts_default_ccache_guess (Shishi * handle);
extern const char *shishi_tkts_default_ccache (Shishi * handle);
extern void shishi_tkts_default_ccache_set (Shishi * handle,
					    const char *ccache);
extern int shishi_tkts_add_ccache_mem (Shishi * handle,
				       const char *data, size_t len,
				       Shishi_tkts *tkts);
extern int shishi_tkts_add_ccache_file (Shishi * handle,
					const char *filename,
					Shishi_tkts *tkts);
extern int shishi_tkts_from_ccache_mem (Shishi * handle,
					const char *data, size_t len,
					Shishi_tkts **outtkts);
extern int shishi_tkts_from_ccache_file (Shishi * handle,
					 const char *filename,
					 Shishi_tkts **outtkts);

/* diskio.c */
extern int
shishi_enckdcreppart_print (Shishi * handle,
			    FILE * fh, Shishi_asn1 enckdcreppart);
extern int
shishi_enckdcreppart_save (Shishi * handle,
			   FILE * fh, Shishi_asn1 enckdcreppart);
extern int
shishi_enckdcreppart_parse (Shishi * handle,
			    FILE * fh, Shishi_asn1 * enckdcreppart);
extern int
shishi_enckdcreppart_read (Shishi * handle,
			   FILE * fh, Shishi_asn1 * enckdcreppart);
extern int shishi_ticket_save (Shishi * handle, FILE * fh,
			       Shishi_asn1 ticket);
extern int shishi_ticket_print (Shishi * handle, FILE * fh,
				Shishi_asn1 ticket);
extern int shishi_kdc_print (Shishi * handle, FILE * fh, Shishi_asn1 asreq,
			     Shishi_asn1 asrep, Shishi_asn1 encasreppart);
extern int shishi_ticket_parse (Shishi * handle, FILE * fh,
				Shishi_asn1 * ticket);
extern int shishi_ticket_read (Shishi * handle, FILE * fh,
			       Shishi_asn1 * ticket);
extern int shishi_etype_info_print (Shishi * handle, FILE * fh,
				    Shishi_asn1 etypeinfo);
extern int shishi_etype_info2_print (Shishi * handle, FILE * fh,
				     Shishi_asn1 etypeinfo2);
extern int shishi_padata_print (Shishi * handle, FILE * fh,
				Shishi_asn1 padata);
extern int shishi_methoddata_print (Shishi * handle, FILE * fh,
				    Shishi_asn1 methoddata);

/* authenticator.c */
extern Shishi_asn1 shishi_authenticator (Shishi * handle);
extern int shishi_authenticator_set_crealm (Shishi * handle,
					    Shishi_asn1 authenticator,
					    const char *crealm);
extern int shishi_authenticator_set_cname (Shishi * handle,
					   Shishi_asn1 authenticator,
					   Shishi_name_type name_type,
					   const char *cname[]);
extern int shishi_authenticator_client_set (Shishi * handle,
					    Shishi_asn1 authenticator,
					    const char *client);
extern int shishi_authenticator_ctime (Shishi * handle,
				       Shishi_asn1 authenticator, char **t);
extern int shishi_authenticator_ctime_set (Shishi * handle,
					   Shishi_asn1 authenticator,
					   const char *t);
extern int shishi_authenticator_cusec_get (Shishi * handle,
					   Shishi_asn1 authenticator,
					   uint32_t * cusec);
extern int shishi_authenticator_cusec_set (Shishi * handle,
					   Shishi_asn1 authenticator,
					   uint32_t cusec);
extern int shishi_authenticator_seqnumber_get (Shishi * handle,
					       Shishi_asn1 authenticator,
					       uint32_t * seqnumber);
extern int shishi_authenticator_seqnumber_remove (Shishi * handle,
						  Shishi_asn1 authenticator);
extern int shishi_authenticator_seqnumber_set (Shishi * handle,
					       Shishi_asn1 authenticator,
					       uint32_t seqnumber);
extern int shishi_authenticator_client (Shishi * handle,
					Shishi_asn1 authenticator,
					char **client, size_t *clientlen);
extern int shishi_authenticator_clientrealm (Shishi * handle,
					     Shishi_asn1 authenticator,
					     char **client, size_t *clientlen);
extern int shishi_authenticator_remove_cksum (Shishi * handle,
					      Shishi_asn1 authenticator);
extern int shishi_authenticator_cksum (Shishi * handle,
				       Shishi_asn1 authenticator,
				       int32_t * cksumtype,
				       char **cksum, size_t * cksumlen);
extern int shishi_authenticator_set_cksum (Shishi * handle,
					   Shishi_asn1 authenticator,
					   int cksumtype,
					   char *cksum, size_t cksumlen);
extern int shishi_authenticator_add_cksum (Shishi * handle,
					   Shishi_asn1 authenticator,
					   Shishi_key * key,
					   int keyusage,
					   char *data, size_t datalen);
extern int
shishi_authenticator_add_cksum_type (Shishi * handle,
				     Shishi_asn1 authenticator,
				     Shishi_key * key,
				     int keyusage, int cksumtype,
				     char *data, size_t datalen);
extern int
shishi_authenticator_remove_subkey (Shishi * handle,
				    Shishi_asn1 authenticator);
extern Shishi_asn1 shishi_authenticator_subkey (Shishi * handle);
extern int
shishi_authenticator_get_subkey (Shishi * handle,
				 Shishi_asn1 authenticator,
				 Shishi_key ** subkey);
extern int
shishi_authenticator_set_subkey (Shishi * handle,
				 Shishi_asn1 authenticator,
				 int32_t subkeytype,
				 const char *subkey, size_t subkeylen);
extern int
shishi_authenticator_add_random_subkey (Shishi * handle,
					Shishi_asn1 authenticator);
extern int
shishi_authenticator_add_random_subkey_etype (Shishi * handle,
					      Shishi_asn1 authenticator,
					      int etype);
extern int
shishi_authenticator_add_subkey (Shishi * handle,
				 Shishi_asn1 authenticator,
				 Shishi_key * subkey);
extern int
shishi_authenticator_clear_authorizationdata (Shishi * handle,
					      Shishi_asn1 authenticator);
extern int
shishi_authenticator_add_authorizationdata (Shishi * handle,
					    Shishi_asn1 authenticator,
					    int32_t adtype,
					    const char *addata,
					    size_t addatalen);
extern int
shishi_authenticator_authorizationdata (Shishi * handle,
					Shishi_asn1 authenticator,
					int32_t * adtype,
					char **addata, size_t * addatalen,
					size_t nth);
extern int shishi_authenticator_read (Shishi * handle, FILE * fh,
				      Shishi_asn1 * authenticator);
extern int shishi_authenticator_parse (Shishi * handle, FILE * fh,
				       Shishi_asn1 * authenticator);
extern int shishi_authenticator_from_file (Shishi * handle,
					   Shishi_asn1 * authenticator,
					   int filetype,
					   const char *filename);
extern int shishi_authenticator_print (Shishi * handle, FILE * fh,
				       Shishi_asn1 authenticator);
extern int shishi_authenticator_to_file (Shishi * handle,
					 Shishi_asn1 authenticator,
					 int filetype, const char *filename);
extern int shishi_authenticator_save (Shishi * handle, FILE * fh,
				      Shishi_asn1 authenticator);

/* as.c */
extern int shishi_as (Shishi * handle, Shishi_as ** as);
extern void shishi_as_done (Shishi_as * as);
extern Shishi_asn1 shishi_as_req (Shishi_as * as);
extern int shishi_as_req_build (Shishi_as * as);
extern void shishi_as_req_set (Shishi_as * as, Shishi_asn1 asreq);
extern int shishi_as_req_der (Shishi_as * as, char **out, size_t * outlen);
extern int shishi_as_req_der_set (Shishi_as * as, char *der, size_t derlen);
extern Shishi_asn1 shishi_as_rep (Shishi_as * as);
extern void shishi_as_rep_set (Shishi_as * as, Shishi_asn1 asrep);
extern int shishi_as_rep_build (Shishi_as * as, Shishi_key * key);
extern int shishi_as_rep_der (Shishi_as * as, char **out, size_t * outlen);
extern int shishi_as_rep_der_set (Shishi_as * as, char *der, size_t derlen);
extern Shishi_asn1 shishi_as_krberror (Shishi_as * as);
extern int shishi_as_krberror_der (Shishi_as * as, char **out,
				   size_t * outlen);
extern void shishi_as_krberror_set (Shishi_as * as, Shishi_asn1 krberror);
extern Shishi_tkt *shishi_as_tkt (Shishi_as * as);
extern void shishi_as_tkt_set (Shishi_as * as, Shishi_tkt * tkt);
extern int shishi_as_sendrecv (Shishi_as * as);
extern int shishi_as_sendrecv_hint (Shishi_as * as, Shishi_tkts_hint * hint);
extern int shishi_as_rep_process (Shishi_as * as,
				  Shishi_key * key, const char *password);

/* tgs.c */
extern int shishi_tgs (Shishi * handle, Shishi_tgs ** tgs);
extern void shishi_tgs_done (Shishi_tgs * tgs);
extern Shishi_tkt *shishi_tgs_tgtkt (Shishi_tgs * tgs);
extern void shishi_tgs_tgtkt_set (Shishi_tgs * tgs, Shishi_tkt * tgtkt);
extern Shishi_ap *shishi_tgs_ap (Shishi_tgs * tgs);
extern Shishi_asn1 shishi_tgs_req (Shishi_tgs * tgs);
extern int shishi_tgs_req_der (Shishi_tgs * tgs, char **out, size_t * outlen);
extern int shishi_tgs_req_der_set (Shishi_tgs * tgs, char *der,
				   size_t derlen);
extern void shishi_tgs_req_set (Shishi_tgs * tgs, Shishi_asn1 tgsreq);
extern int shishi_tgs_req_build (Shishi_tgs * tgs);
extern int shishi_tgs_req_process (Shishi_tgs * tgs);
extern Shishi_asn1 shishi_tgs_rep (Shishi_tgs * tgs);
extern int shishi_tgs_rep_der (Shishi_tgs * tgs, char **out, size_t * outlen);
extern int shishi_tgs_rep_build (Shishi_tgs * tgs, int keyusage,
				 Shishi_key * key);
extern int shishi_tgs_rep_process (Shishi_tgs * tgs);
extern Shishi_asn1 shishi_tgs_krberror (Shishi_tgs * tgs);
extern int shishi_tgs_krberror_der (Shishi_tgs * tgs, char **out,
				    size_t * outlen);
extern void shishi_tgs_krberror_set (Shishi_tgs * tgs, Shishi_asn1 krberror);
extern Shishi_tkt *shishi_tgs_tkt (Shishi_tgs * tgs);
extern void shishi_tgs_tkt_set (Shishi_tgs * tgs, Shishi_tkt * tkt);
extern int shishi_tgs_sendrecv (Shishi_tgs * tgs);
extern int shishi_tgs_sendrecv_hint (Shishi_tgs * tgs,
				     Shishi_tkts_hint * hint);
extern int shishi_tgs_set_server (Shishi_tgs * tgs, const char *server);
extern int shishi_tgs_set_realm (Shishi_tgs * tgs, const char *realm);
extern int shishi_tgs_set_realmserver (Shishi_tgs * tgs,
				       const char *realm, const char *server);

/* kdcreq.c */
extern int shishi_kdcreq (Shishi * handle, char *realm,
			  char *service, Shishi_asn1 * req);
extern Shishi_asn1 shishi_asreq (Shishi * handle);
extern Shishi_asn1 shishi_asreq_rsc (Shishi * handle, char *realm,
				     char *server, char *client);
extern Shishi_asn1 shishi_tgsreq (Shishi * handle);
extern Shishi_asn1 shishi_tgsreq_rst (Shishi * handle, char *realm,
				      char *server, Shishi_tkt * tkt);
extern int shishi_kdcreq_save (Shishi * handle, FILE * fh,
			       Shishi_asn1 kdcreq);
extern int shishi_kdcreq_print (Shishi * handle, FILE * fh,
				Shishi_asn1 kdcreq);
extern int shishi_kdcreq_to_file (Shishi * handle, Shishi_asn1 kdcreq,
				  int filetype, const char *filename);
extern int shishi_kdcreq_parse (Shishi * handle, FILE * fh,
				Shishi_asn1 * kdcreq);
extern int shishi_kdcreq_read (Shishi * handle, FILE * fh,
			       Shishi_asn1 * kdcreq);
extern int shishi_kdcreq_from_file (Shishi * handle, Shishi_asn1 * kdcreq,
				    int filetype, const char *filename);
extern int shishi_asreq_clientrealm (Shishi * handle,
				     Shishi_asn1 asreq,
				     char **client, size_t * clientlen);
extern int shishi_kdcreq_nonce (Shishi * handle, Shishi_asn1 kdcreq,
				uint32_t * nonce);
extern int shishi_kdcreq_nonce_set (Shishi * handle,
				    Shishi_asn1 kdcreq, uint32_t nonce);
extern int shishi_kdcreq_client (Shishi * handle, Shishi_asn1 kdcreq,
				 char **client, size_t * clientlen);
extern int shishi_kdcreq_set_cname (Shishi * handle, Shishi_asn1 kdcreq,
				    Shishi_name_type name_type,
				    const char *principal);
extern int shishi_kdcreq_server (Shishi * handle, Shishi_asn1 kdcreq,
				 char **server, size_t * serverlen);
extern int shishi_kdcreq_set_sname (Shishi * handle, Shishi_asn1 kdcreq,
				    Shishi_name_type name_type,
				    const char *sname[]);
extern int shishi_kdcreq_realm (Shishi * handle, Shishi_asn1 kdcreq,
				char **realm, size_t * realmlen);
extern int shishi_kdcreq_realm_get (Shishi * handle, Shishi_asn1 kdcreq,
				    char **realm, size_t * realmlen);
extern int shishi_kdcreq_set_realm (Shishi * handle, Shishi_asn1 kdcreq,
				    const char *realm);
extern int shishi_kdcreq_set_server (Shishi * handle, Shishi_asn1 req,
				     const char *service);
extern int shishi_kdcreq_set_realmserver (Shishi * handle, Shishi_asn1 req,
					  char *realm, char *service);
extern int shishi_kdcreq_till (Shishi * handle, Shishi_asn1 kdcreq,
			       char **till, size_t * tilllen);
extern time_t shishi_kdcreq_tillc (Shishi * handle, Shishi_asn1 kdcreq);
extern int shishi_kdcreq_etype (Shishi * handle, Shishi_asn1 kdcreq,
				int32_t * etype, int netype);
extern int shishi_kdcreq_set_etype (Shishi * handle, Shishi_asn1 kdcreq,
				    int32_t * etype, int netype);
extern int shishi_kdcreq_options (Shishi * handle, Shishi_asn1 kdcreq,
				  uint32_t * flags);
extern int shishi_kdcreq_forwardable_p (Shishi * handle, Shishi_asn1 kdcreq);
extern int shishi_kdcreq_forwarded_p (Shishi * handle, Shishi_asn1 kdcreq);
extern int shishi_kdcreq_proxiable_p (Shishi * handle, Shishi_asn1 kdcreq);
extern int shishi_kdcreq_proxy_p (Shishi * handle, Shishi_asn1 kdcreq);
extern int shishi_kdcreq_allow_postdate_p (Shishi * handle,
					   Shishi_asn1 kdcreq);
extern int shishi_kdcreq_postdated_p (Shishi * handle, Shishi_asn1 kdcreq);
extern int shishi_kdcreq_renewable_p (Shishi * handle, Shishi_asn1 kdcreq);
extern int shishi_kdcreq_disable_transited_check_p (Shishi * handle,
						    Shishi_asn1 kdcreq);
extern int shishi_kdcreq_renewable_ok_p (Shishi * handle, Shishi_asn1 kdcreq);
extern int shishi_kdcreq_enc_tkt_in_skey_p (Shishi * handle,
					    Shishi_asn1 kdcreq);
extern int shishi_kdcreq_renew_p (Shishi * handle, Shishi_asn1 kdcreq);
extern int shishi_kdcreq_validate_p (Shishi * handle, Shishi_asn1 kdcreq);
extern int shishi_kdcreq_options_set (Shishi * handle, Shishi_asn1 kdcreq,
				      uint32_t options);
extern int shishi_kdcreq_options_add (Shishi * handle, Shishi_asn1 kdcreq,
				      uint32_t option);
extern int shishi_kdcreq_clear_padata (Shishi * handle, Shishi_asn1 kdcreq);
extern int shishi_kdcreq_get_padata (Shishi * handle,
				     Shishi_asn1 kdcreq,
				     Shishi_padata_type padatatype,
				     char **out, size_t * outlen);
extern int shishi_kdcreq_get_padata_tgs (Shishi * handle,
					 Shishi_asn1 kdcreq,
					 Shishi_asn1 * apreq);
extern int shishi_kdcreq_add_padata (Shishi * handle,
				     Shishi_asn1 kdcreq,
				     int padatatype,
				     const char *data, size_t datalen);
extern int shishi_kdcreq_add_padata_tgs (Shishi * handle,
					 Shishi_asn1 kdcreq,
					 Shishi_asn1 apreq);
extern int shishi_kdcreq_add_padata_preauth (Shishi * handle,
					     Shishi_asn1 kdcreq,
					     Shishi_key *key);
extern int shishi_kdcreq_build (Shishi * handle, Shishi_asn1 kdcreq);

/* kdc.c */
extern int shishi_as_derive_salt (Shishi * handle,
				  Shishi_asn1 asreq,
				  Shishi_asn1 asrep,
				  char **salt, size_t * saltlen);
extern int shishi_tgs_process (Shishi * handle,
			       Shishi_asn1 tgsreq,
			       Shishi_asn1 tgsrep,
			       Shishi_asn1 authenticator,
			       Shishi_asn1 oldenckdcreppart,
			       Shishi_asn1 * enckdcreppart);
extern int shishi_as_process (Shishi * handle, Shishi_asn1 asreq,
			      Shishi_asn1 asrep,
			      const char *string,
			      Shishi_asn1 * enckdcreppart);
extern int shishi_kdc_process (Shishi * handle, Shishi_asn1 kdcreq,
			       Shishi_asn1 kdcrep, Shishi_key * key,
			       int keyusage, Shishi_asn1 * enckdcreppart);
extern int shishi_kdcreq_sendrecv (Shishi * handle, Shishi_asn1 kdcreq,
				   Shishi_asn1 * kdcrep);
extern int shishi_kdcreq_sendrecv_hint (Shishi * handle,
					Shishi_asn1 kdcreq,
					Shishi_asn1 * kdcrep,
					Shishi_tkts_hint * hint);
extern int shishi_kdc_copy_crealm (Shishi * handle, Shishi_asn1 kdcrep,
				   Shishi_asn1 encticketpart);
extern int shishi_as_check_crealm (Shishi * handle, Shishi_asn1 asreq,
				   Shishi_asn1 asrep);
extern int shishi_kdc_copy_cname (Shishi * handle, Shishi_asn1 kdcrep,
				  Shishi_asn1 encticketpart);
extern int shishi_as_check_cname (Shishi * handle, Shishi_asn1 asreq,
				  Shishi_asn1 asrep);
extern int shishi_kdc_copy_nonce (Shishi * handle, Shishi_asn1 kdcreq,
				  Shishi_asn1 enckdcreppart);
extern int shishi_kdc_check_nonce (Shishi * handle, Shishi_asn1 kdcreq,
				   Shishi_asn1 enckdcreppart);

/* kdcrep.c */
extern Shishi_asn1 shishi_asrep (Shishi * handle);
extern Shishi_asn1 shishi_tgsrep (Shishi * handle);
extern int shishi_kdcrep_save (Shishi * handle, FILE * fh,
			       Shishi_asn1 kdcrep);
extern int shishi_kdcrep_print (Shishi * handle, FILE * fh,
				Shishi_asn1 kdcrep);
extern int shishi_kdcrep_to_file (Shishi * handle, Shishi_asn1 kdcrep,
				  int filetype, const char *filename);
extern int shishi_kdcrep_parse (Shishi * handle, FILE * fh,
				Shishi_asn1 * kdcrep);
extern int shishi_kdcrep_read (Shishi * handle, FILE * fh,
			       Shishi_asn1 * kdcrep);
extern int shishi_kdcrep_from_file (Shishi * handle, Shishi_asn1 * kdcrep,
				    int filetype, const char *filename);
extern int shishi_kdcrep_clear_padata (Shishi * handle, Shishi_asn1 kdcrep);
extern int shishi_kdcrep_get_enc_part_etype (Shishi * handle,
					     Shishi_asn1 kdcrep,
					     int32_t * etype);
extern int shishi_kdcrep_add_enc_part (Shishi * handle,
				       Shishi_asn1 kdcrep,
				       Shishi_key * key,
				       int keyusage,
				       Shishi_asn1 enckdcreppart);
extern int shishi_kdcrep_get_ticket (Shishi * handle,
				     Shishi_asn1 kdcrep,
				     Shishi_asn1 * ticket);
extern int shishi_kdcrep_set_ticket (Shishi * handle, Shishi_asn1 kdcrep,
				     Shishi_asn1 ticket);
extern int shishi_kdcrep_crealm_set (Shishi * handle,
				     Shishi_asn1 kdcrep, const char *crealm);
extern int shishi_kdcrep_cname_set (Shishi * handle,
				    Shishi_asn1 kdcrep,
				    Shishi_name_type name_type,
				    const char *cname[]);
extern int shishi_kdcrep_client_set (Shishi * handle, Shishi_asn1 kdcrep,
				     const char *client);
extern int shishi_kdcrep_crealmserver_set (Shishi * handle,
					   Shishi_asn1 kdcrep,
					   const char *crealm,
					   const char *client);
extern int shishi_kdcrep_set_enc_part (Shishi * handle, Shishi_asn1 kdcrep,
				       int32_t etype, uint32_t kvno,
				       const char *buf, size_t buflen);
extern int shishi_kdcrep_decrypt (Shishi * handle,
				  Shishi_asn1 kdcrep,
				  Shishi_key * key,
				  int keyusage, Shishi_asn1 * enckdcreppart);

/* enckdcreppart.c */
extern Shishi_asn1 shishi_enckdcreppart (Shishi * handle);
extern Shishi_asn1 shishi_encasreppart (Shishi * handle);
extern int shishi_enckdcreppart_get_key (Shishi * handle,
					 Shishi_asn1 enckdcreppart,
					 Shishi_key ** key);
extern int shishi_enckdcreppart_key_set (Shishi * handle,
					 Shishi_asn1 enckdcreppart,
					 Shishi_key * key);
extern int shishi_enckdcreppart_nonce_set (Shishi * handle,
					   Shishi_asn1 enckdcreppart,
					   uint32_t nonce);
extern int shishi_enckdcreppart_flags_set (Shishi * handle,
					   Shishi_asn1 enckdcreppart,
					   int flags);
extern int shishi_enckdcreppart_authtime_set (Shishi * handle,
					     Shishi_asn1 enckdcreppart,
					     const char *authtime);
extern int shishi_enckdcreppart_starttime_set (Shishi * handle,
					     Shishi_asn1 enckdcreppart,
					     const char *starttime);
extern int shishi_enckdcreppart_endtime_set (Shishi * handle,
					     Shishi_asn1 enckdcreppart,
					     const char *endtime);
extern int shishi_enckdcreppart_renew_till_set (Shishi * handle,
						Shishi_asn1 enckdcreppart,
						const char *renew_till);
extern int shishi_enckdcreppart_srealm_set (Shishi * handle,
					    Shishi_asn1 enckdcreppart,
					    const char *srealm);
extern int shishi_enckdcreppart_sname_set (Shishi * handle,
					   Shishi_asn1 enckdcreppart,
					   Shishi_name_type name_type,
					   char *sname[]);
extern int shishi_enckdcreppart_server_set (Shishi * handle,
					    Shishi_asn1 enckdcreppart,
					    const char *server);
extern int shishi_enckdcreppart_srealmserver_set (Shishi * handle,
						  Shishi_asn1 enckdcreppart,
						  const char *srealm,
						  const char *server);
extern int
shishi_enckdcreppart_populate_encticketpart (Shishi * handle,
					     Shishi_asn1 enckdcreppart,
					     Shishi_asn1 encticketpart);

/* krberror.c */
extern Shishi_asn1 shishi_krberror (Shishi * handle);
extern int shishi_krberror_print (Shishi * handle, FILE * fh,
				  Shishi_asn1 krberror);
extern int shishi_krberror_save (Shishi * handle, FILE * fh,
				 Shishi_asn1 krberror);
extern int shishi_krberror_to_file (Shishi * handle, Shishi_asn1 krberror,
				    int filetype, const char *filename);
extern int shishi_krberror_parse (Shishi * handle, FILE * fh,
				  Shishi_asn1 * krberror);
extern int shishi_krberror_read (Shishi * handle, FILE * fh,
				 Shishi_asn1 * krberror);
extern int shishi_krberror_from_file (Shishi * handle, Shishi_asn1 * krberror,
				      int filetype, const char *filename);
extern int shishi_krberror_build (Shishi * handle, Shishi_asn1 krberror);
extern int shishi_krberror_der (Shishi * handle,
				Shishi_asn1 krberror,
				char **out, size_t * outlen);
extern int shishi_krberror_crealm (Shishi * handle,
				   Shishi_asn1 krberror,
				   char **realm, size_t * realmlen);
extern int shishi_krberror_remove_crealm (Shishi * handle,
					  Shishi_asn1 krberror);
extern int shishi_krberror_set_crealm (Shishi * handle,
				       Shishi_asn1 krberror,
				       const char *crealm);
extern int shishi_krberror_client (Shishi * handle,
				   Shishi_asn1 krberror,
				   char **client, size_t * clientlen);
extern int shishi_krberror_set_cname (Shishi * handle,
				      Shishi_asn1 krberror,
				      Shishi_name_type name_type,
				      const char *cname[]);
extern int shishi_krberror_remove_cname (Shishi * handle,
					 Shishi_asn1 krberror);
extern int shishi_krberror_client_set (Shishi * handle,
				       Shishi_asn1 krberror,
				       const char *client);
extern int shishi_krberror_realm (Shishi * handle,
				  Shishi_asn1 krberror,
				  char **realm, size_t * realmlen);
extern int shishi_krberror_set_realm (Shishi * handle,
				      Shishi_asn1 krberror,
				      const char *realm);
extern int shishi_krberror_server (Shishi * handle,
				   Shishi_asn1 krberror,
				   char **server, size_t *serverlen);
extern int shishi_krberror_remove_sname (Shishi * handle,
					 Shishi_asn1 krberror);
extern int shishi_krberror_set_sname (Shishi * handle,
				      Shishi_asn1 krberror,
				      Shishi_name_type name_type,
				      const char *sname[]);
extern int shishi_krberror_server_set (Shishi * handle,
				       Shishi_asn1 krberror,
				       const char *server);
extern int shishi_krberror_ctime (Shishi * handle,
				  Shishi_asn1 krberror, char **t);
extern int shishi_krberror_ctime_set (Shishi * handle,
				      Shishi_asn1 krberror, const char *t);
extern int shishi_krberror_remove_ctime (Shishi * handle,
					 Shishi_asn1 krberror);
extern int shishi_krberror_cusec (Shishi * handle, Shishi_asn1 krberror,
				  uint32_t * cusec);
extern int shishi_krberror_cusec_set (Shishi * handle, Shishi_asn1 krberror,
				      uint32_t cusec);
extern int shishi_krberror_remove_cusec (Shishi * handle,
					 Shishi_asn1 krberror);
extern int shishi_krberror_stime (Shishi * handle, Shishi_asn1 krberror,
				  char **t);
extern int shishi_krberror_stime_set (Shishi * handle, Shishi_asn1 krberror,
				      const char *t);
extern int shishi_krberror_susec (Shishi * handle, Shishi_asn1 krberror,
				  uint32_t * susec);
extern int shishi_krberror_susec_set (Shishi * handle, Shishi_asn1 krberror,
				      uint32_t susec);
extern int shishi_krberror_errorcode_set (Shishi * handle,
					  Shishi_asn1 krberror,
					  int errorcode);
extern int shishi_krberror_etext (Shishi * handle, Shishi_asn1 krberror,
				  char **etext, size_t * etextlen);
extern int shishi_krberror_set_etext (Shishi * handle, Shishi_asn1 krberror,
				      const char *etext);
extern int shishi_krberror_remove_etext (Shishi * handle,
					 Shishi_asn1 krberror);
extern int shishi_krberror_edata (Shishi * handle, Shishi_asn1 krberror,
				  char **edata, size_t * edatalen);
extern int shishi_krberror_set_edata (Shishi * handle, Shishi_asn1 krberror,
				      const char *edata);
extern int shishi_krberror_remove_edata (Shishi * handle,
					 Shishi_asn1 krberror);
extern int shishi_krberror_errorcode (Shishi * handle, Shishi_asn1 krberror,
				      int *errorcode);
extern int shishi_krberror_errorcode_fast (Shishi * handle,
					   Shishi_asn1 krberror);
extern int shishi_krberror_pretty_print (Shishi * handle, FILE * fh,
					 Shishi_asn1 krberror);
extern const char *shishi_krberror_errorcode_message (Shishi * handle,
						      int errorcode);
extern const char *shishi_krberror_message (Shishi * handle,
					    Shishi_asn1 krberror);
extern int shishi_krberror_methoddata (Shishi * handle,
				       Shishi_asn1 krberror,
				       Shishi_asn1 *methoddata);

/* gztime.c */
extern const char *shishi_generalize_time (Shishi * handle, time_t t);
extern const char *shishi_generalize_now (Shishi * handle);
extern time_t shishi_generalize_ctime (Shishi * handle, const char *t);
extern int shishi_time (Shishi * handle, Shishi_asn1 node,
			const char *field, char **t);
extern int shishi_ctime (Shishi * handle, Shishi_asn1 node,
			 const char *field, time_t *t);

/* nettle.c, libgcrypt.c, ... */
extern int shishi_randomize (Shishi * handle, int strong,
			     void *data, size_t datalen);
extern int shishi_crc (Shishi * handle, const char *in, size_t inlen,
		       char *out[4]);
extern int shishi_md4 (Shishi * handle, const char *in, size_t inlen,
		       char *out[16]);
extern int shishi_md5 (Shishi * handle, const char *in, size_t inlen,
		       char *out[16]);
extern int shishi_hmac_md5 (Shishi * handle, const char *key, size_t keylen,
			    const char *in, size_t inlen, char *outhash[16]);
extern int shishi_hmac_sha1 (Shishi * handle, const char *key, size_t keylen,
			     const char *in, size_t inlen, char *outhash[20]);
extern int shishi_des_cbc_mac (Shishi * handle, const char key[8],
			       const char iv[8], const char *in, size_t inlen,
			       char *out[8]);
extern int shishi_arcfour (Shishi * handle, int decryptp,
			   const char *key, size_t keylen,
			   const char iv[258], char *ivout[258],
			   const char *in, size_t inlen, char **out);
extern int shishi_des (Shishi * handle, int decryptp, const char key[8],
		       const char iv[8], char *ivout[8],
		       const char *in, size_t inlen, char **out);
extern int shishi_3des (Shishi * handle, int decryptp, const char key[24],
			const char iv[8], char *ivout[8],
			const char *in, size_t inlen, char **out);
extern int shishi_aes_cts (Shishi * handle, int decryptp,
			   const char *key, size_t keylen,
			   const char iv[16], char *ivout[16],
			   const char *in, size_t inlen, char **out);

/* crypto.c */
extern int shishi_cipher_supported_p (int type);
extern const char *shishi_cipher_name (int type);
extern int shishi_cipher_blocksize (int type);
extern int shishi_cipher_confoundersize (int type);
extern size_t shishi_cipher_keylen (int type);
extern size_t shishi_cipher_randomlen (int type);
extern int shishi_cipher_defaultcksumtype (int32_t type);
extern int shishi_cipher_parse (const char *cipher);
extern int shishi_checksum_supported_p (int32_t type);
extern const char *shishi_checksum_name (int32_t type);
extern size_t shishi_checksum_cksumlen (int32_t type);
extern int shishi_checksum_parse (const char *checksum);
extern int shishi_string_to_key (Shishi * handle,
				 int32_t keytype,
				 const char *password, size_t passwordlen,
				 const char *salt, size_t saltlen,
				 const char *parameter, Shishi_key * outkey);
extern int shishi_random_to_key (Shishi * handle,
				 int32_t keytype,
				 const char *rnd,
				 size_t rndlen, Shishi_key * outkey);
extern int shishi_encrypt_ivupdate_etype (Shishi * handle,
					  Shishi_key * key,
					  int keyusage,
					  int32_t etype,
					  const char *iv, size_t ivlen,
					  char **ivout, size_t * ivoutlen,
					  const char *in, size_t inlen,
					  char **out, size_t * outlen);
extern int shishi_encrypt_iv_etype (Shishi * handle,
				    Shishi_key * key,
				    int keyusage,
				    int32_t etype,
				    const char *iv, size_t ivlen,
				    const char *in, size_t inlen,
				    char **out, size_t * outlen);
extern int shishi_encrypt_etype (Shishi * handle,
				 Shishi_key * key,
				 int keyusage,
				 int32_t etype,
				 const char *in, size_t inlen,
				 char **out, size_t * outlen);
extern int shishi_encrypt_ivupdate (Shishi * handle,
				    Shishi_key * key,
				    int keyusage,
				    const char *iv, size_t ivlen,
				    char **ivout, size_t * ivoutlen,
				    const char *in, size_t inlen,
				    char **out, size_t * outlen);
extern int shishi_encrypt_iv (Shishi * handle,
			      Shishi_key * key,
			      int keyusage,
			      const char *iv, size_t ivlen,
			      const char *in, size_t inlen,
			      char **out, size_t * outlen);
extern int shishi_encrypt (Shishi * handle,
			   Shishi_key * key,
			   int keyusage,
			   char *in, size_t inlen,
			   char **out, size_t * outlen);
extern int shishi_decrypt_ivupdate_etype (Shishi * handle,
					  Shishi_key * key,
					  int keyusage,
					  int32_t etype,
					  const char *iv, size_t ivlen,
					  char **ivout, size_t * ivoutlen,
					  const char *in, size_t inlen,
					  char **out, size_t * outlen);
extern int shishi_decrypt_iv_etype (Shishi * handle,
				    Shishi_key * key,
				    int keyusage,
				    int32_t etype,
				    const char *iv, size_t ivlen,
				    const char *in, size_t inlen,
				    char **out, size_t * outlen);
extern int shishi_decrypt_etype (Shishi * handle,
				 Shishi_key * key,
				 int keyusage,
				 int32_t etype,
				 const char *in, size_t inlen,
				 char **out, size_t * outlen);
extern int shishi_decrypt_ivupdate (Shishi * handle,
				    Shishi_key * key,
				    int keyusage,
				    const char *iv, size_t ivlen,
				    char **ivout, size_t * ivoutlen,
				    const char *in, size_t inlen,
				    char **out, size_t * outlen);
extern int shishi_decrypt_iv (Shishi * handle,
			      Shishi_key * key,
			      int keyusage,
			      const char *iv, size_t ivlen,
			      const char *in, size_t inlen,
			      char **out, size_t * outlen);
extern int shishi_decrypt (Shishi * handle,
			   Shishi_key * key,
			   int keyusage,
			   const char *in, size_t inlen,
			   char **out, size_t * outlen);
extern int shishi_checksum (Shishi * handle,
			    Shishi_key * key,
			    int keyusage,
			    int32_t cksumtype,
			    const char *in, size_t inlen,
			    char **out, size_t * outlen);
extern int shishi_verify (Shishi * handle,
			  Shishi_key * key,
			  int keyusage,
			  int cksumtype,
			  const char *in, size_t inlen,
			  const char *cksum, size_t cksumlen);
extern int shishi_dk (Shishi * handle,
		      Shishi_key * key,
		      const char *prfconstant, size_t prfconstantlen,
		      Shishi_key * derivedkey);
extern int shishi_dr (Shishi * handle,
		      Shishi_key * key,
		      const char *prfconstant, size_t prfconstantlen,
		      char *derivedrandom, size_t derivedrandomlen);
extern int shishi_n_fold (Shishi * handle, const char *in, size_t inlen,
			  char *out, size_t outlen);
extern int shishi_pbkdf2_sha1 (Shishi * handle,
			       const char *P, size_t Plen,
			       const char *S, size_t Slen,
			       unsigned int c, unsigned int dkLen, char *DK);

/* crypto-ctx.c */
extern Shishi_crypto *shishi_crypto (Shishi * handle,
				     Shishi_key * key, int keyusage,
				     int32_t etype,
				     const char *iv, size_t ivlen);
extern void shishi_crypto_close (Shishi_crypto * ctx);
extern int shishi_crypto_encrypt (Shishi_crypto * ctx,
				  const char *in, size_t inlen,
				  char **out, size_t * outlen);
extern int shishi_crypto_decrypt (Shishi_crypto * ctx,
				  const char *in, size_t inlen,
				  char **out, size_t * outlen);

/* version.c */
extern const char *shishi_check_version (const char *req_version);

/* password.c */
typedef int (*shishi_prompt_password_func) (Shishi * handle,
					    char **s,
					    const char *format,
					    va_list ap);
extern void
shishi_prompt_password_callback_set (Shishi * handle,
				     shishi_prompt_password_func cb);
extern shishi_prompt_password_func
shishi_prompt_password_callback_get (Shishi * handle);
extern int
shishi_prompt_password (Shishi * handle, char **s, const char *format, ...);

/* asn1.c */
extern int shishi_asn1_number_of_elements (Shishi * handle,
					   Shishi_asn1 node,
					   const char *field, size_t * n);
extern int shishi_asn1_empty_p (Shishi * handle, Shishi_asn1 node,
				const char *field);

extern int shishi_asn1_read (Shishi * handle, Shishi_asn1 node,
			     const char *field,
			     char **data, size_t * datalen);
extern int shishi_asn1_read_inline (Shishi * handle, Shishi_asn1 node,
				    const char *field,
				    char *data, size_t * datalen);
extern int shishi_asn1_read_integer (Shishi * handle, Shishi_asn1 node,
				     const char *field, int *i);
extern int shishi_asn1_read_int32 (Shishi * handle, Shishi_asn1 node,
				   const char *field, int32_t * i);
extern int shishi_asn1_read_uint32 (Shishi * handle, Shishi_asn1 node,
				    const char *field, uint32_t * i);
extern int shishi_asn1_read_bitstring (Shishi * handle, Shishi_asn1 node,
				       const char *field, uint32_t * flags);
extern int shishi_asn1_read_optional (Shishi * handle,
				      Shishi_asn1 node, const char *field,
				      char **data, size_t * datalen);

extern int shishi_asn1_write (Shishi * handle, Shishi_asn1 node,
			      const char *field,
			      const char *data, size_t datalen);
extern int shishi_asn1_write_integer (Shishi * handle, Shishi_asn1 node,
				      const char *field, int n);
extern int shishi_asn1_write_int32 (Shishi * handle, Shishi_asn1 node,
				    const char *field, int32_t n);
extern int shishi_asn1_write_uint32 (Shishi * handle, Shishi_asn1 node,
				     const char *field, uint32_t n);
extern int shishi_asn1_write_bitstring (Shishi * handle, Shishi_asn1 node,
					const char *field, uint32_t flags);

extern void shishi_asn1_done (Shishi * handle, Shishi_asn1 node);

extern Shishi_asn1 shishi_asn1_pa_enc_ts_enc (Shishi * handle);
extern Shishi_asn1 shishi_asn1_encrypteddata (Shishi * handle);
extern Shishi_asn1 shishi_asn1_padata (Shishi * handle);
extern Shishi_asn1 shishi_asn1_methoddata (Shishi * handle);
extern Shishi_asn1 shishi_asn1_etype_info (Shishi * handle);
extern Shishi_asn1 shishi_asn1_etype_info2 (Shishi * handle);
extern Shishi_asn1 shishi_asn1_asreq (Shishi * handle);
extern Shishi_asn1 shishi_asn1_asrep (Shishi * handle);
extern Shishi_asn1 shishi_asn1_tgsreq (Shishi * handle);
extern Shishi_asn1 shishi_asn1_tgsrep (Shishi * handle);
extern Shishi_asn1 shishi_asn1_apreq (Shishi * handle);
extern Shishi_asn1 shishi_asn1_aprep (Shishi * handle);
extern Shishi_asn1 shishi_asn1_ticket (Shishi * handle);
extern Shishi_asn1 shishi_asn1_encapreppart (Shishi * handle);
extern Shishi_asn1 shishi_asn1_encticketpart (Shishi * handle);
extern Shishi_asn1 shishi_asn1_authenticator (Shishi * handle);
extern Shishi_asn1 shishi_asn1_enckdcreppart (Shishi * handle);
extern Shishi_asn1 shishi_asn1_encasreppart (Shishi * handle);
extern Shishi_asn1 shishi_asn1_krberror (Shishi * handle);
extern Shishi_asn1 shishi_asn1_krbsafe (Shishi * handle);
extern Shishi_asn1 shishi_asn1_priv (Shishi * handle);
extern Shishi_asn1 shishi_asn1_encprivpart (Shishi * handle);

extern int shishi_asn1_to_der (Shishi * handle, Shishi_asn1 node,
			       char **der, size_t * len);
extern int shishi_asn1_to_der_field (Shishi * handle, Shishi_asn1 node,
				     const char *field,
				     char **der, size_t * len);

extern Shishi_msgtype shishi_asn1_msgtype (Shishi * handle, Shishi_asn1 node);
extern Shishi_msgtype shishi_der_msgtype (Shishi * handle,
					  const char *der, size_t derlen);

extern void shishi_asn1_print (Shishi * handle, Shishi_asn1 node, FILE * fh);

extern Shishi_asn1 shishi_der2asn1 (Shishi * handle,
				    const char *der, size_t derlen);
extern Shishi_asn1 shishi_der2asn1_padata (Shishi * handle,
					   const char *der, size_t derlen);
extern Shishi_asn1 shishi_der2asn1_methoddata (Shishi * handle,
					       const char *der, size_t derlen);
extern Shishi_asn1 shishi_der2asn1_etype_info (Shishi * handle,
					       const char *der,
					       size_t derlen);
extern Shishi_asn1 shishi_der2asn1_etype_info2 (Shishi * handle,
						const char *der,
						size_t derlen);
extern Shishi_asn1 shishi_der2asn1_ticket (Shishi * handle,
					   const char *der, size_t derlen);
extern Shishi_asn1 shishi_der2asn1_encticketpart (Shishi * handle,
						  const char *der,
						  size_t derlen);
extern Shishi_asn1 shishi_der2asn1_asreq (Shishi * handle,
					  const char *der, size_t derlen);
extern Shishi_asn1 shishi_der2asn1_tgsreq (Shishi * handle,
					   const char *der, size_t derlen);
extern Shishi_asn1 shishi_der2asn1_asrep (Shishi * handle,
					  const char *der, size_t derlen);
extern Shishi_asn1 shishi_der2asn1_tgsrep (Shishi * handle,
					   const char *der, size_t derlen);
extern Shishi_asn1 shishi_der2asn1_kdcrep (Shishi * handle,
					   const char *der, size_t derlen);
extern Shishi_asn1 shishi_der2asn1_kdcreq (Shishi * handle,
					   const char *der, size_t derlen);
extern Shishi_asn1 shishi_der2asn1_apreq (Shishi * handle,
					  const char *der, size_t derlen);
extern Shishi_asn1 shishi_der2asn1_aprep (Shishi * handle,
					  const char *der, size_t derlen);
extern Shishi_asn1 shishi_der2asn1_authenticator (Shishi * handle,
						  const char *der,
						  size_t derlen);
extern Shishi_asn1 shishi_der2asn1_krberror (Shishi * handle,
					     const char *der, size_t derlen);
extern Shishi_asn1 shishi_der2asn1_krbsafe (Shishi * handle,
					    const char *der, size_t derlen);
extern Shishi_asn1 shishi_der2asn1_priv (Shishi * handle,
					 const char *der, size_t derlen);
extern Shishi_asn1 shishi_der2asn1_encasreppart (Shishi * handle,
						 const char *der,
						 size_t derlen);
extern Shishi_asn1 shishi_der2asn1_enctgsreppart (Shishi * handle,
						  const char *der,
						  size_t derlen);
extern Shishi_asn1 shishi_der2asn1_enckdcreppart (Shishi * handle,
						  const char *der,
						  size_t derlen);
extern Shishi_asn1 shishi_der2asn1_encapreppart (Shishi * handle,
						 const char *der,
						 size_t derlen);
extern Shishi_asn1 shishi_der2asn1_encprivpart (Shishi * handle,
						const char *der,
						size_t derlen);

/* ap.c */
extern int shishi_ap (Shishi * handle, Shishi_ap ** ap);
extern int shishi_ap_etype (Shishi * handle, Shishi_ap ** ap, int etype);
extern int shishi_ap_nosubkey (Shishi * handle, Shishi_ap ** ap);
extern void shishi_ap_done (Shishi_ap * ap);
extern int shishi_ap_set_tktoptions (Shishi_ap * ap,
				     Shishi_tkt * tkt, int options);
extern int shishi_ap_tktoptions (Shishi * handle,
				 Shishi_ap ** ap,
				 Shishi_tkt * tkt, int options);
extern int shishi_ap_etype_tktoptionsdata (Shishi * handle,
					   Shishi_ap ** ap,
					   int32_t etype,
					   Shishi_tkt * tkt, int options,
					   const char *data, size_t len);
extern int shishi_ap_set_tktoptionsdata (Shishi_ap * ap,
					 Shishi_tkt * tkt,
					 int options,
					 const char *data, size_t len);
extern int shishi_ap_tktoptionsdata (Shishi * handle,
				     Shishi_ap ** ap,
				     Shishi_tkt * tkt,
				     int options,
				     const char *data, size_t len);
extern int shishi_ap_set_tktoptionsraw (Shishi_ap * ap,
					Shishi_tkt * tkt,
					int options,
					int32_t cksumtype,
					const char *data, size_t len);
extern int shishi_ap_tktoptionsraw (Shishi * handle,
				    Shishi_ap ** ap,
				    Shishi_tkt * tkt, int options,
				    int32_t cksumtype,
				    const char *data, size_t len);
extern int shishi_ap_set_tktoptionsasn1usage (Shishi_ap * ap,
					      Shishi_tkt * tkt,
					      int options,
					      Shishi_asn1 node,
					      const char *field,
					      int authenticatorcksumkeyusage,
					      int authenticatorkeyusage);
extern int shishi_ap_tktoptionsasn1usage (Shishi * handle,
					  Shishi_ap ** ap,
					  Shishi_tkt * tkt,
					  int options,
					  Shishi_asn1 node,
					  const char *field,
					  int authenticatorcksumkeyusage,
					  int authenticatorkeyusage);

extern Shishi_tkt *shishi_ap_tkt (Shishi_ap * ap);
extern void shishi_ap_tkt_set (Shishi_ap * ap, Shishi_tkt * tkt);

extern int shishi_ap_authenticator_cksumdata (Shishi_ap * ap,
					      char *out, size_t * len);
extern void
shishi_ap_authenticator_cksumdata_set (Shishi_ap * ap,
				       const char *authenticatorcksumdata,
				       size_t authenticatorcksumdatalen);
extern void
shishi_ap_authenticator_cksumraw_set (Shishi_ap * ap,
				      int32_t authenticatorcksumtype,
				      const char *authenticatorcksumraw,
				      size_t authenticatorcksumrawlen);
extern int32_t shishi_ap_authenticator_cksumtype (Shishi_ap * ap);
extern void shishi_ap_authenticator_cksumtype_set (Shishi_ap * ap,
						   int32_t cksumtype);

extern Shishi_asn1 shishi_ap_authenticator (Shishi_ap * ap);
extern void shishi_ap_authenticator_set (Shishi_ap * ap,
					 Shishi_asn1 authenticator);

extern Shishi_asn1 shishi_ap_req (Shishi_ap * ap);
extern void shishi_ap_req_set (Shishi_ap * ap, Shishi_asn1 apreq);
extern int shishi_ap_req_der (Shishi_ap * ap, char **out, size_t * outlen);
extern int shishi_ap_req_der_set (Shishi_ap * ap, char *der, size_t derlen);
extern int shishi_ap_req_build (Shishi_ap * ap);
extern int shishi_ap_req_asn1 (Shishi_ap * ap, Shishi_asn1 * apreq);
extern Shishi_key *shishi_ap_key (Shishi_ap * ap);
extern int shishi_ap_req_decode (Shishi_ap * ap);
extern int shishi_ap_req_process (Shishi_ap * ap, Shishi_key * key);
extern int shishi_ap_req_process_keyusage (Shishi_ap * ap,
					   Shishi_key * key,
					   int32_t keyusage);

extern Shishi_asn1 shishi_ap_rep (Shishi_ap * ap);
extern void shishi_ap_rep_set (Shishi_ap * ap, Shishi_asn1 aprep);
extern int shishi_ap_rep_der (Shishi_ap * ap, char **out, size_t * outlen);
extern int shishi_ap_rep_der_set (Shishi_ap * ap, char *der, size_t derlen);
extern int shishi_ap_rep_verify (Shishi_ap * ap);
extern int shishi_ap_rep_verify_der (Shishi_ap * ap, char *der,
				     size_t derlen);
extern int shishi_ap_rep_verify_asn1 (Shishi_ap * ap, Shishi_asn1 aprep);
extern int shishi_ap_rep_asn1 (Shishi_ap * ap, Shishi_asn1 * aprep);
extern int shishi_ap_rep_build (Shishi_ap * ap);

extern Shishi_asn1 shishi_ap_encapreppart (Shishi_ap * ap);
extern void shishi_ap_encapreppart_set (Shishi_ap * ap,
					Shishi_asn1 encapreppart);

extern const char *shishi_ap_option2string (Shishi_apoptions option);
extern Shishi_apoptions shishi_ap_string2option (const char *str);

/* key.c */
extern const char *shishi_key_principal (const Shishi_key * key);
extern void shishi_key_principal_set (Shishi_key * key,
				      const char *principal);
extern const char *shishi_key_realm (const Shishi_key * key);
extern void shishi_key_realm_set (Shishi_key * key, const char *realm);
extern int shishi_key_type (const Shishi_key * key);
extern void shishi_key_type_set (Shishi_key * key, int32_t type);
extern const char *shishi_key_value (const Shishi_key * key);
extern void shishi_key_value_set (Shishi_key * key, const char *value);
extern const char *shishi_key_name (Shishi_key * key);
extern size_t shishi_key_length (const Shishi_key * key);
extern uint32_t shishi_key_version (const Shishi_key * key);
extern void shishi_key_version_set (Shishi_key * key, uint32_t kvno);
extern int shishi_key (Shishi * handle, Shishi_key ** key);
extern void shishi_key_done (Shishi_key * key);
extern void shishi_key_copy (Shishi_key * dstkey, Shishi_key * srckey);
extern int shishi_key_print (Shishi * handle, FILE * fh,
			     const Shishi_key * key);
extern int shishi_key_to_file (Shishi * handle,
			       const char *filename, Shishi_key * key);
extern int shishi_key_parse (Shishi * handle, FILE * fh, Shishi_key ** key);
extern int shishi_key_random (Shishi * handle,
			      int32_t type, Shishi_key ** key);
extern int shishi_key_from_value (Shishi * handle,
				  int32_t type,
				  const char *value, Shishi_key ** key);
extern int shishi_key_from_base64 (Shishi * handle,
				   int32_t type,
				   const char *value, Shishi_key ** key);
extern int shishi_key_from_random (Shishi * handle,
				   int32_t type,
				   const char *rnd,
				   size_t rndlen, Shishi_key ** outkey);
extern int shishi_key_from_string (Shishi * handle,
				   int32_t type,
				   const char *password, size_t passwordlen,
				   const char *salt, size_t saltlen,
				   const char *parameter,
				   Shishi_key ** outkey);
extern int shishi_key_from_name (Shishi * handle,
				 int32_t type,
				 const char *name,
				 const char *password, size_t passwordlen,
				 const char *parameter,
				 Shishi_key ** outkey);

/* keys.c */
extern int shishi_keys (Shishi * handle, Shishi_keys ** keys);
extern void shishi_keys_done (Shishi_keys ** keys);
extern int shishi_keys_size (Shishi_keys * keys);
extern const Shishi_key *shishi_keys_nth (Shishi_keys * keys, int keyno);
extern void shishi_keys_remove (Shishi_keys * keys, int keyno);
extern int shishi_keys_add (Shishi_keys * keys, Shishi_key * key);

extern int shishi_keys_add_keytab_mem (Shishi * handle,
				       const char *data, size_t len,
				       Shishi_keys *keys);
extern int shishi_keys_add_keytab_file (Shishi * handle,
					const char *filename,
					Shishi_keys *keys);
extern int shishi_keys_from_keytab_mem (Shishi * handle,
					const char *data, size_t len,
					Shishi_keys **outkeys);
extern int shishi_keys_from_keytab_file (Shishi * handle,
					 const char *filename,
					 Shishi_keys **outkeys);

extern int shishi_keys_print (Shishi_keys * keys, FILE *fh);
extern int shishi_keys_to_file (Shishi * handle,
				const char *filename,
				Shishi_keys * keys);

extern Shishi_key *shishi_keys_for_serverrealm_in_file (Shishi * handle,
							const char *filename,
							const char *server,
							const char *realm);
extern Shishi_key *shishi_keys_for_server_in_file (Shishi * handle,
						   const char *filename,
						   const char *server);
extern Shishi_key *shishi_keys_for_localservicerealm_in_file (Shishi * handle,
							      const char
							      *filename,
							      const char
							      *service,
							      const char
							      *realm);

/* hostkeys.c */
extern const char *shishi_hostkeys_default_file (Shishi * handle);
extern void shishi_hostkeys_default_file_set (Shishi * handle,
					      const char *hostkeysfile);
extern Shishi_key *shishi_hostkeys_for_server (Shishi * handle,
					       const char *server);
extern Shishi_key *shishi_hostkeys_for_serverrealm (Shishi * handle,
						    const char *server,
						    const char *realm);
extern Shishi_key *shishi_hostkeys_for_localservicerealm (Shishi * handle,
							  const char *service,
							  const char *realm);
extern Shishi_key *shishi_hostkeys_for_localservice (Shishi * handle,
						     const char *service);

/* encapreppart.c */
extern Shishi_asn1 shishi_encapreppart (Shishi * handle);
extern int shishi_encapreppart_time_copy (Shishi * handle,
					  Shishi_asn1 encapreppart,
					  Shishi_asn1 authenticator);
extern int shishi_encapreppart_ctime (Shishi * handle,
				      Shishi_asn1 encapreppart, char **t);
extern int shishi_encapreppart_ctime_set (Shishi * handle,
					  Shishi_asn1 encapreppart,
					  const char *t);
extern int shishi_encapreppart_cusec_get (Shishi * handle,
					  Shishi_asn1 encapreppart,
					  uint32_t * cusec);
extern int shishi_encapreppart_cusec_set (Shishi * handle,
					  Shishi_asn1 encapreppart,
					  uint32_t cusec);
extern int shishi_encapreppart_print (Shishi * handle, FILE * fh,
				      Shishi_asn1 encapreppart);
extern int shishi_encapreppart_save (Shishi * handle, FILE * fh,
				     Shishi_asn1 encapreppart);
extern int shishi_encapreppart_to_file (Shishi * handle,
					Shishi_asn1 encapreppart,
					int filetype, const char *filename);
extern int shishi_encapreppart_read (Shishi * handle, FILE * fh,
				     Shishi_asn1 * encapreppart);
extern int shishi_encapreppart_parse (Shishi * handle, FILE * fh,
				      Shishi_asn1 * encapreppart);
extern int shishi_encapreppart_from_file (Shishi * handle,
					  Shishi_asn1 * encapreppart,
					  int filetype, const char *filename);
extern int shishi_encapreppart_get_key (Shishi * handle,
					Shishi_asn1 encapreppart,
					Shishi_key ** key);
extern int shishi_encapreppart_seqnumber_get (Shishi * handle,
					      Shishi_asn1 encapreppart,
					      uint32_t * seqnumber);
extern int shishi_encapreppart_seqnumber_remove (Shishi * handle,
						 Shishi_asn1 encapreppart);
extern int shishi_encapreppart_seqnumber_set (Shishi * handle,
					      Shishi_asn1 encapreppart,
					      uint32_t seqnumber);

/* apreq.c */
extern Shishi_asn1 shishi_apreq (Shishi * handle);
extern int shishi_apreq_parse (Shishi * handle, FILE * fh,
			       Shishi_asn1 * apreq);
extern int shishi_apreq_from_file (Shishi * handle, Shishi_asn1 * apreq,
				   int filetype, const char *filename);
extern int shishi_apreq_print (Shishi * handle, FILE * fh, Shishi_asn1 apreq);
extern int shishi_apreq_to_file (Shishi * handle, Shishi_asn1 apreq,
				 int filetype, const char *filename);
extern int shishi_apreq_read (Shishi * handle, FILE * fh,
			      Shishi_asn1 * apreq);
extern int shishi_apreq_save (Shishi * handle, FILE * fh, Shishi_asn1 apreq);
extern int shishi_apreq_set_ticket (Shishi * handle, Shishi_asn1 apreq,
				    Shishi_asn1 ticket);
extern int shishi_apreq_set_authenticator (Shishi * handle, Shishi_asn1 apreq,
					   int32_t etype, uint32_t kvno,
					   const char *buf, size_t buflen);
extern int shishi_apreq_add_authenticator (Shishi * handle, Shishi_asn1 apreq,
					   Shishi_key * key, int keyusage,
					   Shishi_asn1 authenticator);
extern int shishi_apreq_options (Shishi * handle, Shishi_asn1 apreq,
				 uint32_t * flags);
extern int shishi_apreq_use_session_key_p (Shishi * handle,
					   Shishi_asn1 apreq);
extern int shishi_apreq_mutual_required_p (Shishi * handle,
					   Shishi_asn1 apreq);
extern int shishi_apreq_options_set (Shishi * handle, Shishi_asn1 apreq,
				     uint32_t options);
extern int shishi_apreq_options_add (Shishi * handle, Shishi_asn1 apreq,
				     uint32_t option);
extern int shishi_apreq_options_remove (Shishi * handle, Shishi_asn1 apreq,
					uint32_t option);
extern int shishi_apreq_get_ticket (Shishi * handle, Shishi_asn1 apreq,
				    Shishi_asn1 * ticket);
extern int shishi_apreq_get_authenticator_etype (Shishi * handle,
						 Shishi_asn1 apreq,
						 int32_t * etype);
extern int shishi_apreq_decrypt (Shishi * handle, Shishi_asn1 apreq,
				 Shishi_key * key, int keyusage,
				 Shishi_asn1 * authenticator);

/* aprep.c */
extern Shishi_asn1 shishi_aprep (Shishi * handle);
extern int shishi_aprep_print (Shishi * handle, FILE * fh, Shishi_asn1 aprep);
extern int shishi_aprep_save (Shishi * handle, FILE * fh, Shishi_asn1 aprep);
extern int shishi_aprep_to_file (Shishi * handle, Shishi_asn1 aprep,
				 int filetype, const char *filename);
extern int shishi_aprep_read (Shishi * handle, FILE * fh,
			      Shishi_asn1 * aprep);
extern int shishi_aprep_parse (Shishi * handle, FILE * fh,
			       Shishi_asn1 * aprep);
extern int shishi_aprep_from_file (Shishi * handle, Shishi_asn1 * aprep,
				   int filetype, const char *filename);
extern int shishi_aprep_decrypt (Shishi * handle, Shishi_asn1 aprep,
				 Shishi_key * key, int keyusage,
				 Shishi_asn1 * encapreppart);
extern int shishi_aprep_verify (Shishi * handle, Shishi_asn1 authenticator,
				Shishi_asn1 encapreppart);
extern int shishi_aprep_enc_part_set (Shishi * handle, Shishi_asn1 aprep,
				      int etype,
				      const char *buf, size_t buflen);
extern int shishi_aprep_enc_part_add (Shishi * handle, Shishi_asn1 aprep,
				      Shishi_asn1 encticketpart,
				      Shishi_asn1 encapreppart);
extern int shishi_aprep_enc_part_make (Shishi * handle, Shishi_asn1 aprep,
				       Shishi_asn1 encapreppart,
				       Shishi_asn1 authenticator,
				       Shishi_asn1 encticketpart);
extern int shishi_aprep_get_enc_part_etype (Shishi * handle,
					    Shishi_asn1 aprep,
					    int32_t * etype);

/* netio.c */
extern int shishi_kdc_sendrecv (Shishi * handle, char *realm,
				const char *indata, size_t inlen,
				char **outdata, size_t * outlen);
extern int shishi_kdc_sendrecv_hint (Shishi * handle, char *realm,
				     const char *indata, size_t inlen,
				     char **outdata, size_t * outlen,
				     Shishi_tkts_hint * hint);

/* encticketpart.c */
extern Shishi_asn1 shishi_encticketpart (Shishi * handle);
extern int shishi_encticketpart_key_set (Shishi * handle,
					 Shishi_asn1 encticketpart,
					 Shishi_key * key);
extern int shishi_encticketpart_get_key (Shishi * handle,
					 Shishi_asn1 encticketpart,
					 Shishi_key ** key);
extern int shishi_encticketpart_crealm (Shishi * handle,
					Shishi_asn1 encticketpart,
					char **crealm, size_t * crealmlen);
extern int shishi_encticketpart_crealm_set (Shishi * handle,
					    Shishi_asn1 encticketpart,
					    const char *realm);
extern int shishi_encticketpart_client (Shishi * handle,
					Shishi_asn1 encticketpart,
					char **client, size_t * clientlen);
extern int shishi_encticketpart_clientrealm (Shishi * handle,
					     Shishi_asn1 encticketpart,
					     char **client, size_t *clientlen);
extern int shishi_encticketpart_cname_set (Shishi * handle,
					   Shishi_asn1 encticketpart,
					   Shishi_name_type name_type,
					   const char *principal);
extern int shishi_encticketpart_print (Shishi * handle, FILE * fh,
				       Shishi_asn1 encticketpart);
extern int shishi_encticketpart_flags_set (Shishi * handle,
					   Shishi_asn1 encticketpart,
					   int flags);
extern int shishi_encticketpart_transited_set (Shishi * handle,
					       Shishi_asn1 encticketpart,
					       int32_t trtype,
					       const char *trdata,
					       size_t trdatalen);
extern int shishi_encticketpart_authtime_set (Shishi * handle,
					      Shishi_asn1 encticketpart,
					      const char *authtime);
extern int shishi_encticketpart_endtime_set (Shishi * handle,
					     Shishi_asn1 encticketpart,
					     const char *endtime);
extern int shishi_encticketpart_authtime (Shishi * handle,
					  Shishi_asn1 encticketpart,
					  char *authtime,
					  size_t * authtimelen);
extern time_t shishi_encticketpart_authctime (Shishi * handle,
					      Shishi_asn1 encticketpart);

/* safe.c */
extern int shishi_safe (Shishi * handle, Shishi_safe ** safe);
extern void shishi_safe_done (Shishi_safe * safe);
extern Shishi_key *shishi_safe_key (Shishi_safe * safe);
extern void shishi_safe_key_set (Shishi_safe * safe, Shishi_key * key);
extern Shishi_asn1 shishi_safe_safe (Shishi_safe * safe);
extern void shishi_safe_safe_set (Shishi_safe * safe, Shishi_asn1 asn1safe);
extern int shishi_safe_safe_der (Shishi_safe * safe, char **out,
				 size_t * outlen);
extern int shishi_safe_safe_der_set (Shishi_safe * safe,
				     char *der, size_t derlen);
extern int shishi_safe_print (Shishi * handle, FILE * fh, Shishi_asn1 safe);
extern int shishi_safe_save (Shishi * handle, FILE * fh, Shishi_asn1 safe);
extern int shishi_safe_to_file (Shishi * handle, Shishi_asn1 safe,
				int filetype, const char *filename);
extern int shishi_safe_parse (Shishi * handle, FILE * fh, Shishi_asn1 * safe);
extern int shishi_safe_read (Shishi * handle, FILE * fh, Shishi_asn1 * safe);
extern int shishi_safe_from_file (Shishi * handle, Shishi_asn1 * safe,
				  int filetype, const char *filename);
extern int shishi_safe_cksum (Shishi * handle,
			      Shishi_asn1 safe,
			      int32_t * cksumtype,
			      char **cksum, size_t * cksumlen);
extern int shishi_safe_set_cksum (Shishi * handle,
				  Shishi_asn1 safe,
				  int32_t cksumtype,
				  const char *cksum, size_t cksumlen);
extern int shishi_safe_user_data (Shishi * handle,
				  Shishi_asn1 safe,
				  char **userdata, size_t * userdatalen);
extern int shishi_safe_set_user_data (Shishi * handle,
				      Shishi_asn1 safe,
				      const char *userdata,
				      size_t userdatalen);
extern int shishi_safe_build (Shishi_safe * safe, Shishi_key * key);
extern int shishi_safe_verify (Shishi_safe * safe, Shishi_key * key);

/* priv.c */
extern int shishi_priv (Shishi * handle, Shishi_priv ** priv);
extern void shishi_priv_done (Shishi_priv * priv);
extern Shishi_key *shishi_priv_key (Shishi_priv * priv);
extern void shishi_priv_key_set (Shishi_priv * priv, Shishi_key * key);
extern Shishi_asn1 shishi_priv_priv (Shishi_priv * priv);
extern void shishi_priv_priv_set (Shishi_priv * priv, Shishi_asn1 asn1priv);
extern int shishi_priv_priv_der (Shishi_priv * priv, char **out,
				 size_t * outlen);
extern int shishi_priv_priv_der_set (Shishi_priv * priv,
				     char *der, size_t derlen);
extern Shishi_asn1 shishi_priv_encprivpart (Shishi_priv * priv);
extern void shishi_priv_encprivpart_set (Shishi_priv * priv,
					 Shishi_asn1 asn1encprivpart);
extern int shishi_priv_encprivpart_der (Shishi_priv * priv, char **out,
					size_t * outlen);
extern int shishi_priv_encprivpart_der_set (Shishi_priv * priv,
					    char *der, size_t derlen);
extern int shishi_priv_print (Shishi * handle, FILE * fh, Shishi_asn1 priv);
extern int shishi_priv_save (Shishi * handle, FILE * fh, Shishi_asn1 priv);
extern int shishi_priv_to_file (Shishi * handle, Shishi_asn1 priv,
				int filetype, const char *filename);
extern int shishi_priv_parse (Shishi * handle, FILE * fh, Shishi_asn1 * priv);
extern int shishi_priv_read (Shishi * handle, FILE * fh, Shishi_asn1 * priv);
extern int shishi_priv_from_file (Shishi * handle, Shishi_asn1 * priv,
				  int filetype, const char *filename);
extern int shishi_priv_enc_part_etype (Shishi * handle,
				       Shishi_asn1 priv, int32_t * etype);
extern int shishi_priv_set_enc_part (Shishi * handle,
				     Shishi_asn1 priv,
				     int32_t etype,
				     const char *encpart, size_t encpartlen);
extern int shishi_encprivpart_user_data (Shishi * handle,
					 Shishi_asn1 encprivpart,
					 char **userdata,
					 size_t * userdatalen);
extern int shishi_encprivpart_set_user_data (Shishi * handle,
					     Shishi_asn1 encprivpart,
					     const char *userdata,
					     size_t userdatalen);
extern int shishi_priv_build (Shishi_priv * priv, Shishi_key * key);
extern int shishi_priv_process (Shishi_priv * priv, Shishi_key * key);

/* authorize.c */
extern int shishi_authorized_p (Shishi * handle,
				Shishi_tkt * tkt, const char *authzname);
extern int shishi_authorization_parse (const char *authorization);
extern int shishi_authorize_strcmp (Shishi * handle, const char *principal,
				    const char *authzname);
extern int shishi_authorize_k5login (Shishi * handle, const char *principal,
				     const char *authzname);

/* pki.c */
extern char *shishi_x509ca_default_file_guess (Shishi * handle);
extern void shishi_x509ca_default_file_set (Shishi * handle,
					    const char *x509cafile);
extern const char *shishi_x509ca_default_file (Shishi * handle);
extern char *shishi_x509cert_default_file_guess (Shishi * handle);
extern void shishi_x509cert_default_file_set (Shishi * handle,
					      const char *x509certfile);
extern const char *shishi_x509cert_default_file (Shishi * handle);
extern char *shishi_x509key_default_file_guess (Shishi * handle);
extern void shishi_x509key_default_file_set (Shishi * handle,
					     const char *x509keyfile);
extern const char *shishi_x509key_default_file (Shishi * handle);

/* utils.c */
extern time_t shishi_get_date (const char *p, const time_t * now);
/* Ugly hack to avoid re-declaring shishi_xalloc_die twice.  It is
   already declared in xalloc.h internally in Shishi.h.  This is to
   keep being able to use -Wredundant-decls. */
#if defined(SYSTEMCFGFILE) && !defined(XALLOC_H_)
extern void shishi_xalloc_die (void) __attribute__ ((__noreturn__));
#endif

/* resolv.c */
extern Shishi_dns shishi_resolv (const char *zone, uint16_t querytype);
extern void shishi_resolv_free (Shishi_dns rrs);

# ifdef __cplusplus
}
# endif

#endif
