/* asn1.c	utilities to extract data from RFC 1510 ASN.1 types
 * Copyright (C) 2002  Simon Josefsson
 *
 * This file is part of Shishi.
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
 * License along with Shishi; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "internal.h"

int
_shishi_a2d_field (Shishi *handle,
		   ASN1_TYPE node, char *field,
		   char *der, int *len)
{
  char errorDescription[MAX_ERROR_DESCRIPTION_SIZE];
  int rc;

  rc = asn1_der_coding (node, field, der, len, errorDescription);
  if (rc != ASN1_SUCCESS)
    return SHISHI_ASN1_ERROR;

  return SHISHI_OK;
}

int
_shishi_a2d (Shishi *handle, ASN1_TYPE node, char *der, int *len)
{
  return _shishi_a2d_field (handle, node, node->name, der, len);
}

int
_shishi_asn1_done (Shishi * handle, ASN1_TYPE node)
{

  int rc;

  rc = asn1_delete_structure(&node);
  if (rc != ASN1_SUCCESS)
    {
      shishi_error_set (handle, libtasn1_strerror (rc));
      return SHISHI_ASN1_ERROR;
    }

  return SHISHI_OK;
}


int
_shishi_asn1_field (Shishi * handle,
		    ASN1_TYPE node, char *data, int *datalen, char *field)
{
  int rc;

  rc = asn1_read_value (node, field, data, datalen);
  if (rc != ASN1_SUCCESS)
    {
      shishi_error_set (handle, libtasn1_strerror (rc));
      return SHISHI_ASN1_ERROR;
    }

  return SHISHI_OK;
}

int
_shishi_asn1_optional_field (Shishi * handle,
			     ASN1_TYPE node,
			     char *data, int *datalen, char *field)
{
  int rc;

  rc = asn1_read_value (node, field, data, datalen);
  if (rc != ASN1_SUCCESS && rc != ASN1_ELEMENT_NOT_FOUND)
    {
      shishi_error_set (handle, libtasn1_strerror (rc));
      return SHISHI_ASN1_ERROR;
    }

  if (rc == ASN1_ELEMENT_NOT_FOUND)
    *datalen = 0;

  return SHISHI_OK;
}

int
_shishi_asn1_integer_field (Shishi * handle, ASN1_TYPE node,
			    int *i, char *field)
{
  unsigned char buf[4];
  int buflen;
  int rc;

  memset (buf, 0, sizeof (buf));
  buflen = sizeof (buf);
  rc = asn1_read_value (node, field, buf, &buflen);
  if (rc != ASN1_SUCCESS)
    {
      shishi_error_set (handle, libtasn1_strerror (rc));
      return SHISHI_ASN1_ERROR;
    }

  *i = buf[0] | buf[1] << 8 | buf[2] << 16 | buf[3] << 24;

  return SHISHI_OK;
}


#define SHISHI_TICKET_DEFAULT_TKTVNO "5"
#define SHISHI_TICKET_DEFAULT_TKTVNO_LEN 0

ASN1_TYPE
shishi_asn1_ticket (Shishi * handle)
{
  int res = ASN1_SUCCESS;
  ASN1_TYPE node = ASN1_TYPE_EMPTY;

  res = asn1_create_element (handle->asn1, "Kerberos5.Ticket",
			     &node, "Ticket");
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (node, "Ticket.tkt-vno",
			  SHISHI_TICKET_DEFAULT_TKTVNO,
			  SHISHI_TICKET_DEFAULT_TKTVNO_LEN);
  if (res != ASN1_SUCCESS)
    goto error;

  return node;

error:
  shishi_error_set (handle, libtasn1_strerror (res));
  if (node != ASN1_TYPE_EMPTY)
    asn1_delete_structure (&node);
  return NULL;
}

ASN1_TYPE
shishi_asn1_encticketpart (Shishi * handle)
{
  int res = ASN1_SUCCESS;
  ASN1_TYPE node = ASN1_TYPE_EMPTY;

  res = asn1_create_element (handle->asn1, "Kerberos5.EncTicketPart",
			     &node, "EncTicketPart");
  if (res != ASN1_SUCCESS)
    goto error;

  return node;

error:
  shishi_error_set (handle, libtasn1_strerror (res));
  if (node != ASN1_TYPE_EMPTY)
    asn1_delete_structure (&node);
  return NULL;
}

/** shishi_der2asn1_ticket

name:Ticket  type:SEQUENCE
  name:tkt-vno  type:INTEGER
  name:realm  type:IDENTIFIER  value:Realm
  name:sname  type:IDENTIFIER  value:PrincipalName
  name:enc-part  type:IDENTIFIER  value:EncryptedData
*/
ASN1_TYPE
shishi_der2asn1_ticket (ASN1_TYPE definitions,
			char *der, int der_len, char *errorDescription)
{
  ASN1_TYPE structure = ASN1_TYPE_EMPTY;
  int asn1_result = ASN1_SUCCESS;

  asn1_result = asn1_create_element (definitions,
				     "Kerberos5.Ticket",
				     &structure, "Ticket");
  if (asn1_result != ASN1_SUCCESS)
    {
      strcpy (errorDescription, libtasn1_strerror (asn1_result));
      return ASN1_TYPE_EMPTY;
    }

  asn1_result = asn1_der_decoding (&structure,
				   der, der_len, errorDescription);
  if (asn1_result != ASN1_SUCCESS)
    {
      asn1_delete_structure (&structure);
      return ASN1_TYPE_EMPTY;
    }

  return structure;
}

ASN1_TYPE
shishi_d2a_ticket (Shishi * handle, char *der,
		   int derlen, char *errorDescription)
{
  ASN1_TYPE ticket;

  ticket = shishi_der2asn1_ticket (handle->asn1, der,
				   derlen, errorDescription);
  if (ticket == ASN1_TYPE_EMPTY)
    fprintf (stdout, "Could not DER deocde Ticket\n");

  return ticket;
}

/** shishi_der2asn1_encticketpart

-- Encrypted part of ticket
EncTicketPart   ::= [APPLICATION 3] SEQUENCE {
        flags                   [0] TicketFlags,
        key                     [1] EncryptionKey,
        crealm                  [2] Realm,
        cname                   [3] PrincipalName,
        transited               [4] TransitedEncoding,
        authtime                [5] KerberosTime,
        starttime               [6] KerberosTime OPTIONAL,
        endtime                 [7] KerberosTime,
        renew-till              [8] KerberosTime OPTIONAL,
        caddr                   [9] HostAddresses OPTIONAL,
        authorization-data      [10] AuthorizationData OPTIONAL
}
*/
ASN1_TYPE
shishi_der2asn1_encticketpart (ASN1_TYPE definitions,
			       char *der, int der_len, char *errorDescription)
{
  ASN1_TYPE structure = ASN1_TYPE_EMPTY;
  int asn1_result = ASN1_SUCCESS;

  asn1_result = asn1_create_element (definitions,
				     "Kerberos5.EncTicketPart",
				     &structure, "EncTicketPart");
  if (asn1_result != ASN1_SUCCESS)
    {
      strcpy (errorDescription, libtasn1_strerror (asn1_result));
      return ASN1_TYPE_EMPTY;
    }

  asn1_result = asn1_der_decoding (&structure,
				   der, der_len, errorDescription);
  if (asn1_result != ASN1_SUCCESS)
    {
      asn1_delete_structure (&structure);
      return ASN1_TYPE_EMPTY;
    }

  return structure;
}

ASN1_TYPE
shishi_d2a_encticketpart (Shishi * handle, char *der,
			  int derlen, char *errorDescription)
{
  ASN1_TYPE encticketpart;

  encticketpart = shishi_der2asn1_encticketpart (handle->asn1, der,
						 derlen, errorDescription);
  if (encticketpart == ASN1_TYPE_EMPTY)
    fprintf (stdout, "Could not DER deocde Ticket\n");

  return encticketpart;
}

/** shishi_der2asn1_krb_error

name:KRB-ERROR  type:SEQUENCE
  name:pvno  type:INTEGER
  name:msg-type  type:INTEGER
  name:ctime  type:IDENTIFIER  value:KerberosTime
  name:cusec  type:INTEGER
  name:stime  type:IDENTIFIER  value:KerberosTime
  name:susec  type:INTEGER
  name:error-code  type:INTEGER
  name:crealm  type:IDENTIFIER  value:Realm
  name:cname  type:IDENTIFIER  value:PrincipalName
  name:realm  type:IDENTIFIER  value:Realm
  name:sname  type:IDENTIFIER  value:PrincipalName
  name:e-text  type:GENERALSTRING
  name:e-data  type:OCT_STR
*/
ASN1_TYPE
shishi_der2asn1_krb_error (ASN1_TYPE definitions,
			   char *der, int der_len, char *errorDescription)
{
  ASN1_TYPE structure = ASN1_TYPE_EMPTY;
  int asn1_result = ASN1_SUCCESS;

  asn1_result = asn1_create_element (definitions,
				     "Kerberos5.KRB-ERROR",
				     &structure, "KRB-ERROR");
  if (asn1_result != ASN1_SUCCESS)
    {
      strcpy (errorDescription, libtasn1_strerror (asn1_result));
      return ASN1_TYPE_EMPTY;
    }

  asn1_result = asn1_der_decoding (&structure,
				   der, der_len, errorDescription);
  if (asn1_result != ASN1_SUCCESS)
    {
      asn1_delete_structure (&structure);
      return ASN1_TYPE_EMPTY;
    }

  return structure;
}

/** shishi_der2asn1_as_req

name:AS-REQ  type:IDENTIFIER  value:KDC-REQ
*/
ASN1_TYPE
shishi_der2asn1_as_req (ASN1_TYPE definitions,
			char *der, int der_len, char *errorDescription)
{
  ASN1_TYPE structure = ASN1_TYPE_EMPTY;
  int asn1_result = ASN1_SUCCESS;

  asn1_result = asn1_create_element (definitions,
				     "Kerberos5.AS-REQ",
				     &structure, "KDC-REQ");
  if (asn1_result != ASN1_SUCCESS)
    {
      strcpy (errorDescription, libtasn1_strerror (asn1_result));
      return ASN1_TYPE_EMPTY;
    }

  asn1_result = asn1_der_decoding (&structure,
				   der, der_len, errorDescription);
  if (asn1_result != ASN1_SUCCESS)
    {
      asn1_delete_structure (&structure);
      return ASN1_TYPE_EMPTY;
    }

  return structure;
}

/** shishi_der2asn1_tgs_req

name:TGS-REQ  type:IDENTIFIER  value:KDC-REQ
*/
ASN1_TYPE
shishi_der2asn1_tgs_req (ASN1_TYPE definitions,
			 char *der, int der_len, char *errorDescription)
{
  ASN1_TYPE structure = ASN1_TYPE_EMPTY;
  int asn1_result = ASN1_SUCCESS;

  asn1_result = asn1_create_element (definitions,
				     "Kerberos5.TGS-REQ",
				     &structure, "KDC-REQ");
  if (asn1_result != ASN1_SUCCESS)
    {
      strcpy (errorDescription, libtasn1_strerror (asn1_result));
      return ASN1_TYPE_EMPTY;
    }

  asn1_result = asn1_der_decoding (&structure,
				   der, der_len, errorDescription);
  if (asn1_result != ASN1_SUCCESS)
    {
      asn1_delete_structure (&structure);
      return ASN1_TYPE_EMPTY;
    }

  return structure;
}

/** shishi_der2asn1_as_rep

name:AS-REP  type:IDENTIFIER  value:KDC-REP
*/
ASN1_TYPE
shishi_der2asn1_as_rep (ASN1_TYPE definitions,
			char *der, int der_len, char *errorDescription)
{
  ASN1_TYPE structure = ASN1_TYPE_EMPTY;
  int asn1_result = ASN1_SUCCESS;

  asn1_result = asn1_create_element (definitions,
				     "Kerberos5.AS-REP",
				     &structure, "KDC-REP");
  if (asn1_result != ASN1_SUCCESS)
    {
      strcpy (errorDescription, libtasn1_strerror (asn1_result));
      return ASN1_TYPE_EMPTY;
    }

  asn1_result = asn1_der_decoding (&structure,
				   der, der_len, errorDescription);
  if (asn1_result != ASN1_SUCCESS)
    {
      asn1_delete_structure (&structure);
      return ASN1_TYPE_EMPTY;
    }

  return structure;
}

/** shishi_der2asn1_tgs_rep

name:TGS-REP  type:IDENTIFIER  value:KDC-REP
*/
ASN1_TYPE
shishi_der2asn1_tgs_rep (ASN1_TYPE definitions,
			 char *der, int der_len, char *errorDescription)
{
  ASN1_TYPE structure = ASN1_TYPE_EMPTY;
  int asn1_result = ASN1_SUCCESS;

  asn1_result = asn1_create_element (definitions,
				     "Kerberos5.TGS-REP",
				     &structure, "KDC-REP");
  if (asn1_result != ASN1_SUCCESS)
    {
      strcpy (errorDescription, libtasn1_strerror (asn1_result));
      return ASN1_TYPE_EMPTY;
    }

  asn1_result = asn1_der_decoding (&structure,
				   der, der_len, errorDescription);
  if (asn1_result != ASN1_SUCCESS)
    {
      asn1_delete_structure (&structure);
      return ASN1_TYPE_EMPTY;
    }

  return structure;
}

/** shishi_der2asn1_kdc_req

name:KDC-REQ  type:SEQUENCE
  name:pvno  type:INTEGER
  name:msg-type  type:INTEGER
  name:padata  type:SEQ_OF
    name:NULL  type:IDENTIFIER  value:PA-DATA
  name:req-body  type:IDENTIFIER  value:KDC-REQ-BODY
*/
ASN1_TYPE
shishi_der2asn1_kdc_req (ASN1_TYPE definitions,
			 char *der, int der_len, char *errorDescription)
{
  ASN1_TYPE structure = ASN1_TYPE_EMPTY;
  int asn1_result = ASN1_SUCCESS;

  asn1_result = asn1_create_element (definitions,
				     "Kerberos5.KDC-REQ",
				     &structure, "KDC-REQ");
  if (asn1_result != ASN1_SUCCESS)
    {
      strcpy (errorDescription, libtasn1_strerror (asn1_result));
      return ASN1_TYPE_EMPTY;
    }

  asn1_result = asn1_der_decoding (&structure,
				   der, der_len, errorDescription);
  if (asn1_result != ASN1_SUCCESS)
    {
      asn1_delete_structure (&structure);
      return ASN1_TYPE_EMPTY;
    }

  return structure;
}

/** shishi_der2asn1_kdc_rep

name:KDC-REP  type:SEQUENCE
  name:pvno  type:INTEGER
  name:msg-type  type:INTEGER
  name:padata  type:SEQ_OF
    name:NULL  type:IDENTIFIER  value:PA-DATA
  name:crealm  type:IDENTIFIER  value:Realm
  name:cname  type:IDENTIFIER  value:PrincipalName
  name:ticket  type:IDENTIFIER  value:Ticket
  name:enc-part  type:IDENTIFIER  value:EncryptedData
*/
ASN1_TYPE
shishi_der2asn1_kdc_rep (ASN1_TYPE definitions,
			 char *der, int der_len, char *errorDescription)
{
  ASN1_TYPE structure = ASN1_TYPE_EMPTY;
  int asn1_result = ASN1_SUCCESS;

  asn1_result = asn1_create_element (definitions,
				     "Kerberos5.KDC-REP",
				     &structure, "KDC-REP");
  if (asn1_result != ASN1_SUCCESS)
    {
      strcpy (errorDescription, libtasn1_strerror (asn1_result));
      return ASN1_TYPE_EMPTY;
    }

  asn1_result = asn1_der_decoding (&structure,
				   der, der_len, errorDescription);
  if (asn1_result != ASN1_SUCCESS)
    {
      asn1_delete_structure (&structure);
      return ASN1_TYPE_EMPTY;
    }

  return structure;
}

ASN1_TYPE
shishi_d2a_kdcreq (Shishi * handle, char *der, int derlen)
{
  char errorDescription[MAX_ERROR_DESCRIPTION_SIZE];
  ASN1_TYPE structure = ASN1_TYPE_EMPTY;
  int asn1_result = ASN1_SUCCESS;

  structure = shishi_der2asn1_as_req (handle->asn1, der,
				      derlen, errorDescription);
  if (structure == ASN1_TYPE_EMPTY)
    {
      printf ("bad magic %s\n", errorDescription);
      shishi_error_printf (handle, "Could not DER decode AS-REQ\n");

      structure = shishi_der2asn1_tgs_req (handle->asn1, der,
					   derlen, errorDescription);
      if (structure == ASN1_TYPE_EMPTY)
	{
	  printf ("bad magic %s\n", errorDescription);
	  shishi_error_printf (handle, "Could not DER decode TGS-REQ\n");

	  structure = shishi_der2asn1_kdc_req (handle->asn1, der,
					       derlen, errorDescription);
	  if (structure == ASN1_TYPE_EMPTY)
	    {
	      printf ("bad magic %s\n", errorDescription);
	      shishi_error_printf (handle, "Could not DER decode KDC-REQ\n");

	      return ASN1_TYPE_EMPTY;
	    }
	}
    }

  return structure;
}

ASN1_TYPE
shishi_d2a_encasreppart (Shishi * handle, char *der, int der_len)
{
  char errorDescription[MAX_ERROR_DESCRIPTION_SIZE];
  ASN1_TYPE structure = ASN1_TYPE_EMPTY;
  int asn1_result = ASN1_SUCCESS;

  asn1_result = asn1_create_element (handle->asn1,
				     "Kerberos5.EncASRepPart",
				     &structure, "EncKDCRepPart");
  if (asn1_result != ASN1_SUCCESS)
    {
      shishi_error_set (handle, libtasn1_strerror (asn1_result));
      return ASN1_TYPE_EMPTY;
    }

  asn1_result =
    asn1_der_decoding (&structure, der, der_len, errorDescription);
  if (asn1_result != ASN1_SUCCESS)
    {
      asn1_delete_structure (&structure);
      shishi_error_set (handle, errorDescription);
      return ASN1_TYPE_EMPTY;
    }

  return structure;
}

/** shishi_der2asn1_encasreppart

name:EncASRepPart  type:IDENTIFIER  value:EncKDCRepPart
*/
ASN1_TYPE
shishi_der2asn1_encasreppart (ASN1_TYPE definitions,
			      char *der, int der_len, char *errorDescription)
{
  ASN1_TYPE structure = ASN1_TYPE_EMPTY;
  int asn1_result = ASN1_SUCCESS;

  asn1_result = asn1_create_element (definitions,
				     "Kerberos5.EncASRepPart",
				     &structure, "EncKDCRepPart");
  if (asn1_result != ASN1_SUCCESS)
    {
      strcpy (errorDescription, libtasn1_strerror (asn1_result));
      return ASN1_TYPE_EMPTY;
    }

  asn1_result = asn1_der_decoding (&structure,
				   der, der_len, errorDescription);
  if (asn1_result != ASN1_SUCCESS)
    {
      asn1_delete_structure (&structure);
      return ASN1_TYPE_EMPTY;
    }

  return structure;
}

ASN1_TYPE
shishi_d2a_enctgsreppart (Shishi * handle, char *der, int der_len)
{
  char errorDescription[MAX_ERROR_DESCRIPTION_SIZE];
  ASN1_TYPE structure = ASN1_TYPE_EMPTY;
  int asn1_result = ASN1_SUCCESS;

  asn1_result = asn1_create_element (handle->asn1,
				     "Kerberos5.EncTGSRepPart",
				     &structure, "EncKDCRepPart");
  if (asn1_result != ASN1_SUCCESS)
    {
      shishi_error_set (handle, libtasn1_strerror (asn1_result));
      return ASN1_TYPE_EMPTY;
    }

  asn1_result =
    asn1_der_decoding (&structure, der, der_len, errorDescription);
  if (asn1_result != ASN1_SUCCESS)
    {
      asn1_delete_structure (&structure);
      shishi_error_set (handle, errorDescription);
      return ASN1_TYPE_EMPTY;
    }

  return structure;
}

/** shishi_der2asn1_enctgsreppart

name:EncTGSRepPart  type:IDENTIFIER  value:EncKDCRepPart
*/
ASN1_TYPE
shishi_der2asn1_enctgsreppart (ASN1_TYPE definitions,
			       char *der, int der_len, char *errorDescription)
{
  ASN1_TYPE structure = ASN1_TYPE_EMPTY;
  int asn1_result = ASN1_SUCCESS;

  asn1_result = asn1_create_element (definitions,
				     "Kerberos5.EncTGSRepPart",
				     &structure, "EncKDCRepPart");
  if (asn1_result != ASN1_SUCCESS)
    {
      strcpy (errorDescription, libtasn1_strerror (asn1_result));
      return ASN1_TYPE_EMPTY;
    }

  asn1_result = asn1_der_decoding (&structure,
				   der, der_len, errorDescription);
  if (asn1_result != ASN1_SUCCESS)
    {
      asn1_delete_structure (&structure);
      return ASN1_TYPE_EMPTY;
    }

  return structure;
}

/** shishi_der2asn1_enckdcreppart

name:EncKDCRepPart  type:IDENTIFIER  value:EncKDCRepPart
*/
ASN1_TYPE
shishi_der2asn1_enckdcreppart (ASN1_TYPE definitions,
			       char *der, int der_len, char *errorDescription)
{
  ASN1_TYPE structure = ASN1_TYPE_EMPTY;
  int asn1_result = ASN1_SUCCESS;

  asn1_result = asn1_create_element (definitions,
				     "Kerberos5.EncKDCRepPart",
				     &structure, "EncKDCRepPart");
  if (asn1_result != ASN1_SUCCESS)
    {
      strcpy (errorDescription, libtasn1_strerror (asn1_result));
      return ASN1_TYPE_EMPTY;
    }

  asn1_result = asn1_der_decoding (&structure,
				   der, der_len, errorDescription);
  if (asn1_result != ASN1_SUCCESS)
    {
      asn1_delete_structure (&structure);
      return ASN1_TYPE_EMPTY;
    }

  return structure;
}

/*
2.1.1. Kerberos Principal Name Form

   This name form shall be represented by the Object Identifier {iso(1)
   member-body(2) United States(840) mit(113554) infosys(1) gssapi(2)
   krb5(2) krb5_name(1)}.  The recommended symbolic name for this type
   is "GSS_KRB5_NT_PRINCIPAL_NAME".

   This name type corresponds to the single-string representation of a
   Kerberos name.  (Within the MIT Kerberos V5 implementation, such
   names are parseable with the krb5_parse_name() function.)  The
   elements included within this name representation are as follows,
   proceeding from the beginning of the string:

        (1) One or more principal name components; if more than one
        principal name component is included, the components are
        separated by `/`.  Arbitrary octets may be included within
        principal name components, with the following constraints and
        special considerations:

           (1a) Any occurrence of the characters `@` or `/` within a
           name component must be immediately preceded by the `\`
           quoting character, to prevent interpretation as a component
           or realm separator.

           (1b) The ASCII newline, tab, backspace, and null characters
           may occur directly within the component or may be
           represented, respectively, by `\n`, `\t`, `\b`, or `\0`.

           (1c) If the `\` quoting character occurs outside the contexts
           described in (1a) and (1b) above, the following character is
           interpreted literally.  As a special case, this allows the
           doubled representation `\\` to represent a single occurrence
           of the quoting character.

           (1d) An occurrence of the `\` quoting character as the last
           character of a component is illegal.

        (2) Optionally, a `@` character, signifying that a realm name
        immediately follows. If no realm name element is included, the
        local realm name is assumed.  The `/` , `:`, and null characters
        may not occur within a realm name; the `@`, newline, tab, and
        backspace characters may be included using the quoting
        conventions described in (1a), (1b), and (1c) above.
*/

int
shishi_principal_name_get (Shishi * handle,
			   ASN1_TYPE namenode,
			   char *namefield, char *out, int *outlen)
{
  int res = ASN1_SUCCESS;
  char format[BUFSIZ];
  int totlen = 0;
  int len;
  int i, j, n;

  sprintf (format, "%s.name-string", namefield);
  res = asn1_number_of_elements (namenode, format, &n);
  if (res != ASN1_SUCCESS)
    {
      shishi_error_set (handle, libtasn1_strerror (res));
      return SHISHI_ASN1_ERROR;
    }

  totlen = 0;
  for (i = 1; i <= n; i++)
    {
      len = *outlen - totlen;
      sprintf (format, "%s.name-string.?%d", namefield, i);
      res = asn1_read_value (namenode, format, out + totlen, &len);
      if (res != ASN1_SUCCESS)
	{
	  shishi_error_set (handle, libtasn1_strerror (res));
	  return SHISHI_ASN1_ERROR;
	}

      for (j = 0; j < len; j++)
	{
	  if (out[totlen] == '@' || out[totlen] == '/' || out[totlen] == '\\')
	    {
	      if (totlen + strlen ("\\") > *outlen)
		return SHISHI_TOO_SMALL_BUFFER;
	      out[totlen + 1] = out[totlen];
	      out[totlen] = '\\';
	      len++;
	      totlen++;
	      j++;
	    }
	  totlen++;
	}

      if (i < n)
	{
	  if (totlen + strlen ("/") > *outlen)
	    return SHISHI_TOO_SMALL_BUFFER;
	  out[totlen] = '/';
	  totlen++;
	}
    }

  *outlen = totlen;

  return SHISHI_OK;
}

int
shishi_principal_name_realm_get (Shishi * handle,
				 ASN1_TYPE namenode,
				 char *namefield,
				 ASN1_TYPE realmnode,
				 char *realmfield, char *out, int *outlen)
{
  int res = ASN1_SUCCESS;
  char format[BUFSIZ];
  int totlen = 0;
  int len;
  int i, j, n;

  totlen = *outlen;
  shishi_principal_name_get (handle, namenode, namefield, out, &totlen);

  if (realmnode == ASN1_TYPE_EMPTY && realmfield)
    {
      if (totlen + strlen ("@") + strlen (realmfield) > *outlen)
	return SHISHI_TOO_SMALL_BUFFER;

      memcpy (out + totlen, "@", strlen ("@"));
      totlen += strlen ("@");
      memcpy (out + totlen, realmfield, strlen (realmfield));
      totlen += strlen (realmfield);
    }
  else if (realmnode != ASN1_TYPE_EMPTY)
    {
      if (totlen + strlen ("@") > *outlen)
	return SHISHI_TOO_SMALL_BUFFER;

      memcpy (out + totlen, "@", strlen ("@"));
      totlen += strlen ("@");

      len = *outlen - totlen;
      res = asn1_read_value (namenode, realmfield, out + totlen, &len);
      if (res == ASN1_ELEMENT_NOT_FOUND)
	totlen--;
      else if (res != ASN1_SUCCESS)
	{
	  shishi_error_set (handle, libtasn1_strerror (res));
	  return SHISHI_ASN1_ERROR;
	}
      else
	totlen += len;
    }

  *outlen = totlen;

  return SHISHI_OK;
}

ASN1_TYPE
shishi_der2asn1_authenticator (ASN1_TYPE definitions,
			       char *der, int der_len, char *errorDescription)
{
  ASN1_TYPE structure = ASN1_TYPE_EMPTY;
  int asn1_result = ASN1_SUCCESS;

  asn1_result = asn1_create_element (definitions,
				     "Kerberos5.Authenticator",
				     &structure, "Authenticator");
  if (asn1_result != ASN1_SUCCESS)
    {
      strcpy (errorDescription, libtasn1_strerror (asn1_result));
      return ASN1_TYPE_EMPTY;
    }

  asn1_result = asn1_der_decoding (&structure,
				   der, der_len, errorDescription);
  if (asn1_result != ASN1_SUCCESS)
    {
      asn1_delete_structure (&structure);
      return ASN1_TYPE_EMPTY;
    }

  return structure;
}

ASN1_TYPE
shishi_der2asn1_krberror (ASN1_TYPE definitions,
			       char *der, int der_len, char *errorDescription)
{
  ASN1_TYPE structure = ASN1_TYPE_EMPTY;
  int asn1_result = ASN1_SUCCESS;

  asn1_result = asn1_create_element (definitions,
				     "Kerberos5.KRB-ERROR",
				     &structure, "KRB-ERROR");
  if (asn1_result != ASN1_SUCCESS)
    {
      strcpy (errorDescription, libtasn1_strerror (asn1_result));
      return ASN1_TYPE_EMPTY;
    }

  asn1_result = asn1_der_decoding (&structure,
				   der, der_len, errorDescription);
  if (asn1_result != ASN1_SUCCESS)
    {
      asn1_delete_structure (&structure);
      return ASN1_TYPE_EMPTY;
    }

  return structure;
}

ASN1_TYPE
shishi_d2a_authenticator (Shishi * handle, char *der,
			  int derlen, char *errorDescription)
{
  ASN1_TYPE authenticator;

  authenticator = shishi_der2asn1_authenticator (handle->asn1, der,
						 derlen, errorDescription);
  if (authenticator == ASN1_TYPE_EMPTY)
    fprintf (stdout, "Could not DER deocde AP-REQ\n");

  return authenticator;
}

/** shishi_der2asn1_ap_req

name:AP-REQ  type:SEQUENCE
  name:pvno  type:INTEGER
  name:msg-type  type:INTEGER
  name:ap-options  type:IDENTIFIER  value:APOptions
  name:ticket  type:IDENTIFIER  value:Ticket
  name:authenticator  type:IDENTIFIER  value:EncryptedData
*/
ASN1_TYPE
shishi_der2asn1_ap_req (ASN1_TYPE definitions,
			char *der, int der_len, char *errorDescription)
{
  ASN1_TYPE structure = ASN1_TYPE_EMPTY;
  int asn1_result = ASN1_SUCCESS;

  asn1_result = asn1_create_element (definitions,
				     "Kerberos5.AP-REQ",
				     &structure, "AP-REQ");
  if (asn1_result != ASN1_SUCCESS)
    {
      strcpy (errorDescription, libtasn1_strerror (asn1_result));
      return ASN1_TYPE_EMPTY;
    }

  asn1_result = asn1_der_decoding (&structure,
				   der, der_len, errorDescription);
  if (asn1_result != ASN1_SUCCESS)
    {
      asn1_delete_structure (&structure);
      return ASN1_TYPE_EMPTY;
    }

  return structure;
}

ASN1_TYPE
shishi_d2a_apreq (Shishi * handle, char *der,
		  int derlen, char *errorDescription)
{
  ASN1_TYPE apreq;

  apreq = shishi_der2asn1_ap_req (handle->asn1, der,
				  derlen, errorDescription);
  if (apreq == ASN1_TYPE_EMPTY)
    fprintf (stdout, "Could not DER deocde AP-REQ\n");

  return apreq;
}

/** shishi_der2asn1_ap_rep

   AP-REP ::=         [APPLICATION 15] SEQUENCE {
              pvno[0]                   INTEGER,
              msg-type[1]               INTEGER,
              enc-part[2]               EncryptedData
   }
*/
ASN1_TYPE
shishi_der2asn1_ap_rep (ASN1_TYPE definitions,
			char *der, int der_len, char *errorDescription)
{
  ASN1_TYPE structure = ASN1_TYPE_EMPTY;
  int asn1_result = ASN1_SUCCESS;

  asn1_result = asn1_create_element (definitions,
				     "Kerberos5.AP-REP",
				     &structure, "AP-REP");
  if (asn1_result != ASN1_SUCCESS)
    {
      strcpy (errorDescription, libtasn1_strerror (asn1_result));
      return ASN1_TYPE_EMPTY;
    }

  asn1_result = asn1_der_decoding (&structure,
				   der, der_len, errorDescription);
  if (asn1_result != ASN1_SUCCESS)
    {
      asn1_delete_structure (&structure);
      return ASN1_TYPE_EMPTY;
    }

  return structure;
}

ASN1_TYPE
shishi_d2a_aprep (Shishi * handle, char *der, int derlen)
{
  ASN1_TYPE aprep;
  char errorDescription[MAX_ERROR_DESCRIPTION_SIZE];

  aprep = shishi_der2asn1_ap_rep (handle->asn1, der,
				  derlen, errorDescription);
  if (aprep == ASN1_TYPE_EMPTY)
    fprintf (stdout, "Could not DER deocde AP-REP: %s\n", errorDescription);

  return aprep;
}

ASN1_TYPE
shishi_d2a_encapreppart (Shishi * handle, char *der, int der_len)
{
  char errorDescription[MAX_ERROR_DESCRIPTION_SIZE];
  ASN1_TYPE structure = ASN1_TYPE_EMPTY;
  int asn1_result = ASN1_SUCCESS;

  asn1_result = asn1_create_element (handle->asn1,
				     "Kerberos5.EncAPRepPart",
				     &structure, "EncAPRepPart");
  if (asn1_result != ASN1_SUCCESS)
    {
      shishi_error_set (handle, libtasn1_strerror (asn1_result));
      return ASN1_TYPE_EMPTY;
    }

  asn1_result =
    asn1_der_decoding (&structure, der, der_len, errorDescription);
  if (asn1_result != ASN1_SUCCESS)
    {
      asn1_delete_structure (&structure);
      shishi_error_set (handle, errorDescription);
      return ASN1_TYPE_EMPTY;
    }

  return structure;
}
