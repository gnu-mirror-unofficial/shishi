/* asn1.c	utilities to extract data from RFC 1510 ASN.1 types
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

#include "internal.h"

int
shishi_a2d_field (Shishi * handle,
		  Shishi_asn1 node, char *field, char *der, int *len)
{
  char errorDescription[MAX_ERROR_DESCRIPTION_SIZE];
  int rc;

  rc = asn1_der_coding (node, field, (unsigned char *) der, len,
			errorDescription);
  if (rc != ASN1_SUCCESS)
    return SHISHI_ASN1_ERROR;

  return SHISHI_OK;
}

int
shishi_a2d (Shishi * handle, Shishi_asn1 node, char *der, int *len)
{
  return shishi_a2d_field (handle, node, node->name, der, len);
}

int
shishi_asn1_done (Shishi * handle, Shishi_asn1 node)
{

  int rc;

  rc = asn1_delete_structure (&node);
  if (rc != ASN1_SUCCESS)
    {
      shishi_error_set (handle, libtasn1_strerror (rc));
      return SHISHI_ASN1_ERROR;
    }

  return SHISHI_OK;
}

int
shishi_asn1_write (Shishi * handle, Shishi_asn1 node,
		   const char *field,
		   const char *data, size_t datalen)
{
  int rc;

  rc = asn1_write_value (node, field, (unsigned char *) data, (int) datalen);
  if (rc != ASN1_SUCCESS)
    {
      shishi_error_set (handle, libtasn1_strerror (rc));
      return SHISHI_ASN1_ERROR;
    }

  return SHISHI_OK;
}

int
shishi_asn1_read (Shishi * handle, Shishi_asn1 node,
		  const char *field,
		  const char *data, size_t * datalen)
{
  int rc;

  rc = asn1_read_value (node, field, (unsigned char *) data, (int *) datalen);
  if (rc != ASN1_SUCCESS)
    {
      shishi_error_set (handle, libtasn1_strerror (rc));
      if (rc == ASN1_ELEMENT_NOT_FOUND)
	return SHISHI_ASN1_NO_ELEMENT;
      else
	return SHISHI_ASN1_ERROR;
    }

  return SHISHI_OK;
}

int
shishi_asn1_number_of_elements (Shishi * handle, Shishi_asn1 node,
				const char *field,
				int *n)
{
  int rc;

  rc = asn1_number_of_elements (node, field, n);
  if (rc != ASN1_SUCCESS)
    if (rc == ASN1_ELEMENT_NOT_FOUND)
      return SHISHI_ASN1_NO_ELEMENT;
    else
      return SHISHI_ASN1_ERROR;

  return SHISHI_OK;
}


int
shishi_asn1_field (Shishi * handle,
		   Shishi_asn1 node, char *data, size_t * datalen, char *field)
{
  int rc;

  rc = asn1_read_value (node, field, (unsigned char *) data, (int *) datalen);
  if (rc != ASN1_SUCCESS)
    {
      shishi_error_set (handle, libtasn1_strerror (rc));
      return SHISHI_ASN1_ERROR;
    }

  return SHISHI_OK;
}

int
shishi_asn1_optional_field (Shishi * handle,
			    Shishi_asn1 node,
			    char *data, size_t * datalen, char *field)
{
  int rc;

  rc = asn1_read_value (node, field, (unsigned char *) data, (int *) datalen);
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
shishi_asn1_integer_field (Shishi * handle,
			   Shishi_asn1 node, int *i, char *field)
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

int
shishi_asn1_integer2_field (Shishi * handle,
			    Shishi_asn1 node, unsigned long *i, char *field)
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

  *i = buf[3] | buf[2] << 8 | buf[1] << 16 | buf[0] << 24;

  return SHISHI_OK;
}

#define SHISHI_TICKET_DEFAULT_TKTVNO "5"
#define SHISHI_TICKET_DEFAULT_TKTVNO_LEN 0

Shishi_asn1
shishi_asn1_ticket (Shishi * handle)
{
  int res = ASN1_SUCCESS;
  ASN1_TYPE node = ASN1_TYPE_EMPTY;

  res = asn1_create_element (handle->asn1, "Kerberos5.Ticket",
			     &node, "Ticket");
  if (res != ASN1_SUCCESS)
    goto error;

#if 1
  res = asn1_write_value (node, "Ticket.tkt-vno",
			  (const unsigned char *)
			  SHISHI_TICKET_DEFAULT_TKTVNO,
			  SHISHI_TICKET_DEFAULT_TKTVNO_LEN);
  if (res != ASN1_SUCCESS)
    goto error;
#endif

  return (Shishi_asn1) node;

error:
  shishi_error_set (handle, libtasn1_strerror (res));
  if (node != NULL)
    asn1_delete_structure (&node);
  return NULL;
}

Shishi_asn1
shishi_asn1_encticketpart (Shishi * handle)
{
  int res = ASN1_SUCCESS;
  Shishi_asn1 node = NULL;

  res = asn1_create_element (handle->asn1, "Kerberos5.EncTicketPart",
			     &node, "EncTicketPart");
  if (res != ASN1_SUCCESS)
    goto error;

  return node;

error:
  shishi_error_set (handle, libtasn1_strerror (res));
  if (node != NULL)
    asn1_delete_structure (&node);
  return NULL;
}

Shishi_asn1
shishi_asn1_new (Shishi * handle, const char *field, const char *name)
{
  ASN1_TYPE node = ASN1_TYPE_EMPTY;
  int res;

  res = asn1_create_element (handle->asn1, field, &node, name);
  if (res != ASN1_SUCCESS)
    {
      shishi_error_set (handle, libtasn1_strerror (res));
      return NULL;
    }

  return (Shishi_asn1) node;
}

Shishi_asn1
shishi_asn1_apreq (Shishi * handle)
{
  return shishi_asn1_new (handle, "Kerberos5.AP-REQ", "AP-REQ");
}

Shishi_asn1
shishi_asn1_aprep (Shishi * handle)
{
  return shishi_asn1_new (handle, "Kerberos5.AP-REP", "AP-REP");
}

Shishi_asn1
shishi_d2a (Shishi * handle,
	    char *fieldname, char *nodename, const char *der, size_t derlen)
{
  char errorDescription[MAX_ERROR_DESCRIPTION_SIZE];
  Shishi_asn1 structure = NULL;
  int asn1_result = ASN1_SUCCESS;

  asn1_result = asn1_create_element (handle->asn1, fieldname,
				     &structure, nodename);
  if (asn1_result != ASN1_SUCCESS)
    {
      shishi_error_set (handle, libtasn1_strerror (asn1_result));
      return NULL;
    }

  asn1_result = asn1_der_decoding (&structure, (const unsigned char *) der,
				   (int) derlen, errorDescription);
  if (asn1_result != ASN1_SUCCESS)
    {
      asn1_delete_structure (&structure);
      shishi_error_set (handle, errorDescription);
      return NULL;
    }

  return structure;
}

Shishi_asn1
shishi_d2a_ticket (Shishi * handle, char *der, int derlen)
{
  return shishi_d2a (handle, "Kerberos5.Ticket", "Ticket", der, derlen);
}

Shishi_asn1
shishi_d2a_encticketpart (Shishi * handle, char *der, int derlen)
{
  return shishi_d2a (handle, "Kerberos5.EncTicketPart", "EncTicketPart",
		     der, derlen);
}

Shishi_asn1
shishi_d2a_asreq (Shishi * handle, char *der, int derlen)
{
  return shishi_d2a (handle, "Kerberos5.AS-REQ", "KDC-REQ", der, derlen);
}

Shishi_asn1
shishi_d2a_tgsreq (Shishi * handle, char *der, int derlen)
{
  return shishi_d2a (handle, "Kerberos5.TGS-REQ", "KDC-REQ", der, derlen);
}

Shishi_asn1
shishi_d2a_asrep (Shishi * handle, char *der, int derlen)
{
  return shishi_d2a (handle, "Kerberos5.AS-REP", "KDC-REP", der, derlen);
}

Shishi_asn1
shishi_d2a_tgsrep (Shishi * handle, char *der, int derlen)
{
  return shishi_d2a (handle, "Kerberos5.TGS-REP", "KDC-REP", der, derlen);
}

Shishi_asn1
shishi_d2a_kdcrep (Shishi * handle, char *der, int derlen)
{
  return shishi_d2a (handle, "Kerberos5.KDC-REP", "KDC-REP", der, derlen);
}

Shishi_asn1
shishi_d2a_kdcreq (Shishi * handle, char *der, int derlen)
{
  Shishi_asn1 structure = NULL;

  structure = shishi_d2a_asreq (handle, der, derlen);
  if (structure == NULL)
    {
      printf ("d2a_kdcreq: not asreq\n");
      shishi_error_printf (handle, "Could not DER decode AS-REQ\n");

      structure = shishi_d2a_tgsreq (handle, der, derlen);
      if (structure == NULL)
	{
	  printf ("d2a_kdcreq: not tgsreq\n");
	  shishi_error_printf (handle, "Could not DER decode TGS-REQ\n");

	  structure = shishi_d2a_kdcreq (handle, der, derlen);
	  if (structure == NULL)
	    {
	      printf ("d2a_kdcreq: not kdcreq\n");
	      shishi_error_printf (handle, "Could not DER decode KDC-REQ\n");

	      return NULL;
	    }
	  else
	    printf ("d2a_kdcreq: kdcreq!!\n");
	}
    }

  return structure;
}

Shishi_asn1
shishi_d2a_encasreppart (Shishi * handle, char *der, int derlen)
{
  return shishi_d2a (handle, "Kerberos5.EncASRepPart", "EncKDCRepPart",
		     der, derlen);
}

Shishi_asn1
shishi_d2a_enctgsreppart (Shishi * handle, char *der, int derlen)
{
  return shishi_d2a (handle, "Kerberos5.EncTGSRepPart", "EncKDCRepPart",
		     der, derlen);
}

Shishi_asn1
shishi_d2a_enckdcreppart (Shishi * handle, char *der, int derlen)
{
  return shishi_d2a (handle, "Kerberos5.EncKDCRepPart", "EncKDCRepPart",
		     der, derlen);
}

Shishi_asn1
shishi_d2a_authenticator (Shishi * handle, char *der, int derlen)
{
  return shishi_d2a (handle, "Kerberos5.Authenticator", "Authenticator",
		     der, derlen);
}

Shishi_asn1
shishi_d2a_krberror (Shishi * handle, char *der, int derlen)
{
  return shishi_d2a (handle, "Kerberos5.KRB-ERROR", "KRB-ERROR", der, derlen);
}

Shishi_asn1
shishi_d2a_apreq (Shishi * handle, char *der, int derlen)
{
  return shishi_d2a (handle, "Kerberos5.AP-REQ", "AP-REQ", der, derlen);
}

Shishi_asn1
shishi_d2a_aprep (Shishi * handle, char *der, int derlen)
{
  return shishi_d2a (handle, "Kerberos5.AP-REP", "AP-REP", der, derlen);
}

Shishi_asn1
shishi_d2a_encapreppart (Shishi * handle, char *der, int derlen)
{
  return shishi_d2a (handle, "Kerberos5.EncAPRepPart", "EncAPRepPart",
		     der, derlen);
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
			   Shishi_asn1 namenode,
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
      res = asn1_read_value (namenode, format,
			     (unsigned char *) &out[totlen], &len);
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
				 Shishi_asn1 namenode,
				 char *namefield,
				 Shishi_asn1 realmnode,
				 char *realmfield, char *out, int *outlen)
{
  int res = ASN1_SUCCESS;
  int totlen = 0;
  int len;

  totlen = *outlen;
  shishi_principal_name_get (handle, namenode, namefield, out, &totlen);

  if (realmnode == NULL && realmfield)
    {
      if (totlen + strlen ("@") + strlen (realmfield) > *outlen)
	return SHISHI_TOO_SMALL_BUFFER;

      memcpy (out + totlen, "@", strlen ("@"));
      totlen += strlen ("@");
      memcpy (out + totlen, realmfield, strlen (realmfield));
      totlen += strlen (realmfield);
    }
  else if (realmnode != NULL)
    {
      if (totlen + strlen ("@") > *outlen)
	return SHISHI_TOO_SMALL_BUFFER;

      memcpy (out + totlen, "@", strlen ("@"));
      totlen += strlen ("@");

      len = *outlen - totlen;
      res = asn1_read_value (namenode, realmfield,
			     (unsigned char *) &out[totlen], &len);
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
