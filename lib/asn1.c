/* asn1.c	utilities to manipulate RFC 1510 ASN.1 types
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

#include <libtasn1.h>
#define _SHISHI_HAS_LIBTASN1_H 1
#include "internal.h"

extern const ASN1_ARRAY_TYPE shishi_asn1_tab[];

Shishi_asn1
_shishi_asn1_read (void)
{
  Shishi_asn1 definitions = NULL;
  int asn1_result = ASN1_SUCCESS;
  char errorDescription[MAX_ERROR_DESCRIPTION_SIZE];

  asn1_result = asn1_array2tree (shishi_asn1_tab,
				 &definitions, errorDescription);
  if (asn1_result != ASN1_SUCCESS)
    {
      fprintf (stderr, "libshishi: error: %s\n", errorDescription);
      fprintf (stderr, "libshishi: error: %s\n",
	       libtasn1_strerror (asn1_result));
      return NULL;
    }

  return definitions;
}

Shishi_asn1
shishi_der2asn1 (Shishi * handle,
		 const char *fieldname,
		 const char *nodename, const char *der, size_t derlen)
{
  char errorDescription[MAX_ERROR_DESCRIPTION_SIZE];
  Shishi_asn1 structure = NULL;
  int asn1_result = ASN1_SUCCESS;

  asn1_result = asn1_create_element (handle->asn1, fieldname, &structure);
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

int
shishi_a2d_field (Shishi * handle,
		  Shishi_asn1 node, const char *field, char *der, int *len)
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
  return shishi_a2d_field (handle, node, "", der, len);
}

int
shishi_a2d_new_field (Shishi * handle, Shishi_asn1 node,
		      const char *field, char **der, int *len)
{
  char errorDescription[MAX_ERROR_DESCRIPTION_SIZE];
  int rc;

  *len = 0;
  rc = asn1_der_coding (node, field, NULL, len, errorDescription);
  if (rc != ASN1_MEM_ERROR)
    return SHISHI_ASN1_ERROR;

  *der = malloc(*len);
  if (!*der)
    return SHISHI_MALLOC_ERROR;

  rc = asn1_der_coding (node, field, *der, len, errorDescription);
  if (rc != ASN1_SUCCESS)
    return SHISHI_ASN1_ERROR;

  return SHISHI_OK;
}

int
shishi_new_a2d (Shishi * handle, Shishi_asn1 node, char **der, int *len)
{
  return shishi_a2d_new_field (handle, node, "", der, len);
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
		   const char *field, const char *data, size_t datalen)
{
  int rc;

  rc = asn1_write_value (node, field,
			 (const unsigned char *) data, (int) datalen);
  if (rc != ASN1_SUCCESS)
    {
      shishi_error_set (handle, libtasn1_strerror (rc));
      return SHISHI_ASN1_ERROR;
    }

  return SHISHI_OK;
}

int
shishi_asn1_write_uint32 (Shishi * handle, Shishi_asn1 node,
			  const char *field, uint32_t n)
{
  char *buf;
  int res;

  asprintf (&buf, "%ud", n);
  res = shishi_asn1_write (handle, node, field, buf, 0);
  free(buf);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

int
shishi_asn1_write_int32 (Shishi * handle, Shishi_asn1 node,
			 const char *field, int32_t n)
{
  char *buf;
  int res;

  asprintf (&buf, "%d", n);
  res = shishi_asn1_write (handle, node, field, buf, 0);
  free(buf);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

int
shishi_asn1_write_integer (Shishi * handle, Shishi_asn1 node,
			   const char *field, int n)
{
  return shishi_asn1_write_int32 (handle, node, field, (int32_t)n);
}

int
shishi_asn1_read (Shishi * handle, Shishi_asn1 node,
		  const char *field, char *data, size_t * datalen)
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
shishi_asn1_read_int32 (Shishi * handle, Shishi_asn1 node,
			const char *field, int32_t *i)
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

  if (buflen < 4)
    {
      memset (buf, 0, sizeof (buf));
      rc = asn1_read_value (node, field, &buf[4-buflen], &buflen);
      if (rc != ASN1_SUCCESS)
	{
	  shishi_error_set (handle, libtasn1_strerror (rc));
	  return SHISHI_ASN1_ERROR;
	}
    }
  *i = buf[3] | (buf[2] << 8) | (buf[1] << 16) | (buf[0] << 24);

  return SHISHI_OK;
}

int
shishi_asn1_read_uint32 (Shishi * handle, Shishi_asn1 node,
			 const char *field, uint32_t *i)
{
  shishi_asn1_read_int32 (handle, node, field, (int32_t*)i);
}

int
shishi_asn1_read_integer (Shishi * handle, Shishi_asn1 node,
			  const char *field, int *i)
{
  shishi_asn1_read_int32 (handle, node, field, (int32_t*)i);
}

int
shishi_asn1_read_bitstring (Shishi * handle, Shishi_asn1 node,
			    const char *field, int *flags)
{
  unsigned char buf[4];
  int buflen;
  int i;
  int res;

  memset (buf, 0, sizeof (buf));
  buflen = sizeof (buf);
  res = shishi_asn1_field (handle, node, buf, &buflen, field);
  if (res != SHISHI_OK)
    return res;

  *flags = 0;
  for (i = 0; i < 4; i++)
    {
      *flags |= (((buf[i] >> 7) & 0x01) |
		 ((buf[i] >> 5) & 0x02) |
		 ((buf[i] >> 3) & 0x04) |
		 ((buf[i] >> 1) & 0x08) |
		 ((buf[i] << 1) & 0x10) |
		 ((buf[i] << 3) & 0x20) |
		 ((buf[i] << 5) & 0x40) | ((buf[i] << 7) & 0x80)) << (8 * i);
    }

  return SHISHI_OK;
}

int
shishi_asn1_write_bitstring (Shishi * handle, Shishi_asn1 node,
			     const char *field, int flags)
{
  unsigned char buf[4];
  int buflen;
  int i;
  int res;

  for (i = 0; i < 4; i++)
    {
      buf[i] |= ((((flags & (0xFF << 8*i)) >> 7) & 0x01) |
		 (((flags & (0xFF << 8*i)) >> 5) & 0x02) |
		 (((flags & (0xFF << 8*i)) >> 3) & 0x04) |
		 (((flags & (0xFF << 8*i)) >> 1) & 0x08) |
		 (((flags & (0xFF << 8*i)) << 1) & 0x10) |
		 (((flags & (0xFF << 8*i)) << 3) & 0x20) |
		 (((flags & (0xFF << 8*i)) << 5) & 0x40) |
		 (((flags & (0xFF << 8*i)) << 7) & 0x80)) << (8 * i);
    }

  buflen = sizeof (buf);
  res = shishi_asn1_write (handle, node, field, buf, buflen);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

int
shishi_asn1_number_of_elements (Shishi * handle, Shishi_asn1 node,
				const char *field, int *n)
{
  int rc;

  rc = asn1_number_of_elements (node, field, n);
  if (rc != ASN1_SUCCESS)
    {
      if (rc == ASN1_ELEMENT_NOT_FOUND)
	return SHISHI_ASN1_NO_ELEMENT;
      else
	return SHISHI_ASN1_ERROR;
    }

  return SHISHI_OK;
}


int
shishi_asn1_field (Shishi * handle,
		   Shishi_asn1 node, char *data, size_t * datalen,
		   const char *field)
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
			    char *data, size_t * datalen, const char *field)
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
			   Shishi_asn1 node, int *i, const char *field)
{
  /* OBSOLETE */
  return shishi_asn1_read_integer(handle, node, field, i);
}

#define SHISHI_TICKET_DEFAULT_TKTVNO "5"
#define SHISHI_TICKET_DEFAULT_TKTVNO_LEN 0

Shishi_asn1
shishi_asn1_ticket (Shishi * handle)
{
  int res = ASN1_SUCCESS;
  ASN1_TYPE node = ASN1_TYPE_EMPTY;

  res = asn1_create_element (handle->asn1, "Kerberos5.Ticket", &node);
  if (res != ASN1_SUCCESS)
    goto error;

#if 1
  res = asn1_write_value (node, "tkt-vno",
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

static Shishi_asn1
shishi_asn1_new (Shishi * handle, const char *field, const char *name)
{
  ASN1_TYPE node = ASN1_TYPE_EMPTY;
  int res;

  res = asn1_create_element (handle->asn1, field, &node);
  if (res != ASN1_SUCCESS)
    {
      shishi_error_set (handle, libtasn1_strerror (res));
      return NULL;
    }

  return (Shishi_asn1) node;
}

Shishi_asn1
shishi_asn1_asreq (Shishi * handle)
{
  return shishi_asn1_new (handle, "Kerberos5.AS-REQ", "KDC-REQ");
}

Shishi_asn1
shishi_asn1_asrep (Shishi * handle)
{
  return shishi_asn1_new (handle, "Kerberos5.AS-REP", "KDC-REP");
}

Shishi_asn1
shishi_asn1_tgsreq (Shishi * handle)
{
  return shishi_asn1_new (handle, "Kerberos5.TGS-REQ", "KDC-REQ");
}

Shishi_asn1
shishi_asn1_tgsrep (Shishi * handle)
{
  return shishi_asn1_new (handle, "Kerberos5.TGS-REP", "KDC-REP");
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
shishi_asn1_encapreppart (Shishi * handle)
{
  return shishi_asn1_new (handle, "Kerberos5.EncAPRepPart", "EncAPRepPart");
}

Shishi_asn1
shishi_asn1_encticketpart (Shishi * handle)
{
  return shishi_asn1_new (handle, "Kerberos5.EncTicketPart", "EncTicketPart");
}

Shishi_asn1
shishi_asn1_authenticator (Shishi * handle)
{
  return shishi_asn1_new (handle, "Kerberos5.Authenticator", "Authenticator");
}

Shishi_asn1
shishi_asn1_enckdcreppart (Shishi * handle)
{
  return shishi_asn1_new (handle, "Kerberos5.EncKDCRepPart", "EncKDCRepPart");
}

Shishi_asn1
shishi_asn1_encasreppart (Shishi * handle)
{
  return shishi_asn1_new (handle, "Kerberos5.EncASRepPart", "EncKDCRepPart");
}

Shishi_asn1
shishi_asn1_krberror (Shishi * handle)
{
  return shishi_asn1_new (handle, "Kerberos5.KRB-ERROR", "KRB-ERROR");
}

Shishi_asn1
shishi_asn1_krbsafe (Shishi * handle)
{
  return shishi_asn1_new (handle, "Kerberos5.KRB-SAFE", "KRB-SAFE");
}

Shishi_asn1
shishi_der2asn1_ticket (Shishi * handle, const char *der, size_t derlen)
{
  return shishi_der2asn1 (handle, "Kerberos5.Ticket", "Ticket", der, derlen);
}

Shishi_asn1
shishi_der2asn1_encticketpart (Shishi * handle, const char *der,
			       size_t derlen)
{
  return shishi_der2asn1 (handle, "Kerberos5.EncTicketPart", "EncTicketPart",
			  der, derlen);
}

Shishi_asn1
shishi_der2asn1_asreq (Shishi * handle, const char *der, size_t derlen)
{
  return shishi_der2asn1 (handle, "Kerberos5.AS-REQ", "KDC-REQ", der, derlen);
}

Shishi_asn1
shishi_der2asn1_tgsreq (Shishi * handle, const char *der, size_t derlen)
{
  return shishi_der2asn1 (handle, "Kerberos5.TGS-REQ", "KDC-REQ", der,
			  derlen);
}

Shishi_asn1
shishi_der2asn1_asrep (Shishi * handle, const char *der, size_t derlen)
{
  return shishi_der2asn1 (handle, "Kerberos5.AS-REP", "KDC-REP", der, derlen);
}

Shishi_asn1
shishi_der2asn1_tgsrep (Shishi * handle, const char *der, size_t derlen)
{
  return shishi_der2asn1 (handle, "Kerberos5.TGS-REP", "KDC-REP", der,
			  derlen);
}

Shishi_asn1
shishi_der2asn1_kdcrep (Shishi * handle, const char *der, size_t derlen)
{
  return shishi_der2asn1 (handle, "Kerberos5.KDC-REP", "KDC-REP", der,
			  derlen);
}

Shishi_asn1
shishi_der2asn1_kdcreq (Shishi * handle, const char *der, size_t derlen)
{
  Shishi_asn1 structure = NULL;

  structure = shishi_der2asn1_asreq (handle, der, derlen);
  if (structure == NULL)
    {
      printf ("der2asn1_kdcreq: not asreq\n");
      shishi_error_printf (handle, "Could not DER decode AS-REQ\n");

      structure = shishi_der2asn1_tgsreq (handle, der, derlen);
      if (structure == NULL)
	{
	  printf ("der2asn1_kdcreq: not tgsreq\n");
	  shishi_error_printf (handle, "Could not DER decode TGS-REQ\n");

	  structure = shishi_der2asn1_kdcreq (handle, der, derlen);
	  if (structure == NULL)
	    {
	      printf ("der2asn1_kdcreq: not kdcreq\n");
	      shishi_error_printf (handle, "Could not DER decode KDC-REQ\n");

	      return NULL;
	    }
	  else
	    printf ("der2asn1_kdcreq: kdcreq!!\n");
	}
    }

  return structure;
}

Shishi_asn1
shishi_der2asn1_encasreppart (Shishi * handle, const char *der, size_t derlen)
{
  return shishi_der2asn1 (handle, "Kerberos5.EncASRepPart", "EncKDCRepPart",
			  der, derlen);
}

Shishi_asn1
shishi_der2asn1_enctgsreppart (Shishi * handle, const char *der,
			       size_t derlen)
{
  return shishi_der2asn1 (handle, "Kerberos5.EncTGSRepPart", "EncKDCRepPart",
			  der, derlen);
}

Shishi_asn1
shishi_der2asn1_enckdcreppart (Shishi * handle, const char *der,
			       size_t derlen)
{
  return shishi_der2asn1 (handle, "Kerberos5.EncKDCRepPart", "EncKDCRepPart",
			  der, derlen);
}

Shishi_asn1
shishi_der2asn1_authenticator (Shishi * handle, const char *der,
			       size_t derlen)
{
  return shishi_der2asn1 (handle, "Kerberos5.Authenticator", "Authenticator",
			  der, derlen);
}

Shishi_asn1
shishi_der2asn1_krberror (Shishi * handle, const char *der, size_t derlen)
{
  return shishi_der2asn1 (handle, "Kerberos5.KRB-ERROR", "KRB-ERROR", der,
			  derlen);
}

Shishi_asn1
shishi_der2asn1_krbsafe (Shishi * handle, const char *der, size_t derlen)
{
  return shishi_der2asn1 (handle, "Kerberos5.KRB-SAFE", "KRB-SAFE",
			  der, derlen);
}

Shishi_asn1
shishi_der2asn1_apreq (Shishi * handle, const char *der, size_t derlen)
{
  return shishi_der2asn1 (handle, "Kerberos5.AP-REQ", "AP-REQ", der, derlen);
}

Shishi_asn1
shishi_der2asn1_aprep (Shishi * handle, const char *der, size_t derlen)
{
  return shishi_der2asn1 (handle, "Kerberos5.AP-REP", "AP-REP", der, derlen);
}

Shishi_asn1
shishi_der2asn1_encapreppart (Shishi * handle, const char *der, size_t derlen)
{
  return shishi_der2asn1 (handle, "Kerberos5.EncAPRepPart", "EncAPRepPart",
			  der, derlen);
}
