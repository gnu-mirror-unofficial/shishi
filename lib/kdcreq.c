/* kdcreq.c	Key distribution (AS/TGS) request functions
 * Copyright (C) 2002  Simon Josefsson
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

#define SHISHI_KDCREQ_DEFAULT_PVNO      "5"
#define SHISHI_KDCREQ_DEFAULT_PVNO_LEN  0
#define SHISHI_AS_REQ_DEFAULT_MSG_TYPE      "10"
#define SHISHI_AS_REQ_DEFAULT_MSG_TYPE_LEN  0
#define SHISHI_TGS_REQ_DEFAULT_MSG_TYPE      "12"
#define SHISHI_TGS_REQ_DEFAULT_MSG_TYPE_LEN  0
#define SHISHI_KDCREQ_DEFAULT_REQ_BODY_KDC_OPTIONS      "\x00\x00\x00\x00"
#define SHISHI_KDCREQ_DEFAULT_REQ_BODY_KDC_OPTIONS_LEN  32
#define SHISHI_KDCREQ_DEFAULT_REQ_BODY_SNAME_NAME_TYPE "1"	/* SHISHI_NT_PRINCIPAL */
#define SHISHI_KDCREQ_DEFAULT_REQ_BODY_SNAME_NAME_TYPE_LEN 0
#define SHISHI_KDCREQ_DEFAULT_REQ_BODY_TILL ""
#define SHISHI_KDCREQ_DEFAULT_REQ_BODY_TILL_LEN 1

ASN1_TYPE
_shishi_kdcreq (Shishi * handle, int as)
{
  int res = ASN1_SUCCESS;
  ASN1_TYPE node = ASN1_TYPE_EMPTY;
  char *servicebuf[3];
  char noncebuf[4];

  if (as)
    res =
      asn1_create_element (handle->asn1, "Kerberos5.AS-REQ", &node,
			   "KDC-REQ");
  else
    res =
      asn1_create_element (handle->asn1, "Kerberos5.TGS-REQ", &node,
			   "KDC-REQ");
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (node, "KDC-REQ.pvno",
			  SHISHI_KDCREQ_DEFAULT_PVNO,
			  SHISHI_KDCREQ_DEFAULT_PVNO_LEN);
  if (res != ASN1_SUCCESS)
    goto error;

  if (as)
    res = asn1_write_value (node, "KDC-REQ.msg-type",
			    SHISHI_AS_REQ_DEFAULT_MSG_TYPE,
			    SHISHI_AS_REQ_DEFAULT_MSG_TYPE_LEN);
  else
    res = asn1_write_value (node, "KDC-REQ.msg-type",
			    SHISHI_TGS_REQ_DEFAULT_MSG_TYPE,
			    SHISHI_TGS_REQ_DEFAULT_MSG_TYPE_LEN);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (node, "KDC-REQ.req-body.kdc-options",
			  SHISHI_KDCREQ_DEFAULT_REQ_BODY_KDC_OPTIONS,
			  SHISHI_KDCREQ_DEFAULT_REQ_BODY_KDC_OPTIONS_LEN);
  if (res != ASN1_SUCCESS)
    goto error;

  if (as)
    {
      res = shishi_kdcreq_set_cname (handle, node, SHISHI_NT_PRINCIPAL,
				     shishi_principal_default (handle));
      if (res != SHISHI_OK)
	goto error;
    }
  else
    {
      res = asn1_write_value (node, "KDC-REQ.req-body.cname", NULL, 0);
      if (res != ASN1_SUCCESS)
	goto error;
    }

  res = shishi_kdcreq_set_realm (handle, node,
				 shishi_realm_default (handle));
  if (res != SHISHI_OK)
    goto error;

  servicebuf[0] = "krbtgt";
  servicebuf[1] = (char*) shishi_realm_default (handle);
  servicebuf[2] = NULL;
  res = shishi_kdcreq_set_sname (handle, node,
				 SHISHI_NT_PRINCIPAL, servicebuf);
  if (res != SHISHI_OK)
    goto error;

  res = asn1_write_value (node, "KDC-REQ.req-body.sname.name-type",
			  SHISHI_KDCREQ_DEFAULT_REQ_BODY_SNAME_NAME_TYPE,
			  SHISHI_KDCREQ_DEFAULT_REQ_BODY_SNAME_NAME_TYPE_LEN);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (node, "KDC-REQ.req-body.from", NULL, 0);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (node, "KDC-REQ.req-body.till",
			  shishi_generalize_time (handle, time (NULL) + 1000),
			  0);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (node, "KDC-REQ.req-body.rtime", NULL, 0);
  if (res != ASN1_SUCCESS)
    goto error;

  shishi_randomize (handle, &noncebuf[0], sizeof (noncebuf));
  res = asn1_write_value (node, "KDC-REQ.req-body.nonce", noncebuf,
			  sizeof (noncebuf));
  if (res != ASN1_SUCCESS)
    goto error;

  res = shishi_kdcreq_set_etype (handle, node, handle->clientkdcetypes,
				 handle->nclientkdcetypes);
  if (res != SHISHI_OK)
    goto error;

  res = asn1_write_value (node, "KDC-REQ.req-body.addresses", NULL, 0);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_write_value (node, "KDC-REQ.req-body.enc-authorization-data",
			  NULL, 0);
  if (res != ASN1_SUCCESS)
    goto error;

  res =
    asn1_write_value (node, "KDC-REQ.req-body.additional-tickets", NULL, 0);
  if (res != ASN1_SUCCESS)
    goto error;

  return node;

error:
  shishi_error_set (handle, libtasn1_strerror (res));
  if (node != ASN1_TYPE_EMPTY)
    asn1_delete_structure (&node);
  return NULL;
}

/**
 * shishi_as_req:
 * @handle: shishi handle as allocated by shishi_init().
 *
 * This function creates a new AS-REQ, populated with some default
 * values.
 *
 * Return value: Returns the AS-REQ or ASN1_TYPE_EMPTY on failure.
 **/
ASN1_TYPE
shishi_asreq (Shishi * handle)
{
  return _shishi_kdcreq (handle, 1);
}

/**
 * shishi_tgs_req:
 * @handle: shishi handle as allocated by shishi_init().
 *
 * This function creates a new TGS-REQ, populated with some default
 * values.
 *
 * Return value: Returns the TGS-REQ or ASN1_TYPE_EMPTY on failure.
 **/
ASN1_TYPE
shishi_tgsreq (Shishi * handle)
{
  return _shishi_kdcreq (handle, 0);
}

/**
 * shishi_kdcreq_print:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle open for writing.
 * @kdcreq: KDC-REQ to print.
 *
 * Print ASCII armored DER encoding of KDC-REQ to file.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcreq_print (Shishi * handle, FILE * fh, ASN1_TYPE kdcreq)
{
  return _shishi_print_armored_data (handle, fh, kdcreq, "KDC-REQ", NULL);
}

/**
 * shishi_kdcreq_save:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle open for writing.
 * @kdcreq: KDC-REQ to save.
 *
 * Print DER encoding of KDC-REQ to file.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcreq_save (Shishi * handle, FILE * fh, ASN1_TYPE kdcreq)
{
  return _shishi_save_data (handle, fh, kdcreq, "KDC-REQ");
}

/**
 * shishi_kdcreq_to_file:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcreq: KDC-REQ to save.
 * @filetype: input variable specifying type of file to be written,
 *            see Shishi_filetype.
 * @filename: input variable with filename to write to.
 *
 * Write KDC-REQ to file in specified TYPE.  The file will be truncated
 * if it exists.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcreq_to_file (Shishi * handle, ASN1_TYPE kdcreq,
		       int filetype, char *filename)
{
  FILE *fh;
  int res;

  if (VERBOSE (handle))
    printf (_("Writing KDC-REQ to %s...\n"), filename);

  fh = fopen (filename, "w");
  if (fh == NULL)
    return SHISHI_FOPEN_ERROR;

  if (VERBOSE (handle))
    printf (_("Writing KDC-REQ in %s format...\n"),
	    filetype == SHISHI_FILETYPE_TEXT ? "TEXT" : "DER");

  if (filetype == SHISHI_FILETYPE_TEXT)
    res = shishi_kdcreq_print (handle, fh, kdcreq);
  else
    res = shishi_kdcreq_save (handle, fh, kdcreq);
  if (res != SHISHI_OK)
    return res;

  res = fclose (fh);
  if (res != 0)
    return SHISHI_FCLOSE_ERROR;

  if (VERBOSE (handle))
    printf (_("Writing KDC-REQ to %s...done\n"), filename);

  return SHISHI_OK;
}

/**
 * shishi_kdcreq_parse:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle open for reading.
 * @kdcreq: output variable with newly allocated KDC-REQ.
 *
 * Read ASCII armored DER encoded KDC-REQ from file and populate given
 * variable.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcreq_parse (Shishi * handle, FILE * fh, ASN1_TYPE * kdcreq)
{
  return _shishi_kdcreq_input (handle, fh, kdcreq, 0);
}

/**
 * shishi_kdcreq_read:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle open for reading.
 * @kdcreq: output variable with newly allocated KDC-REQ.
 *
 * Read DER encoded KDC-REQ from file and populate given variable.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcreq_read (Shishi * handle, FILE * fh, ASN1_TYPE * kdcreq)
{
  return _shishi_kdcreq_input (handle, fh, kdcreq, 1);
}

/**
 * shishi_kdcreq_from_file:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcreq: output variable with newly allocated KDC-REQ.
 * @filetype: input variable specifying type of file to be read,
 *            see Shishi_filetype.
 * @filename: input variable with filename to read from.
 *
 * Read KDC-REQ from file in specified TYPE.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcreq_from_file (Shishi * handle, ASN1_TYPE * kdcreq,
			 int filetype, char *filename)
{
  int res;
  FILE *fh;

  if (VERBOSE (handle))
    printf (_("Reading KDC-REQ from %s...\n"), filename);

  fh = fopen (filename, "r");
  if (fh == NULL)
    return SHISHI_FOPEN_ERROR;

  if (VERBOSE (handle))
    printf (_("Reading KDC-REQ in %s format...\n"),
	    filetype == SHISHI_FILETYPE_TEXT ? "TEXT" : "DER");

  if (filetype == SHISHI_FILETYPE_TEXT)
    res = shishi_kdcreq_parse (handle, fh, kdcreq);
  else
    res = shishi_kdcreq_read (handle, fh, kdcreq);
  if (res != SHISHI_OK)
    return res;

  res = fclose (fh);
  if (res != 0)
    return SHISHI_FCLOSE_ERROR;

  if (VERBOSE (handle))
    printf (_("Reading KDC-REQ from %s...done\n"), filename);

  return SHISHI_OK;
}

/**
 * shishi_kdcreq_set_cname:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcreq: KDC-REQ variable to set client name field in.
 * @name_type: type of principial, see Shishi_name_type, usually
 *             SHISHI_NT_UNKNOWN.
 * @principal: input array with principal name.
 *
 * Set the client name field in the KDC-REQ.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcreq_set_cname (Shishi * handle,
			 ASN1_TYPE kdcreq,
			 Shishi_name_type name_type,
			 const char *principal)
{
  int res = ASN1_SUCCESS;
  char buf[BUFSIZ];

  sprintf (buf, "%d", name_type);

  res = asn1_write_value (kdcreq, "KDC-REQ.req-body.cname.name-type", buf, 0);
  if (res != ASN1_SUCCESS)
    {
      shishi_error_set (handle, libtasn1_strerror (res));
      return !SHISHI_OK;
    }

  res =
    asn1_write_value (kdcreq, "KDC-REQ.req-body.cname.name-string", NULL, 0);
  if (res != ASN1_SUCCESS)
    {
      shishi_error_set (handle, libtasn1_strerror (res));
      return !SHISHI_OK;
    }

  res =
    asn1_write_value (kdcreq, "KDC-REQ.req-body.cname.name-string", "NEW", 1);
  if (res != ASN1_SUCCESS)
    {
      shishi_error_set (handle, libtasn1_strerror (res));
      return !SHISHI_OK;
    }
  res = asn1_write_value (kdcreq, "KDC-REQ.req-body.cname.name-string.?1",
			  principal, strlen (principal));
  if (res != ASN1_SUCCESS)
    {
      shishi_error_set (handle, libtasn1_strerror (res));
      return !SHISHI_OK;
    }

  return SHISHI_OK;
}

int
shishi_kdcreq_cnamerealm_get (Shishi * handle,
			      ASN1_TYPE kdcreq,
			      char *cnamerealm, size_t *cnamerealmlen)
{
  return shishi_principal_name_realm_get (handle, kdcreq,
					  "KDC-REQ.req-body.cname", kdcreq,
					  "KDC-REQ.req-body.realm",
					  cnamerealm, cnamerealmlen);
}

/**
 * shishi_kdcreq_set_realm:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcreq: KDC-REQ variable to set realm field in.
 * @realm: input array with name of realm.
 *
 * Set the realm field in the KDC-REQ.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcreq_set_realm (Shishi * handle, ASN1_TYPE kdcreq, const char *realm)
{
  int res = ASN1_SUCCESS;

  res = asn1_write_value (kdcreq, "KDC-REQ.req-body.realm", realm, 0);
  if (res != ASN1_SUCCESS)
    {
      shishi_error_set (handle, libtasn1_strerror (res));
      return !SHISHI_OK;
    }

  return SHISHI_OK;
}


/**
 * shishi_kdcreq_set_etype:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcreq: KDC-REQ variable to set etype field in.
 * @etype: input array with encryption types.
 * @netype: number of elements in input array with encryption types.
 *
 * Set the list of supported or wanted encryption types in the
 * request.  The list should be sorted in priority order.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcreq_set_etype (Shishi * handle,
			 ASN1_TYPE kdcreq, int *etype, int netype)
{
  int res = ASN1_SUCCESS;
  char buf[BUFSIZ];
  char buf2[BUFSIZ];
  int i;

  res = asn1_write_value (kdcreq, "KDC-REQ.req-body.etype", NULL, 0);
  if (res != ASN1_SUCCESS)
    {
      shishi_error_set (handle, libtasn1_strerror (res));
      return !SHISHI_OK;
    }

  for (i = 1; i <= netype; i++)
    {
      res = asn1_write_value (kdcreq, "KDC-REQ.req-body.etype", "NEW", 1);
      if (res != ASN1_SUCCESS)
	{
	  shishi_error_set (handle, libtasn1_strerror (res));
	  return !SHISHI_OK;
	}

      sprintf (buf, "KDC-REQ.req-body.etype.?%d", i);
      sprintf (buf2, "%d", etype[i - 1]);
      res = asn1_write_value (kdcreq, buf, buf2, 0);
      if (res != ASN1_SUCCESS)
	{
	  shishi_error_set (handle, libtasn1_strerror (res));
	  return !SHISHI_OK;
	}
    }

  return SHISHI_OK;
}

/**
 * shishi_kdcreq_set_sname:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcreq: KDC-REQ variable to set server name field in.
 * @name_type: type of principial, see Shishi_name_type, usually
 *             SHISHI_NT_UNKNOWN.
 * @principal: input array with principal name.
 *
 * Set the server name field in the KDC-REQ.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcreq_set_sname (Shishi * handle,
			 ASN1_TYPE kdcreq,
			 Shishi_name_type name_type, char *service[])
{
  int res = ASN1_SUCCESS;
  char buf[BUFSIZ];
  int i;

  sprintf (buf, "%d", name_type);

  res = asn1_write_value (kdcreq, "KDC-REQ.req-body.sname.name-type", buf, 0);
  if (res != ASN1_SUCCESS)
    {
      shishi_error_set (handle, libtasn1_strerror (res));
      return !SHISHI_OK;
    }

  res =
    asn1_write_value (kdcreq, "KDC-REQ.req-body.sname.name-string", NULL, 0);
  if (res != ASN1_SUCCESS)
    {
      shishi_error_set (handle, libtasn1_strerror (res));
      return !SHISHI_OK;
    }

  i = 1;
  while (service[i - 1])
    {
      res = asn1_write_value (kdcreq, "KDC-REQ.req-body.sname.name-string",
			      "NEW", 1);
      if (res != ASN1_SUCCESS)
	{
	  shishi_error_set (handle, libtasn1_strerror (res));
	  return !SHISHI_OK;
	}

      sprintf (buf, "KDC-REQ.req-body.sname.name-string.?%d", i);
      res = asn1_write_value (kdcreq, buf, service[i - 1], 0);
      if (res != ASN1_SUCCESS)
	{
	  shishi_error_set (handle, libtasn1_strerror (res));
	  return !SHISHI_OK;
	}

      i++;
    }

  return SHISHI_OK;
}

int
shishi_kdcreq_set_server (Shishi * handle, ASN1_TYPE req, const char *server)
{
  char *tmpserver;
  char **serverbuf;
  char *tokptr;
  int res;
  int i;

  tmpserver = strdup (server);
  if (tmpserver == NULL)
    return SHISHI_MALLOC_ERROR;

  serverbuf = malloc (sizeof (*serverbuf));
  for (i = 0;
       (serverbuf[i] = strtok_r (i == 0 ? tmpserver : NULL, "/", &tokptr));
       i++)
    {
      serverbuf = realloc (serverbuf, (i + 2) * sizeof (*serverbuf));
      if (serverbuf == NULL)
	return SHISHI_MALLOC_ERROR;
    }
  res = shishi_kdcreq_set_sname (handle, req, SHISHI_NT_PRINCIPAL, serverbuf);
  if (res != SHISHI_OK)
    {
      fprintf (stderr, _("Could not set sname: %s\n"),
	       shishi_strerror_details (handle));
      return res;
    }
  free (serverbuf);
  free (tmpserver);

  return SHISHI_OK;
}

int
shishi_kdcreq_set_realmserver (Shishi * handle,
			       ASN1_TYPE req, char *realm, char *server)
{
  int res;

  res = shishi_kdcreq_set_realm (handle, req, realm);
  if (res != SHISHI_OK)
    return res;

  res = shishi_kdcreq_set_server (handle, req, server);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_kdcreq_add_padata:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcreq: KDC-REQ to add PA-DATA to.
 * @padatatype: type of PA-DATA, see Shishi_padata_type.
 * @data: input array with PA-DATA value.
 * @datalen: size of input array with PA-DATA value.
 *
 * Add new pre authentication data (PA-DATA) to KDC-REQ.  This is used
 * to pass various information to KDC, such as in case of a
 * SHISHI_PA_TGS_REQ padatatype the AP-REQ that authenticates the user
 * to get the ticket.  (But also see shishi_kdcreq_add_padata_tgs()
 * which takes an AP-REQ directly.)
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcreq_add_padata (Shishi * handle,
			  ASN1_TYPE kdcreq,
			  int padatatype, char *data, int datalen)
{
  char format[BUFSIZ];
  char buf[BUFSIZ];
  int res;
  int i;

  res = asn1_write_value (kdcreq, "KDC-REQ.padata", "NEW", 1);
  if (res != ASN1_SUCCESS)
    goto error;

  res = asn1_number_of_elements (kdcreq, "KDC-REQ.padata", &i);
  if (res != ASN1_SUCCESS)
    goto error;

  sprintf (format, "KDC-REQ.padata.?%d.padata-value", i);
  res = asn1_write_value (kdcreq, format, data, datalen);
  if (res != ASN1_SUCCESS)
    goto error;

  sprintf (buf, "%d", padatatype);
  sprintf (format, "KDC-REQ.padata.?%d.padata-type", i);
  res = asn1_write_value (kdcreq, format, buf, 0);
  if (res != ASN1_SUCCESS)
    goto error;

  return SHISHI_OK;

error:
  shishi_error_set (handle, libtasn1_strerror (res));
  return SHISHI_ASN1_ERROR;
}

/**
 * shishi_kdcreq_add_padata_tgs:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcreq: KDC-REQ to add PA-DATA to.
 * @apreq: AP-REQ to add as PA-DATA.
 *
 * Add TGS pre-authentication data to KDC-REQ.  The data is an AP-REQ
 * that authenticates the request.  This functions simply DER encodes
 * the AP-REQ and calls shishi_kdcreq_add_padata() with a
 * SHISHI_PA_TGS_REQ padatatype.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcreq_add_padata_tgs (Shishi * handle,
			      ASN1_TYPE kdcreq, ASN1_TYPE apreq)
{
  int res;
  char data[BUFSIZ];
  int datalen;
  char errorDescription[MAX_ERROR_DESCRIPTION_SIZE];

  res = asn1_der_coding (apreq, "AP-REQ", data, &datalen, errorDescription);
  if (res != ASN1_SUCCESS)
    {
      shishi_error_printf (handle, "Could not DER encode AP-REQ: %s\n",
			   errorDescription);
      return SHISHI_ASN1_ERROR;
    }

  res = shishi_kdcreq_add_padata (handle, kdcreq,
				  SHISHI_PA_TGS_REQ, data, datalen);

  return res;
}
