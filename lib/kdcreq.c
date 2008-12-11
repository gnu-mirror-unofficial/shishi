/* kdcreq.c --- Key distribution (AS/TGS) request functions.
 * Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008  Simon Josefsson
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Shishi; if not, see http://www.gnu.org/licenses or write
 * to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
 * Floor, Boston, MA 02110-1301, USA
 *
 */

#include "internal.h"

/* Get _shishi_print_armored_data, etc. */
#include "diskio.h"

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

static Shishi_asn1
_shishi_kdcreq (Shishi * handle, int as)
{
  int res;
  Shishi_asn1 node;
  const char *servicebuf[3];
  uint32_t nonce;

  if (as)
    node = shishi_asn1_asreq (handle);
  else
    node = shishi_asn1_tgsreq (handle);
  if (!node)
    return NULL;

  res = shishi_asn1_write (handle, node, "pvno",
			   SHISHI_KDCREQ_DEFAULT_PVNO,
			   SHISHI_KDCREQ_DEFAULT_PVNO_LEN);
  if (res != SHISHI_OK)
    goto error;

  if (as)
    res = shishi_asn1_write (handle, node, "msg-type",
			     SHISHI_AS_REQ_DEFAULT_MSG_TYPE,
			     SHISHI_AS_REQ_DEFAULT_MSG_TYPE_LEN);
  else
    res = shishi_asn1_write (handle, node, "msg-type",
			     SHISHI_TGS_REQ_DEFAULT_MSG_TYPE,
			     SHISHI_TGS_REQ_DEFAULT_MSG_TYPE_LEN);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_write (handle, node, "req-body.kdc-options",
			   SHISHI_KDCREQ_DEFAULT_REQ_BODY_KDC_OPTIONS,
			   SHISHI_KDCREQ_DEFAULT_REQ_BODY_KDC_OPTIONS_LEN);
  if (res != SHISHI_OK)
    goto error;

  if (as)
    res = shishi_kdcreq_set_cname (handle, node, SHISHI_NT_PRINCIPAL,
				   shishi_principal_default (handle));
  else
    res = shishi_asn1_write (handle, node, "req-body.cname", NULL, 0);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_kdcreq_set_realm (handle, node, shishi_realm_default (handle));
  if (res != SHISHI_OK)
    goto error;

  servicebuf[0] = "krbtgt";
  servicebuf[1] = shishi_realm_default (handle);
  servicebuf[2] = NULL;
  res = shishi_kdcreq_set_sname (handle, node,
				 SHISHI_NT_PRINCIPAL, servicebuf);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_write (handle, node, "req-body.sname.name-type",
			   SHISHI_KDCREQ_DEFAULT_REQ_BODY_SNAME_NAME_TYPE,
			   SHISHI_KDCREQ_DEFAULT_REQ_BODY_SNAME_NAME_TYPE_LEN);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_write (handle, node, "req-body.till",
			   shishi_generalize_time (handle,
						   time (NULL) +
						   handle->ticketlife), 0);
  if (res != SHISHI_OK)
    goto error;

  shishi_randomize (handle, 0, &nonce, sizeof (nonce));
  nonce &= 0x7FFFFFFF;		/* XXX fix _libtasn1_convert_integer. */
  res = shishi_kdcreq_nonce_set (handle, node, nonce);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_kdcreq_set_etype (handle, node, handle->clientkdcetypes,
				 handle->nclientkdcetypes);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_write (handle, node, "req-body.addresses", NULL, 0);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_write (handle, node,
			   "req-body.enc-authorization-data", NULL, 0);
  if (res != SHISHI_OK)
    goto error;

  res =
    shishi_asn1_write (handle, node, "req-body.additional-tickets", NULL, 0);
  if (res != SHISHI_OK)
    goto error;

  return node;

error:
  shishi_asn1_done (handle, node);
  return NULL;
}

/**
 * shishi_asreq:
 * @handle: shishi handle as allocated by shishi_init().
 *
 * This function creates a new AS-REQ, populated with some default
 * values.
 *
 * Return value: Returns the AS-REQ or NULL on failure.
 **/
Shishi_asn1
shishi_asreq (Shishi * handle)
{
  return _shishi_kdcreq (handle, 1);
}

/**
 * shishi_tgsreq:
 * @handle: shishi handle as allocated by shishi_init().
 *
 * This function creates a new TGS-REQ, populated with some default
 * values.
 *
 * Return value: Returns the TGS-REQ or NULL on failure.
 **/
Shishi_asn1
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
shishi_kdcreq_print (Shishi * handle, FILE * fh, Shishi_asn1 kdcreq)
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
shishi_kdcreq_save (Shishi * handle, FILE * fh, Shishi_asn1 kdcreq)
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
shishi_kdcreq_to_file (Shishi * handle, Shishi_asn1 kdcreq,
		       int filetype, const char *filename)
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
    return SHISHI_IO_ERROR;

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
shishi_kdcreq_parse (Shishi * handle, FILE * fh, Shishi_asn1 * kdcreq)
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
shishi_kdcreq_read (Shishi * handle, FILE * fh, Shishi_asn1 * kdcreq)
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
shishi_kdcreq_from_file (Shishi * handle, Shishi_asn1 * kdcreq,
			 int filetype, const char *filename)
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
    return SHISHI_IO_ERROR;

  if (VERBOSE (handle))
    printf (_("Reading KDC-REQ from %s...done\n"), filename);

  return SHISHI_OK;
}

int
shishi_kdcreq_nonce (Shishi * handle, Shishi_asn1 kdcreq, uint32_t * nonce)
{
  int res;

  res = shishi_asn1_read_uint32 (handle, kdcreq, "req-body.nonce", nonce);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_kdcreq_nonce_set:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcreq: KDC-REQ variable to set client name field in.
 * @nonce: integer nonce to store in KDC-REQ.
 *
 * Store nonce number field in KDC-REQ.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_kdcreq_nonce_set (Shishi * handle, Shishi_asn1 kdcreq, uint32_t nonce)
{
  int res;

  res = shishi_asn1_write_uint32 (handle, kdcreq, "req-body.nonce", nonce);
  if (res != SHISHI_OK)
    return res;

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
			 Shishi_asn1 kdcreq,
			 Shishi_name_type name_type, const char *principal)
{
  int res;

  res = shishi_principal_set (handle, kdcreq, "req-body.cname", principal);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_kdcreq_client:
 * @handle: Shishi library handle create by shishi_init().
 * @kdcreq: KDC-REQ variable to get client name from.
 * @client: pointer to newly allocated zero terminated string containing
 *   principal name.  May be %NULL (to only populate @clientlen).
 * @clientlen: pointer to length of @client on output, excluding terminating
 *   zero.  May be %NULL (to only populate @client).
 *
 * Represent client principal name in KDC-REQ as zero-terminated
 * string.  The string is allocate by this function, and it is the
 * responsibility of the caller to deallocate it.  Note that the
 * output length @clientlen does not include the terminating zero.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcreq_client (Shishi * handle, Shishi_asn1 kdcreq,
		      char **client, size_t * clientlen)
{
  return shishi_principal_name (handle, kdcreq, "req-body.cname",
				client, clientlen);
}

/**
 * shishi_asreq_clientrealm:
 * @handle: Shishi library handle create by shishi_init().
 * @asreq: AS-REQ variable to get client name and realm from.
 * @client: pointer to newly allocated zero terminated string containing
 *   principal name and realm.  May be %NULL (to only populate @clientlen).
 * @clientlen: pointer to length of @client on output, excluding terminating
 *   zero.  May be %NULL (to only populate @client).
 *
 * Convert cname and realm fields from AS-REQ to printable principal
 * name format.  The string is allocate by this function, and it is
 * the responsibility of the caller to deallocate it.  Note that the
 * output length @clientlen does not include the terminating zero.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_asreq_clientrealm (Shishi * handle,
			  Shishi_asn1 asreq,
			  char **client, size_t * clientlen)
{
  return shishi_principal_name_realm (handle,
				      asreq, "req-body.cname",
				      asreq, "req-body.realm",
				      client, clientlen);
}

/**
 * shishi_kdcreq_realm:
 * @handle: Shishi library handle create by shishi_init().
 * @kdcreq: KDC-REQ variable to get client name from.
 * @realm: pointer to newly allocated zero terminated string containing
 *   realm.  May be %NULL (to only populate @realmlen).
 * @realmlen: pointer to length of @realm on output, excluding terminating
 *   zero.  May be %NULL (to only populate @realmlen).
 *
 * Get realm field in KDC-REQ as zero-terminated string.  The string
 * is allocate by this function, and it is the responsibility of the
 * caller to deallocate it.  Note that the output length @realmlen
 * does not include the terminating zero.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcreq_realm (Shishi * handle, Shishi_asn1 kdcreq,
		     char **realm, size_t * realmlen)
{
  return shishi_asn1_read_optional (handle, kdcreq, "req-body.realm",
				    realm, realmlen);
}

int
shishi_kdcreq_realm_get (Shishi * handle, Shishi_asn1 kdcreq,
			 char **realm, size_t * realmlen)
{
  return shishi_asn1_read_optional (handle, kdcreq, "req-body.realm",
				    realm, realmlen);
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
shishi_kdcreq_set_realm (Shishi * handle, Shishi_asn1 kdcreq,
			 const char *realm)
{
  int res;

  res = shishi_asn1_write (handle, kdcreq, "req-body.realm", realm, 0);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_kdcreq_server:
 * @handle: Shishi library handle create by shishi_init().
 * @kdcreq: KDC-REQ variable to get server name from.
 * @server: pointer to newly allocated zero terminated string containing
 *   principal name.  May be %NULL (to only populate @serverlen).
 * @serverlen: pointer to length of @server on output, excluding terminating
 *   zero.  May be %NULL (to only populate @server).
 *
 * Represent server principal name in KDC-REQ as zero-terminated
 * string.  The string is allocate by this function, and it is the
 * responsibility of the caller to deallocate it.  Note that the
 * output length @serverlen does not include the terminating zero.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcreq_server (Shishi * handle, Shishi_asn1 kdcreq,
		      char **server, size_t * serverlen)
{
  return shishi_principal_name (handle, kdcreq, "req-body.sname",
				server, serverlen);
}

/**
 * shishi_kdcreq_set_sname:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcreq: KDC-REQ variable to set server name field in.
 * @name_type: type of principial, see Shishi_name_type, usually
 *             SHISHI_NT_UNKNOWN.
 * @sname: input array with principal name.
 *
 * Set the server name field in the KDC-REQ.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcreq_set_sname (Shishi * handle,
			 Shishi_asn1 kdcreq,
			 Shishi_name_type name_type, const char *sname[])
{
  int res;

  res = shishi_principal_name_set (handle, kdcreq, "req-body.sname",
				   name_type, sname);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

int
shishi_kdcreq_set_server (Shishi * handle, Shishi_asn1 req,
			  const char *server)
{
  int res;

  res = shishi_principal_set (handle, req, "req-body.sname", server);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

int
shishi_kdcreq_set_realmserver (Shishi * handle,
			       Shishi_asn1 req, char *realm, char *server)
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
 * shishi_kdcreq_till:
 * @handle: Shishi library handle create by shishi_init().
 * @kdcreq: KDC-REQ variable to get client name from.
 * @till: pointer to newly allocated zero terminated string containing
 *   "till" field with generalized time.  May be %NULL (to only
 *   populate @realmlen).
 * @tilllen: pointer to length of @till on output, excluding
 *   terminating zero.  May be %NULL (to only populate @tilllen).
 *
 * Get "till" field (i.e. "endtime") in KDC-REQ, as zero-terminated
 * string.  The string is typically 15 characters long.  The string is
 * allocated by this function, and it is the responsibility of the
 * caller to deallocate it.  Note that the output length @realmlen
 * does not include the terminating zero.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcreq_till (Shishi * handle, Shishi_asn1 kdcreq,
		    char **till, size_t * tilllen)
{
  return shishi_asn1_read (handle, kdcreq, "req-body.till", till, tilllen);
}

/**
 * shishi_kdcreq_tillc:
 * @handle: Shishi library handle create by shishi_init().
 * @kdcreq: KDC-REQ variable to get till field from.
 *
 * Extract C time corresponding to the "till" field.
 *
 * Return value: Returns C time interpretation of the "till" field in
 * KDC-REQ.
 **/
time_t
shishi_kdcreq_tillc (Shishi * handle, Shishi_asn1 kdcreq)
{
  char *till;
  size_t tilllen;
  time_t t = (time_t) - 1;
  int res;

  res = shishi_kdcreq_till (handle, kdcreq, &till, &tilllen);
  if (res != SHISHI_OK)
    return t;

  if (tilllen == SHISHI_GENERALIZEDTIME_LENGTH + 1)	/* XXX why +1 ? */
    t = shishi_generalize_ctime (handle, till);

  free (till);

  return t;
}

/**
 * shishi_kdcreq_etype:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcreq: KDC-REQ variable to get etype field from.
 * @etype: output encryption type.
 * @netype: element number to return.
 *
 * Return the netype:th encryption type from KDC-REQ.  The first etype
 * is number 1.
 *
 * Return value: Returns SHISHI_OK iff etype successful set.
 **/
int
shishi_kdcreq_etype (Shishi * handle,
		     Shishi_asn1 kdcreq, int32_t * etype, int netype)
{
  char *buf;
  int res;

  asprintf (&buf, "req-body.etype.?%d", netype);
  res = shishi_asn1_read_int32 (handle, kdcreq, buf, etype);
  if (res != SHISHI_OK)
    return res;

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
			 Shishi_asn1 kdcreq, int32_t * etype, int netype)
{
  int res;
  char *buf;
  int i;

  res = shishi_asn1_write (handle, kdcreq, "req-body.etype", NULL, 0);
  if (res != SHISHI_OK)
    return res;

  for (i = 1; i <= netype; i++)
    {
      res = shishi_asn1_write (handle, kdcreq, "req-body.etype", "NEW", 1);
      if (res != SHISHI_OK)
	return res;

      asprintf (&buf, "req-body.etype.?%d", i);
      res = shishi_asn1_write_int32 (handle, kdcreq, buf, etype[i - 1]);
      free (buf);
      if (res != SHISHI_OK)
	return res;
    }

  return SHISHI_OK;
}

/**
 * shishi_kdcreq_options:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcreq: KDC-REQ variable to get kdc-options field from.
 * @flags: pointer to output integer with flags.
 *
 * Extract KDC-Options from KDC-REQ.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcreq_options (Shishi * handle, Shishi_asn1 kdcreq, uint32_t * flags)
{
  return shishi_asn1_read_bitstring (handle, kdcreq,
				     "req-body.kdc-options", flags);
}

/**
 * shishi_kdcreq_forwardable_p:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcreq: KDC-REQ variable to get kdc-options field from.
 *
 * Determine if KDC-Option forwardable flag is set.
 *
 * The FORWARDABLE option indicates that the ticket to be issued is to
 * have its forwardable flag set. It may only be set on the initial
 * request, or in a subsequent request if the ticket-granting ticket
 * on which it is based is also forwardable.
 *
 * Return value: Returns non-0 iff forwardable flag is set in KDC-REQ.
 **/
int
shishi_kdcreq_forwardable_p (Shishi * handle, Shishi_asn1 kdcreq)
{
  uint32_t options = 0;

  shishi_kdcreq_options (handle, kdcreq, &options);

  return options & SHISHI_KDCOPTIONS_FORWARDABLE;
}

/**
 * shishi_kdcreq_forwarded_p:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcreq: KDC-REQ variable to get kdc-options field from.
 *
 * Determine if KDC-Option forwarded flag is set.
 *
 * The FORWARDED option is only specified in a request to the
 * ticket-granting server and will only be honored if the
 * ticket-granting ticket in the request has its FORWARDABLE bit
 * set. This option indicates that this is a request for
 * forwarding. The address(es) of the host from which the resulting
 * ticket is to be valid are included in the addresses field of the
 * request.
 *
 * Return value: Returns non-0 iff forwarded flag is set in KDC-REQ.
 **/
int
shishi_kdcreq_forwarded_p (Shishi * handle, Shishi_asn1 kdcreq)
{
  uint32_t options = 0;

  shishi_kdcreq_options (handle, kdcreq, &options);

  return options & SHISHI_KDCOPTIONS_FORWARDED;
}

/**
 * shishi_kdcreq_proxiable_p:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcreq: KDC-REQ variable to get kdc-options field from.
 *
 * Determine if KDC-Option proxiable flag is set.
 *
 * The PROXIABLE option indicates that the ticket to be issued is to
 * have its proxiable flag set. It may only be set on the initial
 * request, or in a subsequent request if the ticket-granting ticket
 * on which it is based is also proxiable.
 *
 * Return value: Returns non-0 iff proxiable flag is set in KDC-REQ.
 **/
int
shishi_kdcreq_proxiable_p (Shishi * handle, Shishi_asn1 kdcreq)
{
  uint32_t options = 0;

  shishi_kdcreq_options (handle, kdcreq, &options);

  return options & SHISHI_KDCOPTIONS_PROXIABLE;
}

/**
 * shishi_kdcreq_proxy_p:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcreq: KDC-REQ variable to get kdc-options field from.
 *
 * Determine if KDC-Option proxy flag is set.
 *
 * The PROXY option indicates that this is a request for a proxy. This
 * option will only be honored if the ticket-granting ticket in the
 * request has its PROXIABLE bit set.  The address(es) of the host
 * from which the resulting ticket is to be valid are included in the
 * addresses field of the request.
 *
 * Return value: Returns non-0 iff proxy flag is set in KDC-REQ.
 **/
int
shishi_kdcreq_proxy_p (Shishi * handle, Shishi_asn1 kdcreq)
{
  uint32_t options = 0;

  shishi_kdcreq_options (handle, kdcreq, &options);

  return options & SHISHI_KDCOPTIONS_PROXY;
}

/**
 * shishi_kdcreq_allow_postdate_p:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcreq: KDC-REQ variable to get kdc-options field from.
 *
 * Determine if KDC-Option allow-postdate flag is set.
 *
 * The ALLOW-POSTDATE option indicates that the ticket to be issued is
 * to have its MAY-POSTDATE flag set. It may only be set on the
 * initial request, or in a subsequent request if the ticket-granting
 * ticket on which it is based also has its MAY-POSTDATE flag set.
 *
 * Return value: Returns non-0 iff allow-postdate flag is set in KDC-REQ.
 **/
int
shishi_kdcreq_allow_postdate_p (Shishi * handle, Shishi_asn1 kdcreq)
{
  uint32_t options = 0;

  shishi_kdcreq_options (handle, kdcreq, &options);

  return options & SHISHI_KDCOPTIONS_ALLOW_POSTDATE;
}

/**
 * shishi_kdcreq_postdated_p:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcreq: KDC-REQ variable to get kdc-options field from.
 *
 * Determine if KDC-Option postdated flag is set.
 *
 * The POSTDATED option indicates that this is a request for a
 * postdated ticket. This option will only be honored if the
 * ticket-granting ticket on which it is based has its MAY-POSTDATE
 * flag set. The resulting ticket will also have its INVALID flag set,
 * and that flag may be reset by a subsequent request to the KDC after
 * the starttime in the ticket has been reached.
 *
 * Return value: Returns non-0 iff postdated flag is set in KDC-REQ.
 **/
int
shishi_kdcreq_postdated_p (Shishi * handle, Shishi_asn1 kdcreq)
{
  uint32_t options = 0;

  shishi_kdcreq_options (handle, kdcreq, &options);

  return options & SHISHI_KDCOPTIONS_POSTDATED;
}

/**
 * shishi_kdcreq_renewable_p:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcreq: KDC-REQ variable to get kdc-options field from.
 *
 * Determine if KDC-Option renewable flag is set.
 *
 * The RENEWABLE option indicates that the ticket to be issued is to
 * have its RENEWABLE flag set. It may only be set on the initial
 * request, or when the ticket-granting ticket on which the request is
 * based is also renewable. If this option is requested, then the
 * rtime field in the request contains the desired absolute expiration
 * time for the ticket.
 *
 * Return value: Returns non-0 iff renewable flag is set in KDC-REQ.
 **/
int
shishi_kdcreq_renewable_p (Shishi * handle, Shishi_asn1 kdcreq)
{
  uint32_t options = 0;

  shishi_kdcreq_options (handle, kdcreq, &options);

  return options & SHISHI_KDCOPTIONS_RENEWABLE;
}

/**
 * shishi_kdcreq_disable_transited_check_p:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcreq: KDC-REQ variable to get kdc-options field from.
 *
 * Determine if KDC-Option disable-transited-check flag is set.
 *
 * By default the KDC will check the transited field of a
 * ticket-granting-ticket against the policy of the local realm before
 * it will issue derivative tickets based on the ticket-granting
 * ticket. If this flag is set in the request, checking of the
 * transited field is disabled. Tickets issued without the performance
 * of this check will be noted by the reset (0) value of the
 * TRANSITED-POLICY-CHECKED flag, indicating to the application server
 * that the tranisted field must be checked locally. KDCs are
 * encouraged but not required to honor the DISABLE-TRANSITED-CHECK
 * option.
 *
 * This flag is new since RFC 1510
 *
 * Return value: Returns non-0 iff disable-transited-check flag is set
 *   in KDC-REQ.
 **/
int
shishi_kdcreq_disable_transited_check_p (Shishi * handle, Shishi_asn1 kdcreq)
{
  uint32_t options = 0;

  shishi_kdcreq_options (handle, kdcreq, &options);

  return options & SHISHI_KDCOPTIONS_DISABLE_TRANSITED_CHECK;
}

/**
 * shishi_kdcreq_renewable_ok_p:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcreq: KDC-REQ variable to get kdc-options field from.
 *
 * Determine if KDC-Option renewable-ok flag is set.
 *
 * The RENEWABLE-OK option indicates that a renewable ticket will be
 * acceptable if a ticket with the requested life cannot otherwise be
 * provided. If a ticket with the requested life cannot be provided,
 * then a renewable ticket may be issued with a renew-till equal to
 * the requested endtime. The value of the renew-till field may still
 * be limited by local limits, or limits selected by the individual
 * principal or server.
 *
 * Return value: Returns non-0 iff renewable-ok flag is set in KDC-REQ.
 **/
int
shishi_kdcreq_renewable_ok_p (Shishi * handle, Shishi_asn1 kdcreq)
{
  uint32_t options = 0;

  shishi_kdcreq_options (handle, kdcreq, &options);

  return options & SHISHI_KDCOPTIONS_RENEWABLE_OK;
}

/**
 * shishi_kdcreq_enc_tkt_in_skey_p:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcreq: KDC-REQ variable to get kdc-options field from.
 *
 * Determine if KDC-Option enc-tkt-in-skey flag is set.
 *
 * This option is used only by the ticket-granting service. The
 * ENC-TKT-IN-SKEY option indicates that the ticket for the end server
 * is to be encrypted in the session key from the additional
 * ticket-granting ticket provided.
 *
 * Return value: Returns non-0 iff enc-tkt-in-skey flag is set in KDC-REQ.
 **/
int
shishi_kdcreq_enc_tkt_in_skey_p (Shishi * handle, Shishi_asn1 kdcreq)
{
  uint32_t options = 0;

  shishi_kdcreq_options (handle, kdcreq, &options);

  return options & SHISHI_KDCOPTIONS_ENC_TKT_IN_SKEY;
}

/**
 * shishi_kdcreq_renew_p:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcreq: KDC-REQ variable to get kdc-options field from.
 *
 * Determine if KDC-Option renew flag is set.
 *
 * This option is used only by the ticket-granting service. The RENEW
 * option indicates that the present request is for a renewal. The
 * ticket provided is encrypted in the secret key for the server on
 * which it is valid. This option will only be honored if the ticket
 * to be renewed has its RENEWABLE flag set and if the time in its
 * renew-till field has not passed. The ticket to be renewed is passed
 * in the padata field as part of the authentication header.
 *
 * Return value: Returns non-0 iff renew flag is set in KDC-REQ.
 **/
int
shishi_kdcreq_renew_p (Shishi * handle, Shishi_asn1 kdcreq)
{
  uint32_t options = 0;

  shishi_kdcreq_options (handle, kdcreq, &options);

  return options & SHISHI_KDCOPTIONS_RENEW;
}

/**
 * shishi_kdcreq_validate_p:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcreq: KDC-REQ variable to get kdc-options field from.
 *
 * Determine if KDC-Option validate flag is set.
 *
 * This option is used only by the ticket-granting service. The
 * VALIDATE option indicates that the request is to validate a
 * postdated ticket. It will only be honored if the ticket presented
 * is postdated, presently has its INVALID flag set, and would be
 * otherwise usable at this time. A ticket cannot be validated before
 * its starttime. The ticket presented for validation is encrypted in
 * the key of the server for which it is valid and is passed in the
 * padata field as part of the authentication header.
 *
 * Return value: Returns non-0 iff validate flag is set in KDC-REQ.
 **/
int
shishi_kdcreq_validate_p (Shishi * handle, Shishi_asn1 kdcreq)
{
  uint32_t options = 0;

  shishi_kdcreq_options (handle, kdcreq, &options);

  return options & SHISHI_KDCOPTIONS_VALIDATE;
}

/**
 * shishi_kdcreq_options_set:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcreq: KDC-REQ variable to set etype field in.
 * @options: integer with flags to store in KDC-REQ.
 *
 * Set options in KDC-REQ.  Note that this reset any already existing
 * flags.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcreq_options_set (Shishi * handle,
			   Shishi_asn1 kdcreq, uint32_t options)
{
  int res;

  res = shishi_asn1_write_bitstring (handle, kdcreq,
				     "req-body.kdc-options", options);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_kdcreq_options_add:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcreq: KDC-REQ variable to set etype field in.
 * @option: integer with options to add in KDC-REQ.
 *
 * Add KDC-Option to KDC-REQ.  This preserves all existing options.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcreq_options_add (Shishi * handle,
			   Shishi_asn1 kdcreq, uint32_t option)
{
  uint32_t options;
  int res;

  res = shishi_kdcreq_options (handle, kdcreq, &options);
  if (res != SHISHI_OK)
    return res;

  options |= option;

  res = shishi_kdcreq_options_set (handle, kdcreq, options);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_kdcreq_clear_padata:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcreq: KDC-REQ to remove PA-DATA from.
 *
 * Remove the padata field from KDC-REQ.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcreq_clear_padata (Shishi * handle, Shishi_asn1 kdcreq)
{
  int res;

  res = shishi_asn1_write (handle, kdcreq, "padata", NULL, 0);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_kdcreq_get_padata:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcreq: KDC-REQ to get PA-DATA from.
 * @padatatype: type of PA-DATA, see Shishi_padata_type.
 * @out: output array with newly allocated PA-DATA value.
 * @outlen: size of output array with PA-DATA value.
 *
 * Get pre authentication data (PA-DATA) from KDC-REQ.  Pre
 * authentication data is used to pass various information to KDC,
 * such as in case of a SHISHI_PA_TGS_REQ padatatype the AP-REQ that
 * authenticates the user to get the ticket.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcreq_get_padata (Shishi * handle,
			  Shishi_asn1 kdcreq,
			  Shishi_padata_type padatatype,
			  char **out, size_t * outlen)
{
  char *format;
  int res;
  size_t i, n;

  res = shishi_asn1_number_of_elements (handle, kdcreq, "padata", &n);
  if (res != SHISHI_OK)
    return res;

  *out = NULL;
  *outlen = 0;

  for (i = 1; i <= n; i++)
    {
      int32_t patype;

      asprintf (&format, "padata.?%d.padata-type", i);
      res = shishi_asn1_read_int32 (handle, kdcreq, format, &patype);
      free (format);
      if (res != SHISHI_OK)
	return res;

      if (patype == (int32_t) padatatype)
	{
	  asprintf (&format, "padata.?%d.padata-value", i);
	  res = shishi_asn1_read (handle, kdcreq, format, out, outlen);
	  free (format);
	  if (res != SHISHI_OK)
	    return res;
	  break;
	}
    }

  return SHISHI_OK;
}

/**
 * shishi_kdcreq_get_padata_tgs:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcreq: KDC-REQ to get PA-TGS-REQ from.
 * @apreq: Output variable with newly allocated AP-REQ.
 *
 * Extract TGS pre-authentication data from KDC-REQ.  The data is an
 * AP-REQ that authenticates the request.  This function call
 * shishi_kdcreq_get_padata() with a SHISHI_PA_TGS_REQ padatatype and
 * DER decode the result (if any).
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcreq_get_padata_tgs (Shishi * handle,
			      Shishi_asn1 kdcreq, Shishi_asn1 * apreq)
{
  char *der;
  size_t derlen;
  int rc;

  if (VERBOSE (handle))
    printf ("Extracting AP-REQ from KDC-REQ...\n");

  rc = shishi_kdcreq_get_padata (handle, kdcreq, SHISHI_PA_TGS_REQ,
				 &der, &derlen);
  if (rc != SHISHI_OK)
    return rc;

  *apreq = shishi_der2asn1_apreq (handle, der, derlen);
  if (!*apreq)
    return SHISHI_ASN1_ERROR;

  if (VERBOSEASN1 (handle))
    shishi_apreq_print (handle, stdout, *apreq);

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
			  Shishi_asn1 kdcreq,
			  int padatatype, const char *data, size_t datalen)
{
  char *format;
  int res;
  size_t i;

  res = shishi_asn1_write (handle, kdcreq, "padata", "NEW", 1);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_number_of_elements (handle, kdcreq, "padata", &i);
  if (res != SHISHI_OK)
    return res;

  asprintf (&format, "padata.?%d.padata-value", i);
  res = shishi_asn1_write (handle, kdcreq, format, data, datalen);
  free (format);
  if (res != SHISHI_OK)
    return res;

  asprintf (&format, "padata.?%d.padata-type", i);
  res = shishi_asn1_write_uint32 (handle, kdcreq, format, padatatype);
  free (format);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
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
			      Shishi_asn1 kdcreq, Shishi_asn1 apreq)
{
  int res;
  char *data;
  size_t datalen;

  res = shishi_asn1_to_der (handle, apreq, &data, &datalen);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "Could not DER encode AP-REQ: %s\n",
			   shishi_strerror (res));
      return res;
    }

  res = shishi_kdcreq_add_padata (handle, kdcreq,
				  SHISHI_PA_TGS_REQ, data, datalen);
  free (data);
  if (res != SHISHI_OK)
    return res;

  return res;
}

/**
 * shishi_kdcreq_add_padata_preauth:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcreq: KDC-REQ to add pre-authentication data to.
 * @key: Key used to encrypt pre-auth data.
 *
 * Add pre-authentication data to KDC-REQ.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcreq_add_padata_preauth (Shishi * handle,
				  Shishi_asn1 kdcreq,
				  Shishi_key *key)
{
  char *der, *data;
  size_t derlen, datalen;
  Shishi_asn1 pa;
  struct timespec ts;
  int rc;
  Shishi_asn1 ed;

  pa = shishi_asn1_pa_enc_ts_enc (handle);
  if (!pa)
    return SHISHI_ASN1_ERROR;

  gettime (&ts);

  rc = shishi_asn1_write (handle, pa, "patimestamp",
			  shishi_generalize_time (handle, ts.tv_sec),
			  SHISHI_GENERALIZEDTIME_LENGTH);
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_asn1_write_integer (handle, pa, "pausec", ts.tv_nsec / 1000);
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_asn1_to_der (handle, pa, &der, &derlen);
  if (rc != SHISHI_OK)
      return rc;

  rc = shishi_encrypt (handle, key, SHISHI_KEYUSAGE_ASREQ_PA_ENC_TIMESTAMP,
		       der, derlen, &data, &datalen);
  free (der);
  if (rc != SHISHI_OK)
    return rc;

  ed = shishi_asn1_encrypteddata (handle);
  if (!ed)
    return SHISHI_ASN1_ERROR;

  rc = shishi_asn1_write_integer (handle, ed, "etype", shishi_key_type (key));
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_asn1_write (handle, ed, "cipher", data, datalen);
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_asn1_write (handle, ed, "kvno", NULL, 0);
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_asn1_to_der (handle, ed, &der, &derlen);
  free (data);
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_kdcreq_add_padata (handle, kdcreq, SHISHI_PA_ENC_TIMESTAMP,
				 der, derlen);
  free (der);
  if (rc != SHISHI_OK)
    return rc;

  return rc;
}

int
shishi_kdcreq_build (Shishi * handle, Shishi_asn1 kdcreq)
{
  int res;
  size_t n;
  int msgtype;

  shishi_verbose (handle, "Building KDC-REQ...");

  if (shishi_asn1_empty_p (handle, kdcreq, "req-body.rtime"))
    {
      res = shishi_asn1_write (handle, kdcreq, "req-body.rtime", NULL, 0);
      if (res != SHISHI_OK)
	{
	  shishi_error_printf (handle, "Could not write rtime\n");
	  return res;
	}
    }

  if (shishi_asn1_empty_p (handle, kdcreq, "req-body.from"))
    {
      res = shishi_asn1_write (handle, kdcreq, "req-body.from", NULL, 0);
      if (res != SHISHI_OK)
	{
	  shishi_error_printf (handle, "Could not write from\n");
	  return res;
	}
    }

  res = shishi_asn1_read_integer (handle, kdcreq, "msg-type", &msgtype);
  if (res != SHISHI_OK)
    return res;
  if (msgtype == SHISHI_MSGTYPE_AS_REQ)
    {
      res = shishi_asn1_number_of_elements (handle, kdcreq, "padata", &n);
      if (res == SHISHI_OK && n == 0)
	{
	  res = shishi_kdcreq_clear_padata (handle, kdcreq);
	  if (res != SHISHI_OK)
	    {
	      shishi_error_printf (handle, "Could not write padata\n");
	      return res;
	    }
	}
    }

  return SHISHI_OK;
}
