/* krberror.c --- Functions related to KRB-ERROR packet.
 * Copyright (C) 2002, 2003, 2004, 2006, 2007  Simon Josefsson
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

#define SHISHI_KRB_ERROR_DEFAULT_PVNO      "5"
#define SHISHI_KRB_ERROR_DEFAULT_PVNO_LEN  0
#define SHISHI_KRB_ERROR_DEFAULT_MSG_TYPE      "30"
#define SHISHI_KRB_ERROR_DEFAULT_MSG_TYPE_LEN  0

/**
 * shishi_krberror:
 * @handle: shishi handle as allocated by shishi_init().
 *
 * This function creates a new KRB-ERROR, populated with some default
 * values.
 *
 * Return value: Returns the KRB-ERROR or NULL on failure.
 **/
Shishi_asn1
shishi_krberror (Shishi * handle)
{
  Shishi_asn1 krberror;
  struct timeval tv;
  int rc;

  rc = gettimeofday (&tv, NULL);
  if (rc != 0)
    return NULL;

  krberror = shishi_asn1_krberror (handle);
  if (!krberror)
    return NULL;

  rc = shishi_asn1_write (handle, krberror, "pvno",
			  SHISHI_KRB_ERROR_DEFAULT_PVNO,
			  SHISHI_KRB_ERROR_DEFAULT_PVNO_LEN);

  if (rc == SHISHI_OK)
    rc = shishi_asn1_write (handle, krberror, "msg-type",
			    SHISHI_KRB_ERROR_DEFAULT_MSG_TYPE,
			    SHISHI_KRB_ERROR_DEFAULT_MSG_TYPE_LEN);


  if (rc == SHISHI_OK)
    rc = shishi_krberror_susec_set (handle, krberror, tv.tv_usec % 1000000);

  if (rc == SHISHI_OK)
    rc = shishi_asn1_write (handle, krberror, "stime",
			    shishi_generalize_now (handle), 0);

  if (rc != SHISHI_OK)
    {
      shishi_error_printf (handle, "shishi_krberror() failed");
      shishi_asn1_done (handle, krberror);
      krberror = NULL;
    }

  return krberror;
}

/**
 * shishi_krberror_print:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle open for writing.
 * @krberror: KRB-ERROR to print.
 *
 * Print ASCII armored DER encoding of KRB-ERROR to file.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_print (Shishi * handle, FILE * fh, Shishi_asn1 krberror)
{
  return _shishi_print_armored_data (handle, fh, krberror, "KRB-ERROR", NULL);
}

/**
 * shishi_krberror_save:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle open for writing.
 * @krberror: KRB-ERROR to save.
 *
 * Save DER encoding of KRB-ERROR to file.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_save (Shishi * handle, FILE * fh, Shishi_asn1 krberror)
{
  return _shishi_save_data (handle, fh, krberror, "KRB-ERROR");
}

/**
 * shishi_krberror_to_file:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: KRB-ERROR to save.
 * @filetype: input variable specifying type of file to be written,
 *            see Shishi_filetype.
 * @filename: input variable with filename to write to.
 *
 * Write KRB-ERROR to file in specified TYPE.  The file will be
 * truncated if it exists.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_to_file (Shishi * handle, Shishi_asn1 krberror,
			 int filetype, const char *filename)
{
  FILE *fh;
  int res;

  if (VERBOSE (handle))
    printf (_("Writing KRB-ERROR to %s...\n"), filename);

  fh = fopen (filename, "w");
  if (fh == NULL)
    return SHISHI_FOPEN_ERROR;

  if (VERBOSE (handle))
    printf (_("Writing KRB-ERROR in %s format...\n"),
	    filetype == SHISHI_FILETYPE_TEXT ? "TEXT" : "DER");

  if (filetype == SHISHI_FILETYPE_TEXT)
    res = shishi_krberror_print (handle, fh, krberror);
  else
    res = shishi_krberror_save (handle, fh, krberror);
  if (res != SHISHI_OK)
    return res;

  res = fclose (fh);
  if (res != 0)
    return SHISHI_IO_ERROR;

  if (VERBOSE (handle))
    printf (_("Writing KRB-ERROR to %s...done\n"), filename);

  return SHISHI_OK;
}

/**
 * shishi_krberror_parse:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle open for reading.
 * @krberror: output variable with newly allocated KRB-ERROR.
 *
 * Read ASCII armored DER encoded KRB-ERROR from file and populate given
 * variable.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_parse (Shishi * handle, FILE * fh, Shishi_asn1 * krberror)
{
  return _shishi_krberror_input (handle, fh, krberror, 0);
}

/**
 * shishi_krberror_read:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle open for reading.
 * @krberror: output variable with newly allocated KRB-ERROR.
 *
 * Read DER encoded KRB-ERROR from file and populate given variable.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_read (Shishi * handle, FILE * fh, Shishi_asn1 * krberror)
{
  return _shishi_krberror_input (handle, fh, krberror, 1);
}

/**
 * shishi_krberror_from_file:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: output variable with newly allocated KRB-ERROR.
 * @filetype: input variable specifying type of file to be read,
 *            see Shishi_filetype.
 * @filename: input variable with filename to read from.
 *
 * Read KRB-ERROR from file in specified TYPE.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_from_file (Shishi * handle, Shishi_asn1 * krberror,
			   int filetype, const char *filename)
{
  int res;
  FILE *fh;

  if (VERBOSE (handle))
    printf (_("Reading KRB-ERROR from %s...\n"), filename);

  fh = fopen (filename, "r");
  if (fh == NULL)
    return SHISHI_FOPEN_ERROR;

  if (VERBOSE (handle))
    printf (_("Reading KRB-ERROR in %s format...\n"),
	    filetype == SHISHI_FILETYPE_TEXT ? "TEXT" : "DER");

  if (filetype == SHISHI_FILETYPE_TEXT)
    res = shishi_krberror_parse (handle, fh, krberror);
  else
    res = shishi_krberror_read (handle, fh, krberror);
  if (res != SHISHI_OK)
    return res;

  res = fclose (fh);
  if (res != 0)
    return SHISHI_IO_ERROR;

  if (VERBOSE (handle))
    printf (_("Reading KRB-ERROR from %s...done\n"), filename);

  return SHISHI_OK;
}

/**
 * shishi_krberror_build:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: krberror as allocated by shishi_krberror().
 *
 * Finish KRB-ERROR, called before e.g. shishi_krberror_der.  This
 * function removes empty but OPTIONAL fields (such as cname), and
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_build (Shishi * handle, Shishi_asn1 krberror)
{
  char *t;
  size_t tmplen = sizeof (t);
  char *tmp;
  int32_t errc;
  uint32_t usec;
  int rc;

  rc = shishi_krberror_ctime (handle, krberror, &t);
  if (rc != SHISHI_OK &&
      rc != SHISHI_ASN1_NO_ELEMENT && rc != SHISHI_ASN1_NO_VALUE)
    return rc;
  free (t);
  if (rc == SHISHI_ASN1_NO_VALUE)
    {
      rc = shishi_krberror_remove_ctime (handle, krberror);
      if (rc != SHISHI_OK)
	return rc;
    }

  rc = shishi_krberror_cusec (handle, krberror, &usec);
  if (rc != SHISHI_OK &&
      rc != SHISHI_ASN1_NO_ELEMENT && rc != SHISHI_ASN1_NO_VALUE)
    return rc;
  if (rc == SHISHI_ASN1_NO_VALUE)
    {
      rc = shishi_krberror_remove_cusec (handle, krberror);
      if (rc != SHISHI_OK)
	return rc;
    }

  rc = shishi_krberror_crealm (handle, krberror, &tmp, &tmplen);
  if (rc != SHISHI_OK &&
      rc != SHISHI_ASN1_NO_ELEMENT && rc != SHISHI_ASN1_NO_VALUE)
    return rc;
  if (rc == SHISHI_OK)
    free (tmp);
  if (rc == SHISHI_ASN1_NO_VALUE)
    {
      rc = shishi_krberror_remove_crealm (handle, krberror);
      if (rc != SHISHI_OK)
	return rc;
    }

  rc = shishi_krberror_client (handle, krberror, &tmp, &tmplen);
  if (rc != SHISHI_OK &&
      rc != SHISHI_ASN1_NO_ELEMENT && rc != SHISHI_ASN1_NO_VALUE)
    return rc;
  if (rc == SHISHI_OK)
    free (tmp);
  if (rc == SHISHI_ASN1_NO_VALUE || (rc == SHISHI_OK && tmplen == 0))
    {
      rc = shishi_krberror_remove_cname (handle, krberror);
      if (rc != SHISHI_OK)
	return rc;
    }

  rc = shishi_krberror_realm (handle, krberror, &tmp, &tmplen);
  if (rc != SHISHI_OK && rc != SHISHI_ASN1_NO_VALUE)
    return rc;
  if (rc == SHISHI_OK)
    free (tmp);
  if (rc == SHISHI_ASN1_NO_VALUE)
    {
      rc = shishi_krberror_set_realm (handle, krberror, "");
      if (rc != SHISHI_OK)
	return rc;
    }

  rc = shishi_krberror_server (handle, krberror, &tmp, &tmplen);
  if (rc != SHISHI_OK && rc != SHISHI_ASN1_NO_VALUE)
    return rc;
  if (rc == SHISHI_OK)
    free (tmp);
  if (rc == SHISHI_ASN1_NO_VALUE || tmplen == 0)
    {
      rc = shishi_krberror_remove_sname (handle, krberror);
      if (rc != SHISHI_OK)
	return rc;
    }

  rc = shishi_krberror_edata (handle, krberror, &tmp, &tmplen);
  if (rc != SHISHI_OK &&
      rc != SHISHI_ASN1_NO_ELEMENT && rc != SHISHI_ASN1_NO_VALUE)
    return rc;
  if (rc == SHISHI_OK)
    free (tmp);
  if (rc == SHISHI_ASN1_NO_VALUE || (rc == SHISHI_OK && tmplen == 0))
    {
      rc = shishi_krberror_remove_edata (handle, krberror);
      if (rc != SHISHI_OK)
	return rc;
    }

  rc = shishi_krberror_errorcode (handle, krberror, &errc);
  if (rc != SHISHI_OK && rc != SHISHI_ASN1_NO_VALUE)
    return rc;
  if (rc == SHISHI_ASN1_NO_VALUE)
    {
      rc = shishi_krberror_errorcode_set (handle, krberror,
					  SHISHI_KRB_ERR_GENERIC);
      if (rc != SHISHI_OK)
	return rc;
    }

  rc = shishi_krberror_etext (handle, krberror, &tmp, &tmplen);
  if (rc != SHISHI_OK &&
      rc != SHISHI_ASN1_NO_ELEMENT && rc != SHISHI_ASN1_NO_VALUE)
    return rc;
  if (rc == SHISHI_OK)
    free (tmp);
  if (rc == SHISHI_ASN1_NO_VALUE || (rc == SHISHI_OK && tmplen == 0))
    {
      if (shishi_krberror_errorcode_fast (handle, krberror) ==
	  SHISHI_KRB_ERR_GENERIC)
	rc = shishi_krberror_set_etext (handle, krberror,
					"Uninitialized error");
      else
	rc = shishi_krberror_remove_etext (handle, krberror);
      if (rc != SHISHI_OK)
	return rc;
    }

  return SHISHI_OK;
}

/**
 * shishi_krberror_der:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: krberror as allocated by shishi_krberror().
 * @out: output array with newly allocated DER encoding of KRB-ERROR.
 * @outlen: length of output array with DER encoding of KRB-ERROR.
 *
 * DER encode KRB-ERROR.  The caller must deallocate the OUT buffer.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_der (Shishi * handle,
		     Shishi_asn1 krberror, char **out, size_t * outlen)
{
  int rc;

  rc = shishi_krberror_build (handle, krberror);
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_asn1_to_der (handle, krberror, out, outlen);
  if (rc != SHISHI_OK)
    return rc;

  return SHISHI_OK;
}

/**
 * shishi_krberror_crealm:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: krberror as allocated by shishi_krberror().
 * @realm: output array with newly allocated name of realm in KRB-ERROR.
 * @realmlen: size of output array.
 *
 * Extract client realm from KRB-ERROR.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_crealm (Shishi * handle,
			Shishi_asn1 krberror, char **realm, size_t * realmlen)
{
  return shishi_asn1_read (handle, krberror, "crealm", realm, realmlen);
}

/**
 * shishi_krberror_remove_crealm:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: krberror as allocated by shishi_krberror().
 *
 * Remove client realm field in KRB-ERROR.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_remove_crealm (Shishi * handle, Shishi_asn1 krberror)
{
  int res;

  res = shishi_asn1_write (handle, krberror, "crealm", NULL, 0);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_krberror_set_crealm:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: krberror as allocated by shishi_krberror().
 * @crealm: input array with realm.
 *
 * Set realm field in krberror to specified value.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_set_crealm (Shishi * handle,
			    Shishi_asn1 krberror, const char *crealm)
{
  int res;

  res = shishi_asn1_write (handle, krberror, "crealm", crealm, 0);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_krberror_client:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: krberror as allocated by shishi_krberror().
 * @client: pointer to newly allocated zero terminated string containing
 *   principal name.  May be %NULL (to only populate @clientlen).
 * @clientlen: pointer to length of @client on output, excluding terminating
 *   zero.  May be %NULL (to only populate @client).
 *
 * Return client principal name in KRB-ERROR.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_client (Shishi * handle,
			Shishi_asn1 krberror,
			char **client, size_t * clientlen)
{
  int rc;

  rc = shishi_principal_name (handle, krberror, "cname", client, clientlen);
  if (rc != SHISHI_OK)
    return rc;

  return SHISHI_OK;
}

/**
 * shishi_krberror_set_cname:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: krberror as allocated by shishi_krberror().
 * @name_type: type of principial, see Shishi_name_type, usually
 *             SHISHI_NT_UNKNOWN.
 * @cname: input array with principal name.
 *
 * Set principal field in krberror to specified value.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_set_cname (Shishi * handle,
			   Shishi_asn1 krberror,
			   Shishi_name_type name_type, const char *cname[])
{
  int res;

  res = shishi_principal_name_set (handle, krberror, "cname",
				   name_type, cname);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_krberror_remove_cname:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: krberror as allocated by shishi_krberror().
 *
 * Remove client realm field in KRB-ERROR.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_remove_cname (Shishi * handle, Shishi_asn1 krberror)
{
  int res;

  res = shishi_asn1_write (handle, krberror, "cname", NULL, 0);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_krberror_client_set:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: Krberror to set client name field in.
 * @client: zero-terminated string with principal name on RFC 1964 form.
 *
 * Set the client name field in the Krberror.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_client_set (Shishi * handle,
			    Shishi_asn1 krberror, const char *client)
{
  int res;

  res = shishi_principal_set (handle, krberror, "cname", client);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_krberror_realm:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: krberror as allocated by shishi_krberror().
 * @realm: output array with newly allocated name of realm in KRB-ERROR.
 * @realmlen: size of output array.
 *
 * Extract (server) realm from KRB-ERROR.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_realm (Shishi * handle,
		       Shishi_asn1 krberror, char **realm, size_t * realmlen)
{
  return shishi_asn1_read (handle, krberror, "realm", realm, realmlen);
}

/**
 * shishi_krberror_set_realm:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: krberror as allocated by shishi_krberror().
 * @realm: input array with (server) realm.
 *
 * Set (server) realm field in krberror to specified value.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_set_realm (Shishi * handle,
			   Shishi_asn1 krberror, const char *realm)
{
  int res;

  res = shishi_asn1_write (handle, krberror, "realm", realm, 0);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_krberror_server:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: krberror as allocated by shishi_krberror().
 * @server: pointer to newly allocated zero terminated string containing
 *   server name.  May be %NULL (to only populate @serverlen).
 * @serverlen: pointer to length of @server on output, excluding terminating
 *   zero.  May be %NULL (to only populate @server).
 *
 * Return server principal name in KRB-ERROR.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_server (Shishi * handle,
			Shishi_asn1 krberror,
			char **server, size_t * serverlen)
{
  int rc;

  rc = shishi_principal_name (handle, krberror, "sname", server, serverlen);
  if (rc != SHISHI_OK)
    return rc;

  return SHISHI_OK;
}

/**
 * shishi_krberror_remove_sname:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: Krberror to set server name field in.
 *
 * Remove server name field in KRB-ERROR.  (Since it is not marked
 * OPTIONAL in the ASN.1 profile, what is done is to set the name-type
 * to UNKNOWN and make sure the name-string sequence is empty.)
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_remove_sname (Shishi * handle, Shishi_asn1 krberror)
{
  int res;

  res = shishi_asn1_write_int32 (handle, krberror, "sname.name-type",
				 SHISHI_NT_UNKNOWN);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_write (handle, krberror, "sname.name-string", NULL, 0);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_krberror_set_sname:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: krberror as allocated by shishi_krberror().
 * @name_type: type of principial, see Shishi_name_type, usually
 *             SHISHI_NT_UNKNOWN.
 * @sname: input array with principal name.
 *
 * Set principal field in krberror to specified value.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_set_sname (Shishi * handle,
			   Shishi_asn1 krberror,
			   Shishi_name_type name_type, const char *sname[])
{
  int res;

  res = shishi_principal_name_set (handle, krberror, "sname",
				   name_type, sname);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_krberror_server_set:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: Krberror to set server name field in.
 * @server: zero-terminated string with principal name on RFC 1964 form.
 *
 * Set the server name field in the Krberror.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_server_set (Shishi * handle,
			    Shishi_asn1 krberror, const char *server)
{
  int res;

  res = shishi_principal_set (handle, krberror, "sname", server);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_krberror_ctime:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: Krberror to set client name field in.
 * @t: newly allocated zero-terminated output array with client time.
 *
 * Extract client time from KRB-ERROR.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_ctime (Shishi * handle, Shishi_asn1 krberror, char **t)
{
  return shishi_time (handle, krberror, "ctime", t);
}

/**
 * shishi_krberror_ctime_set:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: Krberror as allocated by shishi_krberror().
 * @t: string with generalized time value to store in Krberror.
 *
 * Store client time in Krberror.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_ctime_set (Shishi * handle,
			   Shishi_asn1 krberror, const char *t)
{
  int res;

  if (t)
    res = shishi_asn1_write (handle, krberror, "ctime",
			     t, SHISHI_GENERALIZEDTIME_LENGTH);
  else
    res = shishi_asn1_write (handle, krberror, "ctime", NULL, 0);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_krberror_remove_ctime:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: Krberror as allocated by shishi_krberror().
 *
 * Remove client time field in Krberror.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_remove_ctime (Shishi * handle, Shishi_asn1 krberror)
{
  int res;

  res = shishi_asn1_write (handle, krberror, "ctime", NULL, 0);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_krberror_cusec:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: Krberror as allocated by shishi_krberror().
 * @cusec: output integer with client microseconds field.
 *
 * Extract client microseconds field from Krberror.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_cusec (Shishi * handle, Shishi_asn1 krberror,
		       uint32_t * cusec)
{
  int res;

  res = shishi_asn1_read_uint32 (handle, krberror, "cusec", cusec);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_krberror_cusec_set:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: krberror as allocated by shishi_krberror().
 * @cusec: client microseconds to set in krberror, 0-999999.
 *
 * Set the cusec field in the Krberror.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_cusec_set (Shishi * handle,
			   Shishi_asn1 krberror, uint32_t cusec)
{
  int res;

  res = shishi_asn1_write_uint32 (handle, krberror, "cusec", cusec);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_krberror_remove_cusec:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: Krberror as allocated by shishi_krberror().
 *
 * Remove client usec field in Krberror.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_remove_cusec (Shishi * handle, Shishi_asn1 krberror)
{
  int res;

  res = shishi_asn1_write (handle, krberror, "cusec", NULL, 0);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_krberror_stime:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: Krberror to set client name field in.
 * @t: newly allocated zero-terminated output array with server time.
 *
 * Extract server time from KRB-ERROR.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_stime (Shishi * handle, Shishi_asn1 krberror, char **t)
{
  return shishi_time (handle, krberror, "stime", t);
}

/**
 * shishi_krberror_stime_set:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: Krberror as allocated by shishi_krberror().
 * @t: string with generalized time value to store in Krberror.
 *
 * Store server time in Krberror.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_stime_set (Shishi * handle,
			   Shishi_asn1 krberror, const char *t)
{
  int res;

  res = shishi_asn1_write (handle, krberror, "stime",
			   t, SHISHI_GENERALIZEDTIME_LENGTH);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_krberror_susec:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: Krberror as allocated by shishi_krberror().
 * @susec: output integer with server microseconds field.
 *
 * Extract server microseconds field from Krberror.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_susec (Shishi * handle,
		       Shishi_asn1 krberror, uint32_t * susec)
{
  int res;

  res = shishi_asn1_read_uint32 (handle, krberror, "susec", susec);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_krberror_susec_set:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: krberror as allocated by shishi_krberror().
 * @susec: server microseconds to set in krberror, 0-999999.
 *
 * Set the susec field in the Krberror.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_susec_set (Shishi * handle,
			   Shishi_asn1 krberror, uint32_t susec)
{
  int res;

  res = shishi_asn1_write_uint32 (handle, krberror, "susec", susec);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_krberror_errorcode:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: KRB-ERROR structure with error code.
 * @errorcode: output integer KRB-ERROR error code.
 *
 * Extract error code from KRB-ERROR.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_errorcode (Shishi * handle,
			   Shishi_asn1 krberror, int32_t * errorcode)
{
  return shishi_asn1_read_int32 (handle, krberror, "error-code", errorcode);
}

/**
 * shishi_krberror_errorcode_fast:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: KRB-ERROR structure with error code.
 *
 * Get error code from KRB-ERROR, without error checking.
 *
 * Return value: Return error code (see shishi_krberror_errorcode())
 *               directly, or -1 on error.
 **/
int
shishi_krberror_errorcode_fast (Shishi * handle, Shishi_asn1 krberror)
{
  int i;

  if (shishi_krberror_errorcode (handle, krberror, &i) != SHISHI_OK)
    i = -1;

  return i;
}

/**
 * shishi_krberror_errorcode_set:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: KRB-ERROR structure with error code to set.
 * @errorcode: new error code to set in krberror.
 *
 * Set the error-code field to a new error code.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_errorcode_set (Shishi * handle,
			       Shishi_asn1 krberror, int errorcode)
{
  int res;

  res = shishi_asn1_write_int32 (handle, krberror, "error-code", errorcode);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_krberror_etext:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: KRB-ERROR structure with error code.
 * @etext: output array with newly allocated error text.
 * @etextlen: output length of error text.
 *
 * Extract additional error text from server (possibly empty).
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_etext (Shishi * handle, Shishi_asn1 krberror,
		       char **etext, size_t * etextlen)
{
  return shishi_asn1_read (handle, krberror, "e-text", etext, etextlen);
}

/**
 * shishi_krberror_set_etext:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: krberror as allocated by shishi_krberror().
 * @etext: input array with error text to set.
 *
 * Set error text (e-text) field in KRB-ERROR to specified value.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_set_etext (Shishi * handle,
			   Shishi_asn1 krberror, const char *etext)
{
  int res;

  res = shishi_asn1_write (handle, krberror, "e-text", etext, 0);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_krberror_remove_etext:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: krberror as allocated by shishi_krberror().
 *
 * Remove error text (e-text) field in KRB-ERROR.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_remove_etext (Shishi * handle, Shishi_asn1 krberror)
{
  int res;

  res = shishi_asn1_write (handle, krberror, "e-text", NULL, 0);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_krberror_edata:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: KRB-ERROR structure with error code.
 * @edata: output array with newly allocated error data.
 * @edatalen: output length of error data.
 *
 * Extract additional error data from server (possibly empty).
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_edata (Shishi * handle, Shishi_asn1 krberror,
		       char **edata, size_t * edatalen)
{
  return shishi_asn1_read (handle, krberror, "e-data", edata, edatalen);
}

/**
 * shishi_krberror_methoddata:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: KRB-ERROR structure with error code.
 * @methoddata: output ASN.1 METHOD-DATA.
 *
 * Extract METHOD-DATA ASN.1 object from the e-data field.  The e-data
 * field will only contain a METHOD-DATA if the krberror error code is
 * %SHISHI_KDC_ERR_PREAUTH_REQUIRED.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_methoddata (Shishi * handle, Shishi_asn1 krberror,
			    Shishi_asn1 *methoddata)
{
  int rc;

  *methoddata = NULL;

  if (shishi_krberror_errorcode_fast (handle, krberror)
      == SHISHI_KDC_ERR_PREAUTH_REQUIRED)
    {
      char *buf;
      size_t len;

      rc = shishi_krberror_edata (handle, krberror, &buf, &len);
      if (rc != SHISHI_OK)
	return rc;

      *methoddata = shishi_der2asn1_methoddata (handle, buf, len);
      free (buf);
      if (!*methoddata)
	return SHISHI_ASN1_ERROR;
    }

  return SHISHI_OK;
}

/**
 * shishi_krberror_set_edata:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: krberror as allocated by shishi_krberror().
 * @edata: input array with error text to set.
 *
 * Set error text (e-data) field in KRB-ERROR to specified value.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_set_edata (Shishi * handle,
			   Shishi_asn1 krberror, const char *edata)
{
  int res;

  res = shishi_asn1_write (handle, krberror, "e-data", edata, 0);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_krberror_remove_edata:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: krberror as allocated by shishi_krberror().
 *
 * Remove error text (e-data) field in KRB-ERROR.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_remove_edata (Shishi * handle, Shishi_asn1 krberror)
{
  int res;

  res = shishi_asn1_write (handle, krberror, "e-data", NULL, 0);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_krberror_pretty_print:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle opened for writing.
 * @krberror: KRB-ERROR structure with error code.
 *
 * Print KRB-ERROR error condition and some explanatory text to file
 * descriptor.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_krberror_pretty_print (Shishi * handle, FILE * fh,
			      Shishi_asn1 krberror)
{
  char *buf;
  size_t len;
  int res;

  if (VERBOSEASN1 (handle))
    shishi_krberror_print (handle, fh, krberror);

  if (shishi_krberror_errorcode_fast (handle, krberror) ==
      SHISHI_KRB_ERR_GENERIC)
    {
      fprintf (fh, "Generic error from server:\n");

      res = shishi_krberror_etext (handle, krberror, &buf, &len);
      if (res == SHISHI_OK && len > 0)
	{
	  buf[len] = '\0';
	  fprintf (fh, "%s\n", buf);
	  free (buf);
	}
    }
  else
    {
      fprintf (fh, "Error code from server:\n%s\n",
	       shishi_krberror_message (handle, krberror));

      res = shishi_krberror_etext (handle, krberror, &buf, &len);
      if (res == SHISHI_OK && len > 0)
	{
	  buf[len] = '\0';
	  fprintf (fh, "Additional error message from server:\n%s\n", buf);
	  free (buf);
	}

      if (shishi_krberror_errorcode_fast (handle, krberror) ==
	  SHISHI_KDC_ERR_PREAUTH_REQUIRED)
	{
	  Shishi_asn1 pas;
	  size_t i, n;

	  res = shishi_krberror_methoddata (handle, krberror, &pas);
	  if (res != SHISHI_OK)
	    return res;

	  if (VERBOSEASN1 (handle))
	    shishi_methoddata_print (handle, stdout, pas);

	  res = shishi_asn1_number_of_elements (handle, pas, "", &n);
	  if (res == SHISHI_OK)
	    {
	      fprintf (fh, "Types of PA-DATA in KRB-ERROR: ");

	      for (i = 1; i <= n; i++)
		{
		  char *format = xasprintf ("?%d.padata-type", i);
		  int32_t padatatype;

		  if (i > 1)
		    fprintf (fh, ", ");

		  res = shishi_asn1_read_int32 (handle, pas, format,
						&padatatype);
		  if (res == SHISHI_OK)
		    printf ("%d", padatatype);

		  free (format);
		}

	      fprintf (fh, ".\n");
	    }

	  shishi_asn1_done (handle, pas);
	}
    }


  return SHISHI_OK;
}

struct krb_error_msgs
{
  int errorcode;
  const char *message;
};

static const struct krb_error_msgs
_shishi_krberror_messages[SHISHI_LAST_ERROR_CODE] = {
  {SHISHI_KDC_ERR_NONE,
   N_("No error")},
  {SHISHI_KDC_ERR_NAME_EXP,
   N_("Client's entry in database has expired")},
  {SHISHI_KDC_ERR_SERVICE_EXP,
   N_("Server's entry in database has expired")},
  {SHISHI_KDC_ERR_BAD_PVNO,
   N_("Requested protocol version number not supported")},
  {SHISHI_KDC_ERR_C_OLD_MAST_KVNO,
   N_("Client's key encrypted in old master key")},
  {SHISHI_KDC_ERR_S_OLD_MAST_KVNO,
   N_("Server's key encrypted in old master key")},
  {SHISHI_KDC_ERR_C_PRINCIPAL_UNKNOWN,
   N_("Client not found in database")},
  {SHISHI_KDC_ERR_S_PRINCIPAL_UNKNOWN,
   N_("Server not found in database")},
  {SHISHI_KDC_ERR_PRINCIPAL_NOT_UNIQUE,
   N_("Multiple principal entries in database")},
  {SHISHI_KDC_ERR_NULL_KEY,
   N_("The client or server has a null key")},
  {SHISHI_KDC_ERR_CANNOT_POSTDATE,
   N_("Ticket not eligible for postdating")},
  {SHISHI_KDC_ERR_NEVER_VALID,
   N_("Requested start time is later than end time")},
  {SHISHI_KDC_ERR_POLICY,
   N_("KDC policy rejects request")},
  {SHISHI_KDC_ERR_BADOPTION,
   N_("KDC cannot accommodate requested option")},
  {SHISHI_KDC_ERR_ETYPE_NOSUPP,
   N_("KDC has no support for encryption type")},
  {SHISHI_KDC_ERR_SUMTYPE_NOSUPP,
   N_("KDC has no support for checksum type")},
  {SHISHI_KDC_ERR_PADATA_TYPE_NOSUPP,
   N_("KDC has no support for padata type")},
  {SHISHI_KDC_ERR_TRTYPE_NOSUPP,
   N_("KDC has no support for transited type")},
  {SHISHI_KDC_ERR_CLIENT_REVOKED,
   N_("Clients credentials have been revoked")},
  {SHISHI_KDC_ERR_SERVICE_REVOKED,
   N_("Credentials for server have been revoked")},
  {SHISHI_KDC_ERR_TGT_REVOKED,
   N_("TGT has been revoked")},
  {SHISHI_KDC_ERR_CLIENT_NOTYET,
   N_("Client not yet valid - try again later")},
  {SHISHI_KDC_ERR_SERVICE_NOTYET,
   N_("Server not yet valid - try again later")},
  {SHISHI_KDC_ERR_KEY_EXPIRED,
   N_("Password has expired ")},
  {SHISHI_KDC_ERR_PREAUTH_FAILED,
   N_("Pre-authentication information was invalid")},
  {SHISHI_KDC_ERR_PREAUTH_REQUIRED,
   N_("Additional pre-authentication required")},
  {SHISHI_KDC_ERR_SERVER_NOMATCH,
   N_("Requested server and ticket don't match")},
  {SHISHI_KDC_ERR_MUST_USE_USER2USER,
   N_("Server principal valid for user2user only")},
  {SHISHI_KDC_ERR_PATH_NOT_ACCPETED,
   N_("KDC Policy rejects transited path")},
  {SHISHI_KDC_ERR_SVC_UNAVAILABLE,
   N_("A service is not available")},
  {SHISHI_KRB_AP_ERR_BAD_INTEGRITY,
   N_("Integrity check on decrypted field failed")},
  {SHISHI_KRB_AP_ERR_TKT_EXPIRED,
   N_("Ticket expired")},
  {SHISHI_KRB_AP_ERR_TKT_NYV,
   N_("Ticket not yet valid")},
  {SHISHI_KRB_AP_ERR_REPEAT,
   N_("Request is a replay")},
  {SHISHI_KRB_AP_ERR_NOT_US,
   N_("The ticket isn't for us")},
  {SHISHI_KRB_AP_ERR_BADMATCH,
   N_("Ticket and authenticator don't match")},
  {SHISHI_KRB_AP_ERR_SKEW,
   N_("Clock skew too great")},
  {SHISHI_KRB_AP_ERR_BADADDR,
   N_("Incorrect net address")},
  {SHISHI_KRB_AP_ERR_BADVERSION,
   N_("Protocol version mismatch")},
  {SHISHI_KRB_AP_ERR_MSG_TYPE,
   N_("Invalid msg type")},
  {SHISHI_KRB_AP_ERR_MODIFIED,
   N_("Message stream modified")},
  {SHISHI_KRB_AP_ERR_BADORDER,
   N_("Message out of order")},
  {SHISHI_KRB_AP_ERR_BADKEYVER,
   N_("Specified version of key is not available")},
  {SHISHI_KRB_AP_ERR_NOKEY,
   N_("Service key not available")},
  {SHISHI_KRB_AP_ERR_MUT_FAIL,
   N_("Mutual authentication failed")},
  {SHISHI_KRB_AP_ERR_BADDIRECTION,
   N_("Incorrect message direction")},
  {SHISHI_KRB_AP_ERR_METHOD,
   N_("Alternative authentication method required")},
  {SHISHI_KRB_AP_ERR_BADSEQ,
   N_("Incorrect sequence number in message")},
  {SHISHI_KRB_AP_ERR_INAPP_CKSUM,
   N_("Inappropriate type of checksum in message")},
  {SHISHI_KRB_AP_PATH_NOT_ACCEPTED,
   N_("Policy rejects transited path")},
  {SHISHI_KRB_ERR_RESPONSE_TOO_BIG,
   N_("Response too big for UDP, retry with TCP")},
  {SHISHI_KRB_ERR_GENERIC,
   N_("Generic error (description in e-text)")},
  {SHISHI_KRB_ERR_FIELD_TOOLONG,
   N_("Field is too long for this implementation")},
  {SHISHI_KDC_ERROR_CLIENT_NOT_TRUSTED,
   N_("(pkinit)")},
  {SHISHI_KDC_ERROR_KDC_NOT_TRUSTED,
   N_("(pkinit)")},
  {SHISHI_KDC_ERROR_INVALID_SIG,
   N_("(pkinit)")},
  {SHISHI_KDC_ERR_KEY_TOO_WEAK,
   N_("(pkinit)")},
  {SHISHI_KDC_ERR_CERTIFICATE_MISMATCH,
   N_("(pkinit)")},
  {SHISHI_KRB_AP_ERR_NO_TGT,
   N_("(user-to-user)")},
  {SHISHI_KDC_ERR_WRONG_REALM,
   N_("(user-to-user)")},
  {SHISHI_KRB_AP_ERR_USER_TO_USER_REQUIRED,
   N_("(user-to-user)")},
  {SHISHI_KDC_ERR_CANT_VERIFY_CERTIFICATE,
   N_("(pkinit)")},
  {SHISHI_KDC_ERR_INVALID_CERTIFICATE,
   N_("(pkinit)")},
  {SHISHI_KDC_ERR_REVOKED_CERTIFICATE,
   N_("(pkinit)")},
  {SHISHI_KDC_ERR_REVOCATION_STATUS_UNKNOWN,
   N_("(pkinit)")},
  {SHISHI_KDC_ERR_REVOCATION_STATUS_UNAVAILABLE,
   N_("(pkinit)")},
  {SHISHI_KDC_ERR_CLIENT_NAME_MISMATCH,
   N_("(pkinit)")},
  {SHISHI_KDC_ERR_KDC_NAME_MISMATCH,
   N_("(pkinit)")}
};

/**
 * shishi_krberror_errorcode_message:
 * @handle: shishi handle as allocated by shishi_init().
 * @errorcode: integer KRB-ERROR error code.
 *
 * Get human readable string describing KRB-ERROR code.
 *
 * Return value: Return a string describing error code.  This function
 *               will always return a string even if the error code
 *               isn't known.
 **/
const char *
shishi_krberror_errorcode_message (Shishi * handle, int errorcode)
{
  int i;
  char *p;

  for (i = 0; i < SHISHI_LAST_ERROR_CODE; i++)
    {
      if (errorcode == _shishi_krberror_messages[i].errorcode)
	return _(_shishi_krberror_messages[i].message);
    }

  /* XXX memory leak */
  asprintf (&p, _("Unknown KRB-ERROR error code %d."), errorcode);
  return p;
}

/**
 * shishi_krberror_message:
 * @handle: shishi handle as allocated by shishi_init().
 * @krberror: KRB-ERROR structure with error code.
 *
 * Extract error code (see shishi_krberror_errorcode_fast()) and
 * return error message (see shishi_krberror_errorcode_message()).
 *
 * Return value: Return a string describing error code.  This function
 *               will always return a string even if the error code
 *               isn't known.
 **/
const char *
shishi_krberror_message (Shishi * handle, Shishi_asn1 krberror)
{
  return shishi_krberror_errorcode_message
    (handle, shishi_krberror_errorcode_fast (handle, krberror));
}
