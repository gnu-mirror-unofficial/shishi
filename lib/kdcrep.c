/* kdcrep.c	Key distribution (AS/TGS) Reply functions
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

#define SHISHI_KDCREP_DEFAULT_PVNO      "5"
#define SHISHI_KDCREP_DEFAULT_PVNO_LEN  0
#define SHISHI_AS_REP_DEFAULT_MSG_TYPE      "11"
#define SHISHI_AS_REP_DEFAULT_MSG_TYPE_LEN  0
#define SHISHI_TGS_REP_DEFAULT_MSG_TYPE      "13"
#define SHISHI_TGS_REP_DEFAULT_MSG_TYPE_LEN  0

static Shishi_asn1
_shishi_kdcrep (Shishi * handle, int as)
{
  int res;
  Shishi_asn1 node;

  if (as)
    node = shishi_asn1_asrep (handle);
  else
    node = shishi_asn1_tgsrep (handle);
  if (!node)
    return NULL;

  res = shishi_asn1_write (handle, node, "KDC-REP.pvno",
			   SHISHI_KDCREP_DEFAULT_PVNO,
			   SHISHI_KDCREP_DEFAULT_PVNO_LEN);
  if (res != SHISHI_OK)
    goto error;

  if (as)
    res = shishi_asn1_write (handle, node, "KDC-REP.msg-type",
			     SHISHI_AS_REP_DEFAULT_MSG_TYPE,
			     SHISHI_AS_REP_DEFAULT_MSG_TYPE_LEN);
  else
    res = shishi_asn1_write (handle, node, "KDC-REP.msg-type",
			     SHISHI_TGS_REP_DEFAULT_MSG_TYPE,
			     SHISHI_TGS_REP_DEFAULT_MSG_TYPE_LEN);
  if (res != SHISHI_OK)
    goto error;

  return node;

error:
  shishi_asn1_done (handle, node);
  return NULL;
}

/**
 * shishi_as_rep:
 * @handle: shishi handle as allocated by shishi_init().
 *
 * This function creates a new AS-REP, populated with some default
 * values.
 *
 * Return value: Returns the AS-REP or NULL on failure.
 **/
Shishi_asn1
shishi_asrep (Shishi * handle)
{
  return _shishi_kdcrep (handle, 1);
}

/**
 * shishi_tgs_rep:
 * @handle: shishi handle as allocated by shishi_init().
 *
 * This function creates a new TGS-REP, populated with some default
 * values.
 *
 * Return value: Returns the TGS-REP or NULL on failure.
 **/
Shishi_asn1
shishi_tgsrep (Shishi * handle)
{
  return _shishi_kdcrep (handle, 0);
}


/**
 * shishi_kdcrep_print:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle open for writing.
 * @kdcrep: KDC-REP to print.
 *
 * Print ASCII armored DER encoding of KDC-REP to file.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcrep_print (Shishi * handle, FILE * fh, Shishi_asn1 kdcrep)
{
  return _shishi_print_armored_data (handle, fh, kdcrep, "KDC-REP", NULL);
}

/**
 * shishi_kdcrep_save:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle open for writing.
 * @kdcrep: KDC-REP to save.
 *
 * Print  DER encoding of KDC-REP to file.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcrep_save (Shishi * handle, FILE * fh, Shishi_asn1 kdcrep)
{
  return _shishi_save_data (handle, fh, kdcrep, "KDC-REP");
}

/**
 * shishi_kdcrep_to_file:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcrep: KDC-REP to save.
 * @filetype: input variable specifying type of file to be written,
 *            see Shishi_filetype.
 * @filename: input variable with filename to write to.
 *
 * Write KDC-REP to file in specified TYPE.  The file will be truncated
 * if it exists.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcrep_to_file (Shishi * handle, Shishi_asn1 kdcrep,
		       int filetype, char *filename)
{
  FILE *fh;
  int res;

  if (VERBOSE (handle))
    printf (_("Writing KDC-REP to %s...\n"), filename);

  fh = fopen (filename, "w");
  if (fh == NULL)
    return SHISHI_FOPEN_ERROR;

  if (VERBOSE (handle))
    printf (_("Writing KDC-REP in %s format...\n"),
	    filetype == SHISHI_FILETYPE_TEXT ? "TEXT" : "DER");

  if (filetype == SHISHI_FILETYPE_TEXT)
    res = shishi_kdcrep_print (handle, fh, kdcrep);
  else
    res = shishi_kdcrep_save (handle, fh, kdcrep);
  if (res != SHISHI_OK)
    return res;

  res = fclose (fh);
  if (res != 0)
    return SHISHI_FCLOSE_ERROR;

  if (VERBOSE (handle))
    printf (_("Writing KDC-REP to %s...done\n"), filename);

  return SHISHI_OK;
}

/**
 * shishi_kdcrep_parse:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle open for reading.
 * @kdcrep: output variable with newly allocated KDC-REP.
 *
 * Read ASCII armored DER encoded KDC-REP from file and populate given
 * variable.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcrep_parse (Shishi * handle, FILE * fh, Shishi_asn1 * kdcrep)
{
  return _shishi_kdcrep_input (handle, fh, kdcrep, 0);
}

/**
 * shishi_kdcrep_read:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle open for reading.
 * @kdcrep: output variable with newly allocated KDC-REP.
 *
 * Read DER encoded KDC-REP from file and populate given variable.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcrep_read (Shishi * handle, FILE * fh, Shishi_asn1 * kdcrep)
{
  return _shishi_kdcrep_input (handle, fh, kdcrep, 1);
}

/**
 * shishi_kdcrep_from_file:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcrep: output variable with newly allocated KDC-REP.
 * @filetype: input variable specifying type of file to be read,
 *            see Shishi_filetype.
 * @filename: input variable with filename to read from.
 *
 * Read KDC-REP from file in specified TYPE.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcrep_from_file (Shishi * handle, Shishi_asn1 * kdcrep,
			 int filetype, char *filename)
{
  int res;
  FILE *fh;

  if (VERBOSE (handle))
    printf (_("Reading KDC-REP from %s...\n"), filename);

  fh = fopen (filename, "r");
  if (fh == NULL)
    return SHISHI_FOPEN_ERROR;

  if (VERBOSE (handle))
    printf (_("Reading KDC-REP in %s format...\n"),
	    filetype == SHISHI_FILETYPE_TEXT ? "TEXT" : "DER");

  if (filetype == SHISHI_FILETYPE_TEXT)
    res = shishi_kdcrep_parse (handle, fh, kdcrep);
  else
    res = shishi_kdcrep_read (handle, fh, kdcrep);
  if (res != SHISHI_OK)
    return res;

  res = fclose (fh);
  if (res != 0)
    return SHISHI_FCLOSE_ERROR;

  if (VERBOSE (handle))
    printf (_("Reading KDC-REP from %s...done\n"), filename);

  return SHISHI_OK;
}

/**
 * shishi_kdcrep_crealm_set:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcrep: Kdcrep variable to set realm field in.
 * @crealm: input array with name of realm.
 *
 * Set the client realm field in the KDC-REP.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcrep_crealm_set (Shishi * handle,
			  Shishi_asn1 kdcrep, const char *crealm)
{
  int res;

  res = shishi_asn1_write (handle, kdcrep, "KDC-REP.crealm", crealm, 0);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_kdcrep_cname_set:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcrep: Kdcrep variable to set server name field in.
 * @name_type: type of principial, see Shishi_name_type, usually
 *             SHISHI_NT_UNKNOWN.
 * @cname: input array with principal name.
 *
 * Set the server name field in the KDC-REP.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcrep_cname_set (Shishi * handle,
			 Shishi_asn1 kdcrep,
			 Shishi_name_type name_type, char *cname[])
{
  int res;
  char buf[BUFSIZ];
  int i;

  sprintf (buf, "%d", name_type);

  res = shishi_asn1_write (handle, kdcrep, "KDC-REP.cname.name-type", buf, 0);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_write (handle, kdcrep, "KDC-REP.cname.name-string",
			   NULL, 0);
  if (res != SHISHI_OK)
    return res;

  i = 1;
  while (cname[i - 1])
    {
      res = shishi_asn1_write (handle, kdcrep, "KDC-REP.cname.name-string",
			       "NEW", 1);
      if (res != SHISHI_OK)
	return res;

      sprintf (buf, "KDC-REP.cname.name-string.?%d", i);
      res = shishi_asn1_write (handle, kdcrep, buf, cname[i - 1], 0);
      if (res != SHISHI_OK)
	return res;

      i++;
    }

  return SHISHI_OK;
}

int
shishi_kdcrep_client_set (Shishi * handle,
			  Shishi_asn1 kdcrep, const char *client)
{
  char *tmpclient;
  char **clientbuf;
  char *tokptr;
  int res;
  int i;

  tmpclient = strdup (client);
  if (tmpclient == NULL)
    return SHISHI_MALLOC_ERROR;

  clientbuf = malloc (sizeof (*clientbuf));
  for (i = 0;
       (clientbuf[i] = strtok_r (i == 0 ? tmpclient : NULL, "/", &tokptr));
       i++)
    {
      clientbuf = realloc (clientbuf, (i + 2) * sizeof (*clientbuf));
      if (clientbuf == NULL)
	return SHISHI_MALLOC_ERROR;
    }
  res = shishi_kdcrep_cname_set (handle, kdcrep,
				 SHISHI_NT_PRINCIPAL, clientbuf);
  if (res != SHISHI_OK)
    {
      fprintf (stderr, _("Could not set cname: %s\n"),
	       shishi_strerror_details (handle));
      return res;
    }
  free (clientbuf);
  free (tmpclient);

  return SHISHI_OK;
}

int
shishi_kdcrep_crealmserver_set (Shishi * handle,
				Shishi_asn1 kdcrep,
				const char *crealm, const char *client)
{
  int res;

  res = shishi_kdcrep_crealm_set (handle, kdcrep, crealm);
  if (res != SHISHI_OK)
    return res;

  res = shishi_kdcrep_client_set (handle, kdcrep, client);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_kdcrep_get_enc_part_etype:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcrep: KDC-REP variable to get value from.
 * @etype: output variable that holds the value.
 *
 * Extract KDC-REP.enc-part.etype.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcrep_get_enc_part_etype (Shishi * handle,
				  Shishi_asn1 kdcrep, int *etype)
{
  return shishi_asn1_integer_field (handle, kdcrep, etype,
				    "KDC-REP.enc-part.etype");
}

/**
 * shishi_kdcrep_get_ticket:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcrep: KDC-REP variable to get ticket from.
 * @ticket: output variable to hold extracted ticket.
 *
 * Extract ticket from KDC-REP.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcrep_get_ticket (Shishi * handle,
			  Shishi_asn1 kdcrep, Shishi_asn1 * ticket)
{
  unsigned char buf[BUFSIZ];
  unsigned char format[BUFSIZ];
  int buflen;
  int res;
  int i, n;

  /* there's GOT to be an easier way to do this */

  *ticket = shishi_asn1_ticket (handle);
  if (!*ticket)
    return SHISHI_ASN1_ERROR;

  buflen = BUFSIZ;
  res = shishi_asn1_read (handle, kdcrep, "KDC-REP.ticket.tkt-vno",
			  buf, &buflen);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_write (handle, *ticket, "Ticket.tkt-vno", buf, buflen);
  if (res != SHISHI_OK)
    goto error;

  buflen = BUFSIZ;
  res = shishi_asn1_read (handle, kdcrep, "KDC-REP.ticket.realm",
			  buf, &buflen);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_write (handle, *ticket, "Ticket.realm", buf, buflen);
  if (res != SHISHI_OK)
    goto error;

  buflen = BUFSIZ;
  res = shishi_asn1_read (handle, kdcrep, "KDC-REP.ticket.sname.name-type",
			  buf, &buflen);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_write (handle, *ticket, "Ticket.sname.name-type",
			   buf, buflen);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_number_of_elements (handle, kdcrep,
					"KDC-REP.ticket.sname.name-string",
					&n);
  if (res != SHISHI_OK)
    goto error;

  for (i = 1; i <= n; i++)
    {
      res = shishi_asn1_write (handle, *ticket, "Ticket.sname.name-string",
			       "NEW", 1);
      if (res != SHISHI_OK)
	goto error;

      sprintf (format, "KDC-REP.ticket.sname.name-string.?%d", i);
      buflen = BUFSIZ;
      res = shishi_asn1_read (handle, kdcrep, format, buf, &buflen);
      if (res != SHISHI_OK)
	goto error;

      sprintf (format, "Ticket.sname.name-string.?%d", i);
      res = shishi_asn1_write (handle, *ticket, format, buf, buflen);
      if (res != SHISHI_OK)
	goto error;
    }

  buflen = BUFSIZ;
  res = shishi_asn1_read (handle, kdcrep, "KDC-REP.ticket.enc-part.etype",
			  buf, &buflen);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_write (handle, *ticket, "Ticket.enc-part.etype",
			   buf, buflen);
  if (res != SHISHI_OK)
    goto error;

  buflen = BUFSIZ;
  res = shishi_asn1_read (handle, kdcrep, "KDC-REP.ticket.enc-part.kvno",
			  buf, &buflen);
  if (res != SHISHI_OK && res != SHISHI_ASN1_NO_ELEMENT)
    goto error;

  if (res == SHISHI_ASN1_NO_ELEMENT)
    res = shishi_asn1_write (handle, *ticket, "Ticket.enc-part.kvno",
			     NULL, 0);
  else
    res = shishi_asn1_write (handle, *ticket, "Ticket.enc-part.kvno",
			     buf, buflen);
  if (res != SHISHI_OK)
    goto error;

  buflen = BUFSIZ;
  res = shishi_asn1_read (handle, kdcrep, "KDC-REP.ticket.enc-part.cipher",
			  buf, &buflen);
  if (res != SHISHI_OK)
    goto error;

  res = shishi_asn1_write (handle, *ticket, "Ticket.enc-part.cipher",
			   buf, buflen);
  if (res != SHISHI_OK)
    goto error;

  return SHISHI_OK;

error:
  shishi_asn1_done (handle, *ticket);
  return res;
}

/**
 * shishi_kdcrep_set_ticket:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcrep: KDC-REP to add ticket field to.
 * @ticket: input ticket to copy into KDC-REP ticket field.
 *
 * Copy ticket into KDC-REP.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcrep_set_ticket (Shishi * handle, Shishi_asn1 kdcrep,
			  Shishi_asn1 ticket)
{
  int res = SHISHI_OK;
  unsigned char format[BUFSIZ];
  unsigned char buf[BUFSIZ];
  int buflen;
  int i, n;

  buflen = BUFSIZ;
  res = shishi_asn1_read (handle, ticket, "Ticket.tkt-vno", buf, &buflen);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_write (handle, kdcrep, "KDC-REP.ticket.tkt-vno",
			   buf, buflen);
  if (res != SHISHI_OK)
    return res;

  buflen = BUFSIZ;
  res = shishi_asn1_read (handle, ticket, "Ticket.realm", buf, &buflen);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_write (handle, kdcrep, "KDC-REP.ticket.realm",
			   buf, buflen);
  if (res != SHISHI_OK)
    return res;

  buflen = BUFSIZ;
  res = shishi_asn1_read (handle, ticket, "Ticket.sname.name-type",
			  buf, &buflen);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_write (handle, kdcrep, "KDC-REP.ticket.sname.name-type",
			   buf, buflen);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_number_of_elements (handle, ticket,
					"Ticket.sname.name-string", &n);
  if (res != SHISHI_OK)
    return res;

  for (i = 1; i <= n; i++)
    {
      res = shishi_asn1_write (handle, kdcrep,
			       "KDC-REP.ticket.sname.name-string", "NEW", 1);
      if (res != SHISHI_OK)
	return res;

      sprintf (format, "Ticket.sname.name-string.?%d", i);

      buflen = BUFSIZ;
      res = shishi_asn1_read (handle, ticket, format, buf, &buflen);
      if (res != SHISHI_OK)
	return res;

      sprintf (format, "KDC-REP.ticket.sname.name-string.?%d", i);

      res = shishi_asn1_write (handle, kdcrep, format, buf, buflen);
      if (res != SHISHI_OK)
	return res;
    }

  buflen = BUFSIZ;
  res = shishi_asn1_read (handle, ticket, "Ticket.enc-part.etype",
			  buf, &buflen);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_write (handle, kdcrep, "KDC-REP.ticket.enc-part.etype",
			   buf, buflen);
  if (res != SHISHI_OK)
    return res;

  buflen = BUFSIZ;
  res = shishi_asn1_read (handle, ticket, "Ticket.enc-part.kvno",
			  buf, &buflen);
  if (res != SHISHI_OK)
    res = shishi_asn1_write (handle, kdcrep, "KDC-REP.ticket.enc-part.kvno",
			     NULL, 0);
  else
    res = shishi_asn1_write (handle, kdcrep, "KDC-REP.ticket.enc-part.kvno",
			     buf, buflen);
  if (res != SHISHI_OK)
    return res;

  buflen = BUFSIZ;
  res = shishi_asn1_read (handle, ticket, "Ticket.enc-part.cipher",
			  buf, &buflen);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_write (handle, kdcrep, "KDC-REP.ticket.enc-part.cipher",
			   buf, buflen);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_kdcrep_set_enc_part:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcrep: KDC-REP to add enc-part field to.
 * @etype: encryption type used to encrypt enc-part.
 * @kvno: key version number.
 * @buf: input array with encrypted enc-part.
 * @buflen: size of input array with encrypted enc-part.
 *
 * Set the encrypted enc-part field in the KDC-REP.  The encrypted
 * data is usually created by calling shishi_encrypt() on the DER
 * encoded enc-part.  To save time, you may want to use
 * shishi_kdcrep_add_enc_part() instead, which calculates the
 * encrypted data and calls this function in one step.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcrep_set_enc_part (Shishi * handle,
			    Shishi_asn1 kdcrep,
			    int etype, int kvno, char *buf, int buflen)
{
  char *format;
  int res = SHISHI_OK;

  res = shishi_asn1_write (handle, kdcrep, "KDC-REP.enc-part.cipher",
			   buf, buflen);
  if (res != SHISHI_OK)
    return res;

  shishi_asprintf (&format, "%d", etype);
  res = shishi_asn1_write (handle, kdcrep, "KDC-REP.enc-part.etype",
			   format, 0);
  free (format);
  if (res != SHISHI_OK)
    return res;

  if (kvno == 0)
    {
      res = shishi_asn1_write (handle, kdcrep, "KDC-REP.enc-part.kvno",
			       NULL, 0);
      if (res != SHISHI_OK)
	return res;
    }
  else
    {
      shishi_asprintf (&format, "%d", etype);
      res = shishi_asn1_write (handle, kdcrep, "KDC-REP.enc-part.kvno",
			       format, 0);
      free (format);
      if (res != SHISHI_OK)
	return res;
    }

  return SHISHI_OK;
}

/**
 * shishi_kdcrep_add_enc_part:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcrep: KDC-REP to add enc-part field to.
 * @key: key used to encrypt enc-part.
 * @keyusage: key usage to use, normally SHISHI_KEYUSAGE_ENCASREPPART,
 *            SHISHI_KEYUSAGE_ENCTGSREPPART_SESSION_KEY or
 *            SHISHI_KEYUSAGE_ENCTGSREPPART_AUTHENTICATOR_KEY.
 * @enckdcreppart: EncKDCRepPart to add.
 *
 * Encrypts DER encoded EncKDCRepPart using key and stores it in the
 * KDC-REP.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcrep_add_enc_part (Shishi * handle,
			    Shishi_asn1 kdcrep,
			    Shishi_key * key,
			    int keyusage, Shishi_asn1 enckdcreppart)
{
  int res = SHISHI_OK;
  char buf[BUFSIZ];
  int buflen;
  char der[BUFSIZ];
  size_t derlen;

  res = shishi_a2d (handle, enckdcreppart, der, &derlen);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "Could not DER encode enckdcreppart: %s\n",
			   shishi_strerror (res));
      return !SHISHI_OK;
    }

  buflen = BUFSIZ;
  res = shishi_encrypt (handle, key, keyusage, der, derlen, buf, &buflen);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "des_encrypt fail\n");
      return res;
    }

  res = shishi_kdcrep_set_enc_part (handle, kdcrep, shishi_key_type (key),
				    shishi_key_version (key), buf, buflen);

  return res;
}

int
shishi_kdcrep_decrypt (Shishi * handle,
		       Shishi_asn1 kdcrep,
		       Shishi_key * key,
		       int keyusage, Shishi_asn1 * enckdcreppart)
{
  int res;
  int i;
  int buflen = BUFSIZ;
  unsigned char buf[BUFSIZ];
  unsigned char cipher[BUFSIZ];
  int cipherlen;
  int etype;

  res = shishi_kdcrep_get_enc_part_etype (handle, kdcrep, &etype);
  if (res != SHISHI_OK)
    return res;

  if (etype != shishi_key_type (key))
    return SHISHI_KDCREP_BAD_KEYTYPE;

  cipherlen = BUFSIZ;
  res = shishi_asn1_field (handle, kdcrep, cipher, &cipherlen,
			   "KDC-REP.enc-part.cipher");
  if (res != SHISHI_OK)
    return res;

  res = shishi_decrypt (handle, key, keyusage,
			cipher, cipherlen, buf, &buflen);
  if (res != SHISHI_OK)
    {
      if (VERBOSE (handle))
	printf ("des_decrypt failed: %s\n", shishi_strerror_details (handle));
      shishi_error_printf (handle,
			   "des_decrypt fail, most likely wrong password\n");
      return res;
    }

  /* The crypto is so 1980; no length indicator. Trim off pad bytes
     until we can parse it. */
  for (i = 0; i < 8; i++)
    {
      if (VERBOSEASN1 (handle))
	printf ("Trying with %d pad in enckdcrep...\n", i);

      *enckdcreppart = shishi_der2asn1_encasreppart (handle, &buf[0],
						     buflen - i);
      if (*enckdcreppart != NULL)
	break;

      *enckdcreppart = shishi_der2asn1_enctgsreppart (handle, &buf[0],
						      buflen - i);
      if (*enckdcreppart != NULL)
	break;

      *enckdcreppart = shishi_der2asn1_enckdcreppart (handle, &buf[0],
						      buflen - i);
      if (*enckdcreppart != NULL)
	break;
    }

  if (*enckdcreppart == NULL)
    {
      shishi_error_printf (handle, "Could not DER decode EncKDCRepPart. "
			   "Password probably correct (decrypt ok) though\n");
      return SHISHI_ASN1_ERROR;
    }

  return SHISHI_OK;
}

/**
 * shishi_kdcrep_clear_padata:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcrep: KDC-REP to remove PA-DATA from.
 *
 * Remove the padata field from KDC-REP.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_kdcrep_clear_padata (Shishi * handle, Shishi_asn1 kdcrep)
{
  int res;

  res = shishi_asn1_write (handle, kdcrep, "KDC-REP.padata", NULL, 0);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}
