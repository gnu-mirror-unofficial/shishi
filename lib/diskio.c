/* diskio.c	read and write data structures from disk
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

#define HEADERBEG "-----BEGIN SHISHI %s-----"
#define HEADEREND "-----END SHISHI %s-----"

/*
 * Note to self: if you change any *print* function, remember to change
 * the corresponding *parse* function too.
 *
 */

int
_shishi_print_armored_data (Shishi * handle,
			    FILE * fh,
			    ASN1_TYPE asn1, char *asn1type, char *headers)
{
  char der[BUFSIZ];
  int derlen = BUFSIZ;
  char errorDescription[MAX_ERROR_DESCRIPTION_SIZE];
  char b64der[BUFSIZ];
  int res;
  int i;
  char *tmp;

  if (asn1 == ASN1_TYPE_EMPTY)
    return !SHISHI_OK;

  asn1_print_structure (fh, asn1, asn1->name, ASN1_PRINT_NAME_TYPE_VALUE);

  res = asn1_der_coding (asn1, asn1type, der, &derlen, errorDescription);
  if (res != ASN1_SUCCESS)
    {
      shishi_error_printf (handle, "Could not DER encode %s: %s\n",
			   asn1type, errorDescription);
      return !SHISHI_OK;
    }

  shishi_to_base64 (b64der, der, derlen, sizeof (b64der));

  fprintf (fh, HEADERBEG "\n", asn1type);

  if (headers)
    {
      fprintf (fh, headers);
      fprintf (fh, "\n");
    }

  for (i = 0; i < strlen (b64der); i++)
    {
      fprintf (fh, "%c", b64der[i]);
      if ((i + 1) % 64 == 0)
	fprintf (fh, "\n");
    }
  if ((i + 1) % 64 != 0)
    fprintf (fh, "\n");

  fprintf (fh, HEADEREND "\n", asn1type);

  return SHISHI_OK;
}

int
_shishi_save_data (Shishi * handle, FILE * fh, ASN1_TYPE asn1, char *asn1type)
{
  int res;
  int derlen;
  unsigned char der[BUFSIZ];
  char errorDescription[MAX_ERROR_DESCRIPTION_SIZE];
  int i;

  derlen = sizeof (der);
  res = asn1_der_coding (asn1, asn1type, der, &derlen, errorDescription);
  if (res != ASN1_SUCCESS)
    {
      shishi_error_printf (handle, "Could not DER encode %s: %s\n",
			   asn1type, errorDescription);
      return !SHISHI_OK;
    }

  i = fwrite (der, sizeof (der[0]), derlen, fh);
  if (i != derlen)
    {
      shishi_error_printf (handle, "Short write to file (wrote %d of %d)\n",
			   i, derlen);
      return !SHISHI_OK;
    }

  return SHISHI_OK;
}

int
shishi_enckdcreppart_print (Shishi * handle,
			    FILE * fh, ASN1_TYPE enckdcreppart)
{
  return _shishi_print_armored_data (handle, fh, enckdcreppart,
				     "EncKDCRepPart", NULL);
}

int
shishi_enckdcreppart_save (Shishi * handle,
			   FILE * fh, ASN1_TYPE enckdcreppart)
{
  return _shishi_save_data (handle, fh, enckdcreppart, "EncKDCRepPart");
}

int
shishi_ticket_save (Shishi * handle, FILE * fh, ASN1_TYPE ticket)
{
  return _shishi_save_data (handle, fh, ticket, "Ticket");
}

int
shishi_asn1ticket_print (Shishi * handle, FILE * fh, ASN1_TYPE ticket)
{
  return _shishi_print_armored_data (handle, fh, ticket, "Ticket", NULL);
}

int
shishi_encticketpart_print (Shishi * handle, FILE * fh,
			    ASN1_TYPE encticketpart)
{
  return _shishi_print_armored_data (handle, fh, encticketpart,
				     "EncTicketPart", NULL);
}

static int
_shishi_read_armored_data (Shishi * handle,
			   FILE * fh, char *buffer, int len, char *tag)
{
  int lno = 0;
  int maxsize = len;
  char line[BUFSIZ];
  char armorbegin[BUFSIZ];
  char armorend[BUFSIZ];
  int in_data = 0;

  sprintf (armorbegin, HEADERBEG, tag);
  sprintf (armorend, HEADEREND, tag);

  len = 0;
  while (fgets (line, sizeof (line), fh))
    {
      lno++;
      line[sizeof (line) - 1] = '\0';
      if (!*line || line[strlen (line) - 1] != '\n')
	{
	  fprintf (stderr, "input line %u too long or missing LF\n", lno);
	  continue;
	}
      line[strlen (line) - 1] = '\0';
      if (VERBOSE (handle))
	printf ("line %d read %d bytes: %s\n", lno, strlen (line), line);

      /* XXX check if all chars in line are b64 data, otherwise bail out */

      if (in_data)
	{
	  if (strncmp (line, armorend, strlen (armorend)) == 0)
	    break;
	}
      else
	{
	  in_data = strncmp (line, armorbegin, strlen (armorbegin)) == 0;
	  continue;
	}

      if (len + strlen (line) >= maxsize)
	{
	  shishi_error_printf (handle, "too large input size on line %d\n",
			       lno);
	  return !SHISHI_OK;
	}

      memcpy (buffer + len, line, strlen (line));
      len += strlen (line);
    }

  if (len <= 0)
    return !SHISHI_OK;

  buffer[len] = '\0';

  return SHISHI_OK;
}

static int
_shishi_ticket_input (Shishi * handle,
		      FILE * fh, ASN1_TYPE * ticket, int type)
{
  char der[BUFSIZ];
  size_t derlen;
  char errorDescription[MAX_ERROR_DESCRIPTION_SIZE];
  char b64der[BUFSIZ];
  size_t b64len = 0;
  int res;
  int i;
  size_t nread;
  int in_data = 0;
  int lno = 0;

  if (type == 0)
    {
      b64len = sizeof (b64der);
      res = _shishi_read_armored_data (handle, fh, b64der, b64len, "Ticket");
      if (res != SHISHI_OK)
	{
	  printf ("armor data read fail\n");
	  return res;
	}

      derlen = shishi_from_base64 (&der[0], b64der);
    }
  else
    {
      derlen =
	fread (der, sizeof (der[0]), sizeof (der) / sizeof (der[0]), fh);
      if (derlen <= 0 || !feof (fh) || ferror (fh))
	{
	  shishi_error_printf (handle,
			       "Error reading from file (got %d bytes)...",
			       derlen);
	  return !SHISHI_OK;
	}
    }

  *ticket = shishi_der2asn1_ticket (handle->asn1, der,
				    derlen, errorDescription);
  if (*ticket == ASN1_TYPE_EMPTY)
    {
      shishi_error_printf (handle, "Could not DER decode Ticket: %s",
			   errorDescription);

      return !SHISHI_OK;
    }

  return SHISHI_OK;
}

int
shishi_ticket_parse (Shishi * handle, FILE * fh, ASN1_TYPE * ticket)
{
  return _shishi_ticket_input (handle, fh, ticket, 0);
}

int
shishi_ticket_read (Shishi * handle, FILE * fh, ASN1_TYPE * ticket)
{
  return _shishi_ticket_input (handle, fh, ticket, 1);
}

int
_shishi_enckdcreppart_input (Shishi * handle,
			     FILE * fh, ASN1_TYPE * enckdcreppart, int type)
{
  char der[BUFSIZ];
  size_t derlen;
  char errorDescription[MAX_ERROR_DESCRIPTION_SIZE];
  char b64der[BUFSIZ];
  size_t b64len = 0;
  int res;
  int i;
  size_t nread;
  int in_data = 0;
  int lno = 0;

  if (type == 0)
    {
      b64len = sizeof (b64der);
      res = _shishi_read_armored_data (handle, fh,
				       b64der, b64len, "EncKDCRepPart");
      if (res != SHISHI_OK)
	{
	  shishi_error_printf (handle, "armor data read fail\n");
	  return res;
	}

      derlen = shishi_from_base64 (&der[0], b64der);
    }
  else
    {
      derlen =
	fread (der, sizeof (der[0]), sizeof (der) / sizeof (der[0]), fh);
      if (derlen <= 0 || !feof (fh) || ferror (fh))
	{
	  shishi_error_printf (handle,
			       "Error reading from file (got %d bytes)...",
			       derlen);
	  return !SHISHI_OK;
	}
    }

  *enckdcreppart = shishi_der2asn1_encasreppart (handle->asn1, der,
						 derlen, errorDescription);
  if (*enckdcreppart == ASN1_TYPE_EMPTY)
    {
      shishi_error_printf (handle, "Could not DER decode Encasreppart: %s",
			   errorDescription);

      *enckdcreppart = shishi_der2asn1_enctgsreppart (handle->asn1, der,
						      derlen,
						      errorDescription);
      if (*enckdcreppart == ASN1_TYPE_EMPTY)
	{
	  shishi_error_printf (handle,
			       "Could not DER decode Enctgsreppart: %s",
			       errorDescription);

	  *enckdcreppart = shishi_der2asn1_enckdcreppart (handle->asn1, der,
							  derlen,
							  errorDescription);
	  if (*enckdcreppart == ASN1_TYPE_EMPTY)
	    {
	      shishi_error_printf (handle,
				   "Could not DER decode Enckdcreppart: %s",
				   errorDescription);
	      return !SHISHI_OK;
	    }
	}
    }

  return SHISHI_OK;
}

int
shishi_enckdcreppart_parse (Shishi * handle,
			    FILE * fh, ASN1_TYPE * enckdcreppart)
{
  return _shishi_enckdcreppart_input (handle, fh, enckdcreppart, 0);
}

int
shishi_enckdcreppart_read (Shishi * handle,
			   FILE * fh, ASN1_TYPE * enckdcreppart)
{
  return _shishi_enckdcreppart_input (handle, fh, enckdcreppart, 1);
}

int
_shishi_kdcreq_input (Shishi * handle, FILE * fh, ASN1_TYPE * asreq, int type)
{
  char der[BUFSIZ];
  size_t derlen;
  char errorDescription[MAX_ERROR_DESCRIPTION_SIZE];
  char b64der[BUFSIZ];
  size_t b64len = 0;
  int res;
  int i;
  size_t nread;
  int in_data = 0;
  int lno = 0;

  if (type == 0)
    {
      b64len = sizeof (b64der);
      res = _shishi_read_armored_data (handle, fh, b64der, b64len, "KDC-REQ");
      if (res != SHISHI_OK)
	{
	  printf ("armor data read fail\n");
	  return res;
	}

      derlen = shishi_from_base64 (&der[0], b64der);
    }
  else
    {
      derlen =
	fread (der, sizeof (der[0]), sizeof (der) / sizeof (der[0]), fh);
      if (derlen <= 0 || !feof (fh) || ferror (fh))
	{
	  shishi_error_printf (handle,
			       "Error reading from file (got %d bytes)...",
			       derlen);
	  return !SHISHI_OK;
	}
    }

  *asreq = shishi_der2asn1_as_req (handle->asn1, der,
				   derlen, errorDescription);
  if (*asreq == ASN1_TYPE_EMPTY)
    {
      printf ("bad magic %s\n", errorDescription);
      shishi_error_printf (handle, "Could not DER decode AS-REQ\n");

      *asreq = shishi_der2asn1_tgs_req (handle->asn1, der,
					derlen, errorDescription);
      if (*asreq == ASN1_TYPE_EMPTY)
	{
	  printf ("bad magic %s\n", errorDescription);
	  shishi_error_printf (handle, "Could not DER decode TGS-REQ\n");

	  *asreq = shishi_der2asn1_kdc_req (handle->asn1, der,
					    derlen, errorDescription);
	  if (*asreq == ASN1_TYPE_EMPTY)
	    {
	      printf ("bad magic %s\n", errorDescription);
	      shishi_error_printf (handle, "Could not DER decode KDC-REQ\n");

	      return !SHISHI_OK;
	    }
	}
    }

  return SHISHI_OK;
}

int
_shishi_kdcrep_input (Shishi * handle, FILE * fh, ASN1_TYPE * asrep, int type)
{
  char der[BUFSIZ];
  size_t derlen;
  char errorDescription[MAX_ERROR_DESCRIPTION_SIZE];
  char b64der[BUFSIZ];
  size_t b64len = 0;
  int res;
  int i;

  if (type == 0)
    {
      b64len = sizeof (b64der);
      res = _shishi_read_armored_data (handle, fh, b64der, b64len, "KDC-REP");
      if (res != SHISHI_OK)
	{
	  printf ("armor data read fail\n");
	  return res;
	}

      derlen = shishi_from_base64 (&der[0], b64der);
    }
  else
    {
      derlen =
	fread (der, sizeof (der[0]), sizeof (der) / sizeof (der[0]), fh);
      if (derlen <= 0 || !feof (fh) || ferror (fh))
	{
	  shishi_error_printf (handle,
			       "Error reading from file (got %d bytes)...",
			       derlen);
	  return !SHISHI_OK;
	}
    }

  *asrep = shishi_der2asn1_as_rep (handle->asn1, der,
				   derlen, errorDescription);
  if (*asrep == ASN1_TYPE_EMPTY)
    {
      printf ("Could not DER decode AS-REP: %s\n", errorDescription);
      printf ("Trying TGS-REP...\n");

      *asrep = shishi_der2asn1_tgs_rep (handle->asn1, der,
					derlen, errorDescription);
      if (*asrep == ASN1_TYPE_EMPTY)
	{
	  printf ("Could not DER decode KDC-REP: %s\n", errorDescription);
	  printf ("Parsing AS/TGS-REP as KDC-REP (bug work around)\n");

	  *asrep = shishi_der2asn1_kdc_rep (handle->asn1, der,
					    derlen, errorDescription);
	  if (*asrep == ASN1_TYPE_EMPTY)
	    {
	      fprintf (stderr, "Could not DER decode KDC-REP: %s\n",
		       errorDescription);
	      return ASN1_TYPE_EMPTY;
	    }

	  fprintf (stderr, "Bug workaround code successful...\n");
	}
    }

  asn1_print_structure (stdout, *asrep, (*asrep)->name,
			ASN1_PRINT_NAME_TYPE_VALUE);

  return SHISHI_OK;
}

int
_shishi_apreq_input (Shishi * handle, FILE * fh, ASN1_TYPE * apreq, int type)
{
  char der[BUFSIZ];
  size_t derlen;
  char errorDescription[MAX_ERROR_DESCRIPTION_SIZE];
  char b64der[BUFSIZ];
  size_t b64len = 0;
  int res;
  int i;
  size_t nread;
  int in_data = 0;
  int lno = 0;

  if (type == 0)
    {
      b64len = sizeof (b64der);
      res = _shishi_read_armored_data (handle, fh, b64der, b64len, "AP-REQ");
      if (res != SHISHI_OK)
	{
	  printf ("armor data read fail\n");
	  return res;
	}

      derlen = shishi_from_base64 (&der[0], b64der);
    }
  else
    {
      derlen =
	fread (der, sizeof (der[0]), sizeof (der) / sizeof (der[0]), fh);
      if (derlen <= 0 || !feof (fh) || ferror (fh))
	{
	  shishi_error_printf (handle,
			       "Error reading from file (got %d bytes)...",
			       derlen);
	  return !SHISHI_OK;
	}
    }

  *apreq = shishi_der2asn1_ap_req (handle->asn1, der,
				   derlen, errorDescription);
  if (*apreq == ASN1_TYPE_EMPTY)
    {
      printf ("bad magic %s\n", errorDescription);
      shishi_error_printf (handle, "Could not DER decode AP-REQ\n");

      return !SHISHI_OK;
    }

  return SHISHI_OK;
}

int
_shishi_aprep_input (Shishi * handle, FILE * fh, ASN1_TYPE * aprep, int type)
{
  char der[BUFSIZ];
  size_t derlen;
  char errorDescription[MAX_ERROR_DESCRIPTION_SIZE];
  char b64der[BUFSIZ];
  size_t b64len = 0;
  int res;
  int i;
  size_t nread;
  int in_data = 0;
  int lno = 0;

  if (type == 0)
    {
      b64len = sizeof (b64der);
      res = _shishi_read_armored_data (handle, fh, b64der, b64len, "AP-REP");
      if (res != SHISHI_OK)
	{
	  printf ("armor data read fail\n");
	  return res;
	}

      derlen = shishi_from_base64 (&der[0], b64der);
    }
  else
    {
      derlen =
	fread (der, sizeof (der[0]), sizeof (der) / sizeof (der[0]), fh);
      if (derlen <= 0 || !feof (fh) || ferror (fh))
	{
	  shishi_error_printf (handle,
			       "Error reading from file (got %d bytes)...",
			       derlen);
	  return !SHISHI_OK;
	}
    }

  *aprep = shishi_der2asn1_ap_req (handle->asn1, der,
				   derlen, errorDescription);
  if (*aprep == ASN1_TYPE_EMPTY)
    {
      printf ("bad magic %s\n", errorDescription);
      shishi_error_printf (handle, "Could not DER decode AP-REP\n");

      return !SHISHI_OK;
    }

  return SHISHI_OK;
}

int
_shishi_encapreppart_input (Shishi * handle, FILE * fh,
			    ASN1_TYPE * encapreppart, int type)
{
  char der[BUFSIZ];
  size_t derlen;
  char errorDescription[MAX_ERROR_DESCRIPTION_SIZE];
  char b64der[BUFSIZ];
  size_t b64len = 0;
  int res;
  int i;
  size_t nread;
  int in_data = 0;
  int lno = 0;

  if (type == 0)
    {
      b64len = sizeof (b64der);
      res =
	_shishi_read_armored_data (handle, fh, b64der, b64len,
				   "EncAPRepPart");
      if (res != SHISHI_OK)
	{
	  printf ("armor data read fail\n");
	  return res;
	}

      derlen = shishi_from_base64 (&der[0], b64der);
    }
  else
    {
      derlen =
	fread (der, sizeof (der[0]), sizeof (der) / sizeof (der[0]), fh);
      if (derlen <= 0 || !feof (fh) || ferror (fh))
	{
	  shishi_error_printf (handle,
			       "Error reading from file (got %d bytes)...",
			       derlen);
	  return !SHISHI_OK;
	}
    }

  *encapreppart = shishi_d2a_encapreppart (handle->asn1, der, derlen);
  if (*encapreppart == ASN1_TYPE_EMPTY)
    {
      printf ("bad magic %s\n", errorDescription);
      shishi_error_printf (handle, "Could not DER decode EncAPRepPart\n");

      return !SHISHI_OK;
    }

  return SHISHI_OK;
}

int
_shishi_authenticator_input (Shishi * handle,
			     FILE * fh, ASN1_TYPE * authenticator, int type)
{
  char der[BUFSIZ];
  size_t derlen;
  char errorDescription[MAX_ERROR_DESCRIPTION_SIZE];
  char b64der[BUFSIZ];
  size_t b64len = 0;
  int res;
  int i;
  size_t nread;
  int in_data = 0;
  int lno = 0;

  if (type == 0)
    {
      b64len = sizeof (b64der);
      res = _shishi_read_armored_data (handle, fh, b64der, b64len,
				       "Authenticator");
      if (res != SHISHI_OK)
	{
	  printf ("armor data read fail\n");
	  return res;
	}

      derlen = shishi_from_base64 (&der[0], b64der);
    }
  else
    {
      derlen =
	fread (der, sizeof (der[0]), sizeof (der) / sizeof (der[0]), fh);
      if (derlen <= 0 || !feof (fh) || ferror (fh))
	{
	  shishi_error_printf (handle,
			       "Error reading from file (got %d bytes)...",
			       derlen);
	  return !SHISHI_OK;
	}
    }

  *authenticator = shishi_der2asn1_authenticator (handle->asn1, der,
						  derlen, errorDescription);
  if (*authenticator == ASN1_TYPE_EMPTY)
    {
      printf ("bad magic %s\n", errorDescription);
      shishi_error_printf (handle, "Could not DER decode AP-REQ\n");

      return !SHISHI_OK;
    }

  return SHISHI_OK;
}

int
_shishi_krberror_input (Shishi * handle,
			FILE * fh, ASN1_TYPE * krberror, int type)
{
  char der[BUFSIZ];
  size_t derlen;
  char errorDescription[MAX_ERROR_DESCRIPTION_SIZE];
  char b64der[BUFSIZ];
  size_t b64len = 0;
  int res;
  int i;
  size_t nread;
  int in_data = 0;
  int lno = 0;

  if (type == 0)
    {
      b64len = sizeof (b64der);
      res = _shishi_read_armored_data (handle, fh, b64der, b64len,
				       "KRB-ERROR");
      if (res != SHISHI_OK)
	{
	  printf ("armor data read fail\n");
	  return res;
	}

      derlen = shishi_from_base64 (&der[0], b64der);
    }
  else
    {
      derlen = fread (der, sizeof (der[0]),
		      sizeof (der) / sizeof (der[0]), fh);
      if (derlen <= 0 || !feof (fh) || ferror (fh))
	{
	  shishi_error_printf (handle,
			       "Error reading from file (got %d bytes)...",
			       derlen);
	  return !SHISHI_OK;
	}
    }

  *krberror = shishi_der2asn1_krberror (handle->asn1, der,
					derlen, errorDescription);
  if (*krberror == ASN1_TYPE_EMPTY)
    {
      printf ("bad magic %s\n", errorDescription);
      shishi_error_printf (handle, "Could not DER decode AP-REQ\n");

      return !SHISHI_OK;
    }

  return SHISHI_OK;
}

/**
 * shishi_key_print:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle opened for writing.
 * @key: key to print.
 * @clientname: optional string representation of name
 *              of principal owning key.
 * @realm:  optional string representation of realm
 *          of principal owning key.
 *
 * Print an ASCII representation of a key structure to file
 * descriptor.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_key_print (Shishi * handle, FILE * fh, Shishi *key,
		  char *clientname, char *realm)
{
  char b64key[BUFSIZ];
  int res;
  int i;

  shishi_to_base64 (b64key, shishi_key_value(key),
		    shishi_key_length(key), sizeof (b64key));

  fprintf (fh, HEADERBEG "\n", "KEY");

  fprintf (fh, "Keytype: %d (%s)\n", shishi_key_type(key),
	   shishi_cipher_name (shishi_key_type(key)));
  if (clientname)
    fprintf (fh, "Clientname: %s\n", clientname);
  if (realm)
    fprintf (fh, "Realm: %s\n", realm);
  if (shishi_key_version(key))
    fprintf (fh, "Key-Version-Number: %d\n", shishi_key_version(key));
  fprintf (fh, "\n");

  for (i = 0; i < strlen (b64key); i++)
    {
      fprintf (fh, "%c", b64key[i]);
      if ((i + 1) % 64 == 0)
	fprintf (fh, "\n");
    }
  if ((i + 1) % 64 != 0)
    fprintf (fh, "\n");

  fprintf (fh, HEADEREND "\n", "KEY");

  return SHISHI_OK;
}

/**
 * shishi_key_to_file:
 * @handle: shishi handle as allocated by shishi_init().
 * @filename: filename to append key to.
 * @key: key to print.
 * @clientname: optional string representation of name
 *              of principal owning key.
 * @realm:  optional string representation of realm
 *          of principal owning key.
 *
 * Print an ASCII representation of a key structure to a file.  The
 * file is appended to if it exists.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_key_to_file (Shishi * handle, char *filename, Shishi *key,
		    char *clientname, char *realm)
{
  FILE *fh;
  int res;

  if (VERBOSE (handle))
    printf (_("Writing KEY to %s...\n"), filename);

  fh = fopen (filename, "a");
  if (fh == NULL)
    return SHISHI_FOPEN_ERROR;

  res = shishi_key_print (handle, fh, key, clientname, realm);
  if (res != SHISHI_OK)
    return res;

  res = fclose (fh);
  if (res != 0)
    return SHISHI_FCLOSE_ERROR;

  if (VERBOSE (handle))
    printf (_("Writing KEY to %s...done\n"), filename);

  return SHISHI_OK;
}
