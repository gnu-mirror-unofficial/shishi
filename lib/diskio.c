/* diskio.c --- Read and write data structures from disk.
 * Copyright (C) 2002, 2003, 2004, 2006, 2007, 2008  Simon Josefsson
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

/* XXX oh, please, rewrite this file. */

#include "internal.h"
#include "diskio.h"

#define HEADERBEG "-----BEGIN SHISHI %s-----"
#define HEADEREND "-----END SHISHI %s-----"

#define BUFSIZE 5000

/*
 * Note to self: if you change any *print* function, remember to change
 * the corresponding *parse* function too.
 *
 */

static char *
armor_data (const char *data, size_t len,
	    const char *armortype,
	    const char *armorheaders)
{
  /* Must be a multiple of 4. */
#define WRAP_COL 64
  char *armorbegin, *armorend;
  char *b64data, *out;
  size_t wrapb64len = BASE64_LENGTH (len) + BASE64_LENGTH (len) / WRAP_COL + 1;
  size_t i;

  b64data = xmalloc (wrapb64len + 1);

  for (i = 0; i <= BASE64_LENGTH (len) / WRAP_COL; i++)
    {
      size_t readpos = i * WRAP_COL * 3 /4;
      size_t nread = WRAP_COL * 3 /4;
      size_t storepos = i * WRAP_COL + i;
      size_t nstore = WRAP_COL;

      if (readpos >= len)
	break;

      if (readpos + nread >= len)
	{
	  nread = len - readpos;
	  nstore = BASE64_LENGTH (nread);
	}

      base64_encode (data + readpos, nread, b64data + storepos, nstore);
      b64data[storepos + nstore] = '\n';
      b64data[storepos + nstore + 1] = '\0';

#if 0
      printf ("alloc %d len %d curlen %d "
	      "readpos %d nread %d storepos %d nstore %d\n",
	      wrapb64len + 1, len, strlen (b64data),
	      readpos, nread, storepos, nstore);
#endif
    }

  armorbegin = xasprintf (HEADERBEG, armortype);
  armorend = xasprintf (HEADEREND, armortype);

  out = xasprintf ("%s\n%s%s%s%s\n",
		   armorbegin,
		   armorheaders ? armorheaders : "",
		   armorheaders ? "\n" : "",
		   b64data,
		   armorend);

  free (b64data);
  free (armorend);
  free (armorbegin);

  return out;
}

static char *
armor_asn1 (Shishi * handle,
	    Shishi_asn1 asn1,
	    const char *armortype,
	    const char *armorheaders)
{
  char *der;
  size_t derlen;
  char *out;
  int rc;

  rc = shishi_asn1_to_der (handle, asn1, &der, &derlen);
  if (rc != SHISHI_OK)
    return NULL;

  out = armor_data (der, derlen, armortype, armorheaders);

  free (der);

  return out;
}

int
_shishi_print_armored_data (Shishi * handle,
			    FILE * fh,
			    Shishi_asn1 asn1,
			    const char *asn1type, char *headers)
{
  char *data = armor_asn1 (handle, asn1, asn1type, headers);

  shishi_asn1_print (handle, asn1, fh);

  fprintf (fh, "%s\n", data);

  return SHISHI_OK;
}

int
_shishi_save_data (Shishi * handle, FILE * fh, Shishi_asn1 asn1,
		   const char *asn1type)
{
  char *der;
  size_t derlen;
  size_t i;
  int res;

  res = shishi_asn1_to_der_field (handle, asn1, asn1type, &der, &derlen);
  if (res != SHISHI_OK)
    return res;

  i = fwrite (der, sizeof (der[0]), derlen, fh);
  if (i != derlen)
    return SHISHI_IO_ERROR;

  return SHISHI_OK;
}

int
shishi_padata_print (Shishi * handle, FILE * fh, Shishi_asn1 padata)
{
  return _shishi_print_armored_data (handle, fh, padata, "PA-DATA", NULL);
}

int
shishi_methoddata_print (Shishi * handle, FILE * fh, Shishi_asn1 methoddata)
{
  return _shishi_print_armored_data (handle, fh, methoddata,
				     "METHOD-DATA", NULL);
}

int
shishi_etype_info_print (Shishi * handle, FILE * fh, Shishi_asn1 etypeinfo)
{
  return _shishi_print_armored_data (handle, fh, etypeinfo,
				     "ETYPE-INFO", NULL);
}

int
shishi_etype_info2_print (Shishi * handle, FILE * fh, Shishi_asn1 etypeinfo2)
{
  return _shishi_print_armored_data (handle, fh, etypeinfo2,
				     "ETYPE-INFO2", NULL);
}

int
shishi_enckdcreppart_print (Shishi * handle,
			    FILE * fh, Shishi_asn1 enckdcreppart)
{
  return _shishi_print_armored_data (handle, fh, enckdcreppart,
				     "EncKDCRepPart", NULL);
}

int
shishi_enckdcreppart_save (Shishi * handle,
			   FILE * fh, Shishi_asn1 enckdcreppart)
{
  return _shishi_save_data (handle, fh, enckdcreppart, "EncKDCRepPart");
}

int
shishi_ticket_save (Shishi * handle, FILE * fh, Shishi_asn1 ticket)
{
  return _shishi_save_data (handle, fh, ticket, "Ticket");
}

int
shishi_ticket_print (Shishi * handle, FILE * fh, Shishi_asn1 ticket)
{
  return _shishi_print_armored_data (handle, fh, ticket, "Ticket", NULL);
}

int
shishi_encticketpart_print (Shishi * handle, FILE * fh,
			    Shishi_asn1 encticketpart)
{
  return _shishi_print_armored_data (handle, fh, encticketpart,
				     "EncTicketPart", NULL);
}

static int
_shishi_read_armored_data (Shishi * handle,
			   FILE * fh, char *buffer, size_t len,
			   const char *tag)
{
  char *line = NULL;
  size_t linelen = 0;
  char *armorbegin, *armorend;
  int phase = 0;
  int res = SHISHI_OK;

  armorbegin = xasprintf (HEADERBEG, tag);
  armorend = xasprintf (HEADEREND, tag);

  while (getline (&line, &linelen, fh) > 0)
    {
      while (*line && strchr ("\n\r\t ", line[strlen (line) - 1]))
	line[strlen (line) - 1] = '\0';

      if (phase == 1)
	{
	  if (strcmp (line, armorend) == 0)
	    {
	      phase = 2;
	      break;
	    }
	}
      else
	{
	  if (strcmp (line, armorbegin) == 0)
	    phase = 1;
	  continue;
	}

      if (len <= strlen (line))
	{
	  res = SHISHI_TOO_SMALL_BUFFER;
	  goto done;
	}

      memcpy (buffer, line, strlen (line));
      buffer += strlen (line);
      len -= strlen (line);
    }

  if (len == 0)
    res = SHISHI_TOO_SMALL_BUFFER;
  else
    *buffer = '\0';

  if (phase != 2)
    res = SHISHI_IO_ERROR;

 done:

  free (armorbegin);
  free (armorend);
  if (line)
    free (line);

  return res;
}

static int
_shishi_ticket_input (Shishi * handle,
		      FILE * fh, Shishi_asn1 * ticket, int type)
{
  char der[BUFSIZE];
  size_t derlen;
  char b64der[BUFSIZE];
  size_t b64len = 0;
  int res;

  if (type == 0)
    {
      b64len = sizeof (b64der);
      res = _shishi_read_armored_data (handle, fh, b64der, b64len, "Ticket");
      if (res != SHISHI_OK)
	{
	  shishi_error_printf (handle, "armor data read fail\n");
	  return res;
	}

      derlen = sizeof (der);
      if (!base64_decode (b64der, strlen (b64der), der, &derlen))
	return SHISHI_BASE64_ERROR;
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

  *ticket = shishi_der2asn1_ticket (handle, der, derlen);
  if (*ticket == NULL)
    return SHISHI_ASN1_ERROR;

  return SHISHI_OK;
}

int
shishi_ticket_parse (Shishi * handle, FILE * fh, Shishi_asn1 * ticket)
{
  return _shishi_ticket_input (handle, fh, ticket, 0);
}

int
shishi_ticket_read (Shishi * handle, FILE * fh, Shishi_asn1 * ticket)
{
  return _shishi_ticket_input (handle, fh, ticket, 1);
}

static int
_shishi_enckdcreppart_input (Shishi * handle,
			     FILE * fh, Shishi_asn1 * enckdcreppart, int type)
{
  char der[BUFSIZE];
  size_t derlen;
  char b64der[BUFSIZE];
  size_t b64len = 0;
  int res;

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

      derlen = sizeof (der);
      if (!base64_decode (b64der, strlen (b64der), der, &derlen))
	return SHISHI_BASE64_ERROR;
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

  *enckdcreppart = shishi_der2asn1_encasreppart (handle, der, derlen);
  if (*enckdcreppart == NULL)
    {
      shishi_error_printf (handle, "Could not DER decode Encasreppart: %s",
			   shishi_error (handle));

      *enckdcreppart = shishi_der2asn1_enctgsreppart (handle, der, derlen);
      if (*enckdcreppart == NULL)
	{
	  shishi_error_printf (handle,
			       "Could not DER decode Enctgsreppart: %s",
			       shishi_error (handle));

	  *enckdcreppart =
	    shishi_der2asn1_enckdcreppart (handle, der, derlen);
	  if (*enckdcreppart == NULL)
	    {
	      shishi_error_printf (handle,
				   "Could not DER decode Enckdcreppart: %s",
				   shishi_error (handle));
	      return !SHISHI_OK;
	    }
	}
    }

  return SHISHI_OK;
}

int
shishi_enckdcreppart_parse (Shishi * handle,
			    FILE * fh, Shishi_asn1 * enckdcreppart)
{
  return _shishi_enckdcreppart_input (handle, fh, enckdcreppart, 0);
}

int
shishi_enckdcreppart_read (Shishi * handle,
			   FILE * fh, Shishi_asn1 * enckdcreppart)
{
  return _shishi_enckdcreppart_input (handle, fh, enckdcreppart, 1);
}

int
_shishi_kdcreq_input (Shishi * handle, FILE * fh, Shishi_asn1 * asreq,
		      int type)
{
  char der[BUFSIZE];
  size_t derlen;
  char b64der[BUFSIZE];
  size_t b64len = 0;
  int res;

  if (type == 0)
    {
      b64len = sizeof (b64der);
      res = _shishi_read_armored_data (handle, fh, b64der, b64len, "KDC-REQ");
      if (res != SHISHI_OK)
	{
	  shishi_error_printf (handle, "armor data read fail\n");
	  return res;
	}

      derlen = sizeof (der);
      if (!base64_decode (b64der, strlen (b64der), der, &derlen))
	return SHISHI_BASE64_ERROR;
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

  *asreq = shishi_der2asn1_asreq (handle, der, derlen);
  if (*asreq == NULL)
    {
      printf ("bad asreq magic\n");
      shishi_error_printf (handle, "Could not DER decode AS-REQ\n");

      *asreq = shishi_der2asn1_tgsreq (handle, der, derlen);
      if (*asreq == NULL)
	{
	  printf ("bad tgsreq magic\n");
	  shishi_error_printf (handle, "Could not DER decode TGS-REQ\n");

	  *asreq = shishi_der2asn1_kdcreq (handle, der, derlen);
	  if (*asreq == NULL)
	    {
	      printf ("bad kdcreq magic\n");
	      shishi_error_printf (handle, "Could not DER decode KDC-REQ\n");

	      return !SHISHI_OK;
	    }
	}
    }

  return SHISHI_OK;
}

int
_shishi_kdcrep_input (Shishi * handle, FILE * fh, Shishi_asn1 * asrep,
		      int type)
{
  char der[BUFSIZE];
  size_t derlen;
  char b64der[BUFSIZE];
  size_t b64len = 0;
  int res;

  if (type == 0)
    {
      b64len = sizeof (b64der);
      res = _shishi_read_armored_data (handle, fh, b64der, b64len, "KDC-REP");
      if (res != SHISHI_OK)
	{
	  shishi_error_printf (handle, "armor data read fail\n");
	  return res;
	}

      derlen = sizeof (der);
      if (!base64_decode (b64der, strlen (b64der), der, &derlen))
	return SHISHI_BASE64_ERROR;
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

  *asrep = shishi_der2asn1_asrep (handle, der, derlen);
  if (*asrep == NULL)
    {
      *asrep = shishi_der2asn1_tgsrep (handle, der, derlen);
      if (*asrep == NULL)
	{
	  printf ("Could not DER decode KDC-REP: %s\n",
		  shishi_error (handle));
	  printf ("Parsing AS/TGS-REP as KDC-REP (bug work around)\n");

	  *asrep = shishi_der2asn1_kdcrep (handle, der, derlen);
	  if (*asrep == NULL)
	    {
	      fprintf (stderr, "Could not DER decode KDC-REP: %s\n",
		       shishi_error (handle));
	      return !SHISHI_OK;
	    }

	  fprintf (stderr, "Bug workaround code successful...\n");
	}
    }

  return SHISHI_OK;
}

int
_shishi_apreq_input (Shishi * handle, FILE * fh, Shishi_asn1 * apreq,
		     int type)
{
  char der[BUFSIZE];
  size_t derlen;
  char b64der[BUFSIZE];
  size_t b64len = 0;
  int res;

  if (type == 0)
    {
      b64len = sizeof (b64der);
      res = _shishi_read_armored_data (handle, fh, b64der, b64len, "AP-REQ");
      if (res != SHISHI_OK)
	{
	  shishi_error_printf (handle, "armor data read fail\n");
	  return res;
	}

      derlen = sizeof (der);
      if (!base64_decode (b64der, strlen (b64der), der, &derlen))
	return SHISHI_BASE64_ERROR;
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

  *apreq = shishi_der2asn1_apreq (handle, der, derlen);
  if (*apreq == NULL)
    {
      printf ("bad magic %s\n", shishi_error (handle));
      shishi_error_printf (handle, "Could not DER decode AP-REQ\n");

      return !SHISHI_OK;
    }

  return SHISHI_OK;
}

int
_shishi_aprep_input (Shishi * handle, FILE * fh, Shishi_asn1 * aprep,
		     int type)
{
  char der[BUFSIZE];
  size_t derlen;
  char b64der[BUFSIZE];
  size_t b64len = 0;
  int res;

  if (type == 0)
    {
      b64len = sizeof (b64der);
      res = _shishi_read_armored_data (handle, fh, b64der, b64len, "AP-REP");
      if (res != SHISHI_OK)
	{
	  shishi_error_printf (handle, "armor data read fail\n");
	  return res;
	}

      derlen = sizeof (der);
      if (!base64_decode (b64der, strlen (b64der), der, &derlen))
	return SHISHI_BASE64_ERROR;
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

  *aprep = shishi_der2asn1_aprep (handle, der, derlen);
  if (*aprep == NULL)
    {
      printf ("bad magic %s\n", shishi_error (handle));
      shishi_error_printf (handle, "Could not DER decode AP-REP\n");

      return !SHISHI_OK;
    }

  return SHISHI_OK;
}

int
_shishi_encapreppart_input (Shishi * handle, FILE * fh,
			    Shishi_asn1 * encapreppart, int type)
{
  char der[BUFSIZE];
  size_t derlen;
  char b64der[BUFSIZE];
  size_t b64len = 0;
  int res;

  if (type == 0)
    {
      b64len = sizeof (b64der);
      res =
	_shishi_read_armored_data (handle, fh, b64der, b64len,
				   "EncAPRepPart");
      if (res != SHISHI_OK)
	{
	  shishi_error_printf (handle, "armor data read fail\n");
	  return res;
	}

      derlen = sizeof (der);
      if (!base64_decode (b64der, strlen (b64der), der, &derlen))
	return SHISHI_BASE64_ERROR;
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

  *encapreppart = shishi_der2asn1_encapreppart (handle, der, derlen);
  if (*encapreppart == NULL)
    {
      printf ("bad magic %s\n", shishi_error (handle));
      shishi_error_printf (handle, "Could not DER decode EncAPRepPart\n");

      return !SHISHI_OK;
    }

  return SHISHI_OK;
}

int
_shishi_authenticator_input (Shishi * handle,
			     FILE * fh, Shishi_asn1 * authenticator, int type)
{
  char der[BUFSIZE];
  size_t derlen;
  char b64der[BUFSIZE];
  size_t b64len = 0;
  int res;

  if (type == 0)
    {
      b64len = sizeof (b64der);
      res = _shishi_read_armored_data (handle, fh, b64der, b64len,
				       "Authenticator");
      if (res != SHISHI_OK)
	{
	  shishi_error_printf (handle, "armor data read fail\n");
	  return res;
	}

      derlen = sizeof (der);
      if (!base64_decode (b64der, strlen (b64der), der, &derlen))
	return SHISHI_BASE64_ERROR;
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

  *authenticator = shishi_der2asn1_authenticator (handle, der, derlen);
  if (*authenticator == NULL)
    {
      printf ("bad magic %s\n", shishi_error (handle));
      shishi_error_printf (handle, "Could not DER decode AP-REQ\n");

      return !SHISHI_OK;
    }

  return SHISHI_OK;
}

int
_shishi_krberror_input (Shishi * handle,
			FILE * fh, Shishi_asn1 * krberror, int type)
{
  char der[BUFSIZE];
  size_t derlen;
  char b64der[BUFSIZE];
  size_t b64len = 0;
  int res;

  if (type == 0)
    {
      b64len = sizeof (b64der);
      res = _shishi_read_armored_data (handle, fh, b64der, b64len,
				       "KRB-ERROR");
      if (res != SHISHI_OK)
	{
	  shishi_error_printf (handle, "armor data read fail\n");
	  return res;
	}

      derlen = sizeof (der);
      if (!base64_decode (b64der, strlen (b64der), der, &derlen))
	return SHISHI_BASE64_ERROR;
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

  *krberror = shishi_der2asn1_krberror (handle, der, derlen);
  if (*krberror == NULL)
    {
      printf ("bad magic %s\n", shishi_error (handle));
      shishi_error_printf (handle, "Could not DER decode AP-REQ\n");

      return !SHISHI_OK;
    }

  return SHISHI_OK;
}

int
_shishi_safe_input (Shishi * handle, FILE * fh, Shishi_asn1 * safe, int type)
{
  char der[BUFSIZE];
  size_t derlen;
  char b64der[BUFSIZE];
  size_t b64len = 0;
  int res;

  if (type == 0)
    {
      b64len = sizeof (b64der);
      res = _shishi_read_armored_data (handle, fh, b64der, b64len,
				       "KRB-SAFE");
      if (res != SHISHI_OK)
	{
	  shishi_error_printf (handle, "armor data read fail\n");
	  return res;
	}

      derlen = sizeof (der);
      if (!base64_decode (b64der, strlen (b64der), der, &derlen))
	return SHISHI_BASE64_ERROR;
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

  *safe = shishi_der2asn1_krbsafe (handle, der, derlen);
  if (*safe == NULL)
    {
      printf ("bad magic %s\n", shishi_error (handle));
      shishi_error_printf (handle, "Could not DER decode KRB-SAFE\n");

      return !SHISHI_OK;
    }

  return SHISHI_OK;
}

int
_shishi_priv_input (Shishi * handle, FILE * fh, Shishi_asn1 * priv, int type)
{
  char der[BUFSIZE];
  size_t derlen;
  char b64der[BUFSIZE];
  size_t b64len = 0;
  int res;

  if (type == 0)
    {
      b64len = sizeof (b64der);
      res = _shishi_read_armored_data (handle, fh, b64der, b64len,
				       "KRB-PRIV");
      if (res != SHISHI_OK)
	{
	  shishi_error_printf (handle, "armor data read fail\n");
	  return res;
	}

      derlen = sizeof (der);
      if (!base64_decode (b64der, strlen (b64der), der, &derlen))
	return SHISHI_BASE64_ERROR;
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

  *priv = shishi_der2asn1_priv (handle, der, derlen);
  if (*priv == NULL)
    {
      printf ("bad magic %s\n", shishi_error (handle));
      shishi_error_printf (handle, "Could not DER decode KRB-PRIV\n");

      return !SHISHI_OK;
    }

  return SHISHI_OK;
}

int
shishi_key_parse (Shishi * handle, FILE * fh, Shishi_key ** key)
{
  int lno = 0;
  char line[BUFSIZE];
  char *b64buffer;
  char armorbegin[BUFSIZE];
  char armorend[BUFSIZE];
  int in_key = 0, in_body = 0;
  int res;
  size_t len;
  Shishi_key *lkey = NULL;

  sprintf (armorbegin, HEADERBEG, "KEY");
  sprintf (armorend, HEADEREND, "KEY");

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
      if (VERBOSENOISE (handle))
	printf ("line %d read %d bytes: %s\n", lno, strlen (line), line);

      if (!in_key)
	{
	  in_key = strncmp (line, armorbegin, strlen (armorbegin)) == 0;
	  if (in_key)
	    {
	      res = shishi_key (handle, &lkey);
	      if (res != SHISHI_OK)
		return res;

	    }
	  continue;
	}

      if (strcmp (line, armorend) == 0)
	break;

      if (in_body)
	{
	  int ok = base64_decode_alloc (line, strlen (line), &b64buffer, NULL);
	  if (!ok)
	    return SHISHI_BASE64_ERROR;
	  shishi_key_value_set (lkey, b64buffer);
	}
      else
	{
	  if (strcmp (line, "") == 0 || strcmp (line, " ") == 0)
	    in_body = 1;

	  if (strncmp (line, "Keytype: ", strlen ("Keytype: ")) == 0)
	    {
	      int type;
	      if (sscanf (line, "Keytype: %d (", &type) == 1)
		shishi_key_type_set (lkey, type);
	    }
	  else if (strncmp (line, "Key-Version-Number: ",
			    strlen ("Key-Version-Number: ")) == 0)
	    {
	      int type;
	      if (sscanf (line, "Key-Version-Number: %d", &type) == 1)
		shishi_key_version_set (lkey, type);
	    }
	  else if (strncmp (line, "Realm: ", strlen ("Realm: ")) == 0)
	    {
	      shishi_key_realm_set (lkey, line + strlen ("Realm: "));
	    }
	  else if (strncmp (line, "Principal: ", strlen ("Principal: ")) == 0)
	    {
	      shishi_key_principal_set (lkey, line + strlen ("Principal: "));
	    }
	}
    }

  if (!lkey)
    return SHISHI_OK;

  *key = lkey;

  return SHISHI_OK;
}

/**
 * shishi_key_print:
 * @handle: shishi handle as allocated by shishi_init().
 * @fh: file handle opened for writing.
 * @key: key to print.
 *
 * Print an ASCII representation of a key structure to file
 * descriptor.  Example output:
 *
 * -----BEGIN SHISHI KEY-----
 * Keytype: 18 (aes256-cts-hmac-sha1-96)
 * Principal: host/latte.josefsson.org
 * Realm: JOSEFSSON.ORG
 * Key-Version-Number: 1
 *
 * P1QdeW/oSiag/bTyVEBAY2msiGSTmgLXlopuCKoppDs=
 * -----END SHISHI KEY-----
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_key_print (Shishi * handle, FILE * fh, const Shishi_key * key)
{
  char *b64key;
  size_t i;

  base64_encode_alloc (shishi_key_value (key), shishi_key_length (key),
		       &b64key);

  if (!b64key)
    return SHISHI_MALLOC_ERROR;

  fprintf (fh, HEADERBEG "\n", "KEY");

  fprintf (fh, "Keytype: %d (%s)\n", shishi_key_type (key),
	   shishi_cipher_name (shishi_key_type (key)));
  if (shishi_key_principal (key))
    fprintf (fh, "Principal: %s\n", shishi_key_principal (key));
  if (shishi_key_realm (key))
    fprintf (fh, "Realm: %s\n", shishi_key_realm (key));
  if (shishi_key_version (key) != UINT32_MAX)
    fprintf (fh, "Key-Version-Number: %d\n", shishi_key_version (key));
  fprintf (fh, "\n");

  for (i = 0; i < strlen (b64key); i++)
    {
      fprintf (fh, "%c", b64key[i]);
      if ((i + 1) % 64 == 0)
	fprintf (fh, "\n");
    }
  if ((i + 1) % 64 != 0)
    fprintf (fh, "\n");

  free (b64key);

#if 0
  if (VERBOSENOISE (handle))
    {
      for (i = 0; i < shishi_key_length (key); i++)
	fprintf (stdout, "%02x", shishi_key_value (key)[i] & 0xFF);
      fprintf (stdout, "\n");
    }
#endif

  fprintf (fh, HEADEREND "\n", "KEY");

  return SHISHI_OK;
}

/**
 * shishi_key_to_file:
 * @handle: shishi handle as allocated by shishi_init().
 * @filename: filename to append key to.
 * @key: key to print.
 *
 * Print an ASCII representation of a key structure to a file.  The
 * file is appended to if it exists.  See shishi_key_print() for
 * format of output.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_key_to_file (Shishi * handle, const char *filename, Shishi_key * key)
{
  FILE *fh;
  int res;

  if (VERBOSE (handle))
    printf (_("Writing KEY to %s...\n"), filename);

  fh = fopen (filename, "a");
  if (fh == NULL)
    return SHISHI_FOPEN_ERROR;

  res = shishi_key_print (handle, fh, key);
  if (res != SHISHI_OK)
    return res;

  res = fclose (fh);
  if (res != 0)
    return SHISHI_IO_ERROR;

  if (VERBOSE (handle))
    printf (_("Writing KEY to %s...done\n"), filename);

  return SHISHI_OK;
}
