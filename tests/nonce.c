/* nonce.c --- Shishi nonce handling regression self tests.
 * Copyright (C) 2006, 2007  Simon Josefsson
 *
 * This file is part of Shishi.
 *
 * Shishi is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * Shishi is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Shishi; if not, see http://www.gnu.org/licenses or write
 * to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
 * Floor, Boston, MA 02110-1301, USA
 *
 */

const char *asreq = "aoGQMIGNoQMCAQWiAwIBCqSBgDB+oAcDBQAAAAAAoRAwDqADAgEAoQcwBRsDamFzog8bDUpPU0VGU1NPTi5PUkejIjAgoAMCAQGhGTAXGwZrcmJ0Z3QbDUpPU0VGU1NPTi5PUkelERgPMjAwNjExMDEyMDMwMDVapwYCBAlXUoOoETAPAgESAgEQAgEDAgECAgEB";
const char *asreppart = "eYGYMIGVoCMwIaADAgEQoRoEGPSJH0z06kWoouBUejc+L566tgEBAQEZDqECMACiBgIEf////6QHAwUAAEAAAKURGA8yMDA2MTEwMTEyMDkyNVqnERgPMjAwNjExMDEyMDA5MjVaqQ8bDUpPU0VGU1NPTi5PUkeqIjAgoAMCAQGhGTAXGwZrcmJ0Z3QbDUpPU0VGU1NPTi5PUkc=";

#include "utils.c"

#include <base64.h>

void
test (Shishi * handle)
{
  Shishi_asn1 req, rep;
  char *reqder, *repder;
  size_t reqderlen, repderlen;
  int rc;
  uint32_t nonce;

  if (!base64_decode_alloc (asreq, strlen (asreq), &reqder, &reqderlen))
    fail ("base64 req\n");

  if (!base64_decode_alloc (asreppart, strlen (asreppart), &repder, &repderlen))
    fail ("base64 rep\n");

  req = shishi_der2asn1_asreq (handle, reqder, reqderlen);
  if (!req)
    fail ("der2asn1 req\n");

  rep = shishi_der2asn1_encasreppart (handle, repder, repderlen);
  if (!rep)
    fail ("der2asn1 rep\n");

  if (debug)
    {
      shishi_kdcreq_print (handle, stdout, req);
      shishi_enckdcreppart_print (handle, stdout, rep);
    }

  /* Read and check req */

  rc = shishi_asn1_read_uint32 (handle, req, "req-body.nonce", &nonce);
  if (rc)
    fail ("shishi_asn1_read_uint32\n");

  printf ("req nonce: %x\n", nonce);

  if (nonce != 0x09575283)
    fail ("nonce mismatch low\n");

  rc = shishi_kdcreq_nonce (handle, req, &nonce);
  if (rc)
    fail ("shishi_kdcreq_nonce\n");

  printf ("req nonce: %x\n", nonce);

  if (nonce != 0x09575283)
    fail ("nonce mismatch high");

  /* Read and check rep */

  rc = shishi_asn1_read_uint32 (handle, rep, "nonce", &nonce);
  if (rc)
    fail ("read rep uint32");

  printf ("old rep nonce: %x\n", nonce);

  if (nonce != 0x7fffffff)
    fail ("nonce mismatch high");

  /* Copy nonce. */

  rc = shishi_kdc_copy_nonce (handle, req, rep);
  if (rc)
    fail ("shishi_kdc_copy_nonce\n");

  /* Read and check rep */

  rc = shishi_asn1_read_uint32 (handle, rep, "nonce", &nonce);
  if (rc)
    fail ("read rep uint32");

  printf ("new rep nonce: %x\n", nonce);

  if (nonce != 0x09575283)
    fail ("nonce mismatch high");

  free (reqder);
  free (repder);

  shishi_asn1_done (handle, req);
  shishi_asn1_done (handle, rep);
}
