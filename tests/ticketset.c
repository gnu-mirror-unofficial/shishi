/* ticketset.c --- Shishi ticketset self tests.
 * Copyright (C) 2002, 2003, 2004, 2006, 2007, 2008  Simon Josefsson
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

#include "utils.c"

static const char tkt1kdcrepb64[] =
  "a4ICITCCAh2gAwIBBaEDAgELow8bDUpPU0VGU1NPTi5PUkekEDAOoAMCAQGhBzAF"
  "GwNqYXOlggECYYH/MIH8oAMCAQWhDxsNSk9TRUZTU09OLk9SR6IiMCCgAwIBAaEZ"
  "MBcbBmtyYnRndBsNSk9TRUZTU09OLk9SR6OBvzCBvKADAgEQoQMCAQGiga8Egayq"
  "ttjMpRNM2iVVR5RjtMNH3i75hjnUiXQ7UeT7DMShJ5IxiBr09dggaZzTAHrBAvV8"
  "5xON3p39rMpmCg9utizrxzT1JXruoGF/+ofuT7lEDfRr437QJD5WuOtlfmkM2i5s"
  "2bGYZlHNdBonapJCcMeUSS45HEoM5iy0dK2JeaOliOVKTDpX9gOayKSIFYnuzIb+"
  "cg1ATHm29ahK5AY+LU9E4v8Yj1/02srRuERApoHnMIHkoAMCARChAwIBBaKB1wSB"
  "1AiMSoSQrE5FSE2CYpTOdLgVWRw/k1cqBtswVKRTdgj2As6WG6mhFczy7RF62GVM"
  "6gJGNQRx1mAg0d5C7pNKRCgAZ2oQdJIGW6CLTy2L0LxM104HA0XrZ+zfFLKlZTOV"
  "T85LIoSneI/yKNh3iYeVQwp6AdMRw6562fHMie22I4sy22wNVz1toTrKixILvoMy"
  "eoD7ET43Y1eo0SeXj8LPmZyqLARBknl2ZvNcDpjWpI57QycHV28BhcvVPu72kObJ"
  "/68tCNEJ8J+vHArpFA5V9BDsFcGs";

static const char tkt1enckdcreppartb64[] =
  "eYGyMIGvoCMwIaADAgEQoRoEGPF/LFgc3IYq3+AZofutur+wsK5i6vSbN6EcMBow"
  "GKADAgEAoREYDzE5NzAwMTAxMDAwMDAwWqIGAgTl7iQgpAcDBQAAQAAApREYDzIw"
  "MDIxMjExMTM0MDU0WqcRGA8yMDAyMTIxMTEzNTczNFqpDxsNSk9TRUZTU09OLk9S"
  "R6oiMCCgAwIBAaEZMBcbBmtyYnRndBsNSk9TRUZTU09OLk9SRw==";

static const char tkt1ticketb64[] =
  "YYH/MIH8oAMCAQWhDxsNSk9TRUZTU09OLk9SR6IiMCCgAwIBAaEZMBcbBmtyYnRn"
  "dBsNSk9TRUZTU09OLk9SR6OBvzCBvKADAgEQoQMCAQGiga8EgayqttjMpRNM2iVV"
  "R5RjtMNH3i75hjnUiXQ7UeT7DMShJ5IxiBr09dggaZzTAHrBAvV85xON3p39rMpm"
  "Cg9utizrxzT1JXruoGF/+ofuT7lEDfRr437QJD5WuOtlfmkM2i5s2bGYZlHNdBon"
  "apJCcMeUSS45HEoM5iy0dK2JeaOliOVKTDpX9gOayKSIFYnuzIb+cg1ATHm29ahK"
  "5AY+LU9E4v8Yj1/02srRuERA";

static const char tkt2kdcrepb64[] =
  "bYICSjCCAkagAwIBBaEDAgENow8bDUpPU0VGU1NPTi5PUkekEDAOoAMCAQGhBzAF"
  "GwNqYXOlggEYYYIBFDCCARCgAwIBBaEPGw1KT1NFRlNTT04uT1JHoiYwJKADAgEB"
  "oR0wGxsEaG9zdBsTbGF0dGUuam9zZWZzc29uLm9yZ6OBzzCBzKADAgEQoQMCAQKi"
  "gb8EgbzEU6KFfSSQg4xxSxJBp2QBtaNGyzawROAGFsztZcY+gl5K2ki6xDT10kCY"
  "yfORXXXraoYIcwJl6EW8RGl4KKsZlZmNWuw0/mO4Gglga6sM06vQDs2TcSc8hWDJ"
  "4I1vU6/WlKtwzNj0Cw+6fqyDJIt6PmRpUe/yGZe6hSQkrqgQuBhpAHZF4/aoWqOm"
  "NufTdGa+5gHzqcEmQerWD8YhImeD+Xe5citg92XTPx2nHiNMBMmwgWJHf1Tjddiw"
  "saaB+jCB96ADAgEQooHvBIHsmctkNNI2jJwUEdTe9o5WeHyTCWMSO9AA0luxjX2D"
  "CR5kNOZuPx5YfHWHwKlqrOtwo1E0Cb7bpKHPUOWhhIGUXcV0z1ETSEOX8Ho3iIOc"
  "8LSNVq8UqVf/wBnndLiljZveTbbu+YcFNbF7g+q2VDYffKgXsUi6HV2Ue7OGawvY"
  "DxU7KDVpPWgitPGrNItdaJ1QVfVH+cXLdiqEV7RR+JOsFc8jkBxNOq/rx60Ga73F"
  "urdXCqM1tz5T2QHgoI6y0HjGuEbjymFQfCt1hclIvu7EzWn29p2oZJUj1Vv7vpNz"
  "tDy+gjC3uMYj7JGdoTg=";

static const char tkt2enckdcreppartb64[] =
  "eoHJMIHGoCMwIaADAgEQoRoEGFS29KeMuXZDeqcEud/gWHln/db7bje26aEcMBow"
  "GKADAgEAoREYDzE5NzAwMTAxMDAwMDAwWqIGAgScLHDdpAcDBQAAAAAApREYDzIw"
  "MDIxMjExMTM0MDU0WqYRGA8yMDAyMTIxMTEzNDEwNFqnERgPMjAwMjEyMTExMzU3"
  "MzRaqQ8bDUpPU0VGU1NPTi5PUkeqJjAkoAMCAQGhHTAbGwRob3N0GxNsYXR0ZS5q"
  "b3NlZnNzb24ub3Jn";

static const char tkt2ticketb64[] =
  "YYIBFDCCARCgAwIBBaEPGw1KT1NFRlNTT04uT1JHoiYwJKADAgEBoR0wGxsEaG9z"
  "dBsTbGF0dGUuam9zZWZzc29uLm9yZ6OBzzCBzKADAgEQoQMCAQKigb8EgbzEU6KF"
  "fSSQg4xxSxJBp2QBtaNGyzawROAGFsztZcY+gl5K2ki6xDT10kCYyfORXXXraoYI"
  "cwJl6EW8RGl4KKsZlZmNWuw0/mO4Gglga6sM06vQDs2TcSc8hWDJ4I1vU6/WlKtw"
  "zNj0Cw+6fqyDJIt6PmRpUe/yGZe6hSQkrqgQuBhpAHZF4/aoWqOmNufTdGa+5gHz"
  "qcEmQerWD8YhImeD+Xe5citg92XTPx2nHiNMBMmwgWJHf1TjddiwsQ==";

#define BUFSIZE 5000

void
test (Shishi * handle)
{
  Shishi_tkts *tktset;
  Shishi_tkts_hint hint;
  Shishi_tkt *t1, *t2, *t3;
  Shishi_asn1 tkt1asn1, tkt1asn2, tkt1asn3;
  Shishi_asn1 tkt2asn1, tkt2asn2, tkt2asn3;
  char buffer[BUFSIZE];
  char buffer2[BUFSIZE];
  char *buf;
  char *p, *q;
  size_t n;
  int res;

  /* shishi_tkts_default_file() */
  p = strdup (shishi_tkts_default_file (handle));
  if (debug)
    printf ("shishi_tkts_default_file () => `%s'.\n", p ? p : "<null>");
  if (p)
    success ("shishi_tkts_default_file() OK\n");
  else
    fail ("shishi_tkts_default_file() failed\n");

  /* shishi_tkts_default_file_set() */
  shishi_tkts_default_file_set (handle, "foo");
  q = strdup (shishi_tkts_default_file (handle));
  if (debug)
    printf ("shishi_tkts_default_file () => `%s'.\n", q ? q : "<null>");
  if (q && strcmp (q, "foo") == 0)
    success ("shishi_tkts_default_file_set() OK\n");
  else
    fail ("shishi_tkts_default_file_set() failed\n");
  free (q);

  /* shishi_tkts_default_file_set() */
  shishi_tkts_default_file_set (handle, NULL);
  q = strdup (shishi_tkts_default_file (handle));
  if (debug)
    printf ("shishi_tkts_default_file () => `%s'.\n", q ? q : "<null>");
  if (p && q && strcmp (p, q) == 0)
    success ("shishi_tkts_default_file_set() OK\n");
  else
    fail ("shishi_tkts_default_file_set() failed\n");
  free (q);
  free (p);

  /* shishi_tkts () */
  res = shishi_tkts (handle, &tktset);
  if (res == SHISHI_OK)
    success ("shishi_tkts() OK\n");
  else
    fail ("shishi_tkts() failed\n");

  /* shishi_tkts_size () */
  n = shishi_tkts_size (tktset);
  if (debug)
    printf ("shishi_tkts_size () => `%d'.\n", n);
  if (n == 0)
    success ("shishi_tkts_size() OK\n");
  else
    fail ("shishi_tkts_size() failed\n");

  /* shishi_tkts_nth () */
  t1 = shishi_tkts_nth (tktset, 0);
  if (t1 == NULL)
    success ("shishi_tkts_nth() OK\n");
  else
    fail ("shishi_tkts_nth() failed\n");

  /* shishi_tkts_nth () */
  t1 = shishi_tkts_nth (tktset, 42);
  if (t1 == NULL)
    success ("shishi_tkts_nth() OK\n");
  else
    fail ("shishi_tkts_nth() failed\n");

  /* shishi_tkts_add () */
  res = shishi_tkts_add (tktset, NULL);
  if (res == SHISHI_INVALID_TICKET)
    success ("shishi_tkts_add() OK\n");
  else
    fail ("shishi_tkts_add() failed\n");

  /* shishi_tkts_remove () */
  res = shishi_tkts_remove (tktset, 0);
  if (res == SHISHI_OK)
    success ("shishi_tkts_remove() OK\n");
  else
    fail ("shishi_tkts_remove() failed\n");

  /* shishi_tkts_remove () */
  res = shishi_tkts_remove (tktset, 42);
  if (res == SHISHI_OK)
    success ("shishi_tkts_remove() OK\n");
  else
    fail ("shishi_tkts_remove() failed\n");

  /* shishi_tkts_remove () */
  res = shishi_tkts_remove (NULL, 0);
  if (res == SHISHI_INVALID_TKTS)
    success ("shishi_tkts_remove() OK\n");
  else
    fail ("shishi_tkts_remove() failed\n");

  /* create ticket */
  n = BUFSIZE;
  if (!base64_decode (tkt1ticketb64, strlen (tkt1ticketb64), buffer, &n))
    fail ("base64_decode() failed\n");
  tkt1asn1 = shishi_der2asn1_ticket (handle, buffer, n);
  if (!tkt1asn1)
    fail ("shishi_der2asn1_ticket() failed\n");

  n = BUFSIZE;
  if (!base64_decode (tkt1enckdcreppartb64, strlen (tkt1enckdcreppartb64),
		      buffer, &n))
    fail ("base64_decode() failed\n");
  tkt1asn2 = shishi_der2asn1_encasreppart (handle, buffer, n);
  if (!tkt1asn2)
    fail ("shishi_der2asn1_encasreppart() failed\n");

  n = BUFSIZE;
  if (!base64_decode (tkt1kdcrepb64, strlen (tkt1kdcrepb64), buffer, &n))
    fail ("base64_decode() failed\n");
  tkt1asn3 = shishi_der2asn1_asrep (handle, buffer, n);
  if (!tkt1asn3)
    fail ("shishi_der2asn1_asrep() failed\n");

  /* shishi_tkts_new() */
  res = shishi_tkts_new (tktset, tkt1asn1, tkt1asn2, tkt1asn3);
  if (res == SHISHI_OK)
    success ("shishi_tkts_new() OK\n");
  else
    fail ("shishi_tkts_new() failed\n");

  /* shishi_tkts_size () */
  n = shishi_tkts_size (tktset);
  if (debug)
    printf ("shishi_tkts_size () => `%d'.\n", n);
  if (n == 1)
    success ("shishi_tkts_size() OK\n");
  else
    fail ("shishi_tkts_size() failed\n");

  /* shishi_tkts_nth () */
  t1 = shishi_tkts_nth (tktset, 0);
  if (debug)
    {
      shishi_tkt_pretty_print (t1, stdout);
      printf ("t1=%p\n", t1);
    }
  if (t1)
    success ("shishi_tkts_nth() OK\n");
  else
    fail ("shishi_tkts_nth() failed\n");

  /* shishi_tkts_remove () */
  res = shishi_tkts_remove (tktset, 0);
  if (res == SHISHI_OK)
    success ("shishi_tkts_remove() OK\n");
  else
    fail ("shishi_tkts_remove() failed\n");

  /* shishi_tkts_size () */
  n = shishi_tkts_size (tktset);
  if (debug)
    printf ("shishi_tkts_size () => `%d'.\n", n);
  if (n == 0)
    success ("shishi_tkts_size() OK\n");
  else
    fail ("shishi_tkts_size() failed\n");

  /* shishi_tkts_nth () */
  t2 = shishi_tkts_nth (tktset, 0);
  if (t2 == NULL)
    success ("shishi_tkts_nth() OK\n");
  else
    fail ("shishi_tkts_nth() failed\n");

  /* shishi_tkts_add () */
  res = shishi_tkts_add (tktset, t1);
  if (res == SHISHI_OK)
    success ("shishi_tkts_add() OK\n");
  else
    fail ("shishi_tkts_add() failed\n");

  /* shishi_tkts_size () */
  n = shishi_tkts_size (tktset);
  if (debug)
    printf ("shishi_tkts_size () => `%d'.\n", n);
  if (n == 1)
    success ("shishi_tkts_size() OK\n");
  else
    fail ("shishi_tkts_size() failed\n");

  /* create ticket */
  n = BUFSIZE;
  if (!base64_decode (tkt2ticketb64, strlen (tkt2ticketb64), buffer, &n))
    fail ("base64_decode() failed\n");
  tkt2asn1 = shishi_der2asn1_ticket (handle, buffer, n);
  if (!tkt2asn1)
    fail ("shishi_der2asn1_ticket() failed\n");

  n = BUFSIZE;
  if (!base64_decode (tkt2enckdcreppartb64, strlen (tkt2enckdcreppartb64),
		      buffer, &n))
    fail ("base64_decode() failed\n");
  tkt2asn2 = shishi_der2asn1_enctgsreppart (handle, buffer, n);
  if (!tkt2asn2)
    fail ("shishi_der2asn1_enctgsreppart() failed\n");

  n = BUFSIZE;
  if (!base64_decode (tkt2kdcrepb64, strlen (tkt2kdcrepb64), buffer, &n))
    fail ("base64_decode() failed\n");
  tkt2asn3 = shishi_der2asn1_tgsrep (handle, buffer, n);
  if (!tkt2asn3)
    fail ("shishi_der2asn1_kdcrep() failed\n");

  /* shishi_tkts_new() */
  res = shishi_tkts_new (tktset, tkt2asn1, tkt2asn2, tkt2asn3);
  if (res == SHISHI_OK)
    success ("shishi_tkts_new() OK\n");
  else
    fail ("shishi_tkts_new() failed\n");

  /* shishi_tkts_size () */
  n = shishi_tkts_size (tktset);
  if (debug)
    printf ("shishi_tkts_size () => `%d'.\n", n);
  if (n == 2)
    success ("shishi_tkts_size() OK\n");
  else
    fail ("shishi_tkts_size() failed\n");

  /* shishi_tkts_nth () */
  t2 = shishi_tkts_nth (tktset, 1);
  if (debug)
    {
      shishi_tkt_pretty_print (t2, stdout);
      printf ("t2=%p\n", t2);
    }
  if (t2)
    success ("shishi_tkts_nth() OK\n");
  else
    fail ("shishi_tkts_nth() failed\n");

  /* shishi_tkts_find () */
  memset (&hint, 0, sizeof (hint));
  hint.server = (char *) "host/latte.josefsson.org";
  hint.flags = SHISHI_TKTSHINTFLAGS_ACCEPT_EXPIRED;
  t3 = shishi_tkts_find (tktset, &hint);
  if (debug)
    printf ("t3=%p\n", t3);
  if (t3 == t2)
    success ("shishi_tkts_find() for server OK\n");
  else
    fail ("shishi_tkts_find() for server failed\n");

  /* shishi_tkts_find () */
  memset (&hint, 0, sizeof (hint));
  hint.server = (char *) "krbtgt/JOSEFSSON.ORG";
  hint.flags = SHISHI_TKTSHINTFLAGS_ACCEPT_EXPIRED;
  t3 = shishi_tkts_find (tktset, &hint);
  if (t3 == t1)
    success ("shishi_tkts_find() for server OK\n");
  else
    fail ("shishi_tkts_find() for server failed\n");

  /* shishi_tkts_find () */
  memset (&hint, 0, sizeof (hint));
  hint.client = (char *) "jas";
  hint.flags = SHISHI_TKTSHINTFLAGS_ACCEPT_EXPIRED;
  t3 = shishi_tkts_find (tktset, &hint);
  if (debug)
    printf ("t3=%p\n", t3);
  if (t3 == t1)
    success ("shishi_tkts_find() for client OK\n");
  else
    fail ("shishi_tkts_find() for client failed\n");

  /* shishi_tkts_find () */
  memset (&hint, 0, sizeof (hint));
  hint.client = (char *) "jas";
  t3 = shishi_tkts_find (tktset, &hint);
  if (debug)
    printf ("t3=%p\n", t3);
  if (t3 == NULL)
    success ("shishi_tkts_find() for client2 OK\n");
  else
    fail ("shishi_tkts_find() for client2 failed\n");

  res = shishi_tkts_to_file (tktset, "tktset.tmp");
  if (res == SHISHI_OK)
    success ("shishi_tkts_to_file() OK\n");
  else
    fail ("shishi_tkts_to_file() failed\n");

  /* shishi_tkts_add () */
  res = shishi_tkts_add (tktset, t2);
  if (res == SHISHI_OK)
    success ("shishi_tkts_add() OK\n");
  else
    fail ("shishi_tkts_add() failed\n");

  /* shishi_tkts_add () */
  res = shishi_tkts_add (tktset, t1);
  if (res == SHISHI_OK)
    success ("shishi_tkts_add() OK\n");
  else
    fail ("shishi_tkts_add() failed\n");

  /* shishi_tkts_remove () */
  res = shishi_tkts_remove (tktset, 1);
  if (res == SHISHI_OK)
    success ("shishi_tkts_remove() OK\n");
  else
    fail ("shishi_tkts_remove() failed\n");

  /* shishi_tkts_remove () */
  res = shishi_tkts_remove (tktset, 1);
  if (res == SHISHI_OK)
    success ("shishi_tkts_remove() OK\n");
  else
    fail ("shishi_tkts_remove() failed\n");

  memset (&hint, 0, sizeof (hint));
  hint.server = (char *) "host/latte.josefsson.org";
  hint.flags = SHISHI_TKTSHINTFLAGS_ACCEPT_EXPIRED;
  t3 = shishi_tkts_find (tktset, &hint);
  if (t3 == NULL)
    success ("shishi_tkts_find() for server OK\n");
  else
    fail ("shishi_tkts_find() for server failed\n");

  memset (&hint, 0, sizeof (hint));
  hint.server = (char *) "krbtgt/JOSEFSSON.ORG";
  hint.flags = SHISHI_TKTSHINTFLAGS_ACCEPT_EXPIRED;
  t3 = shishi_tkts_find (tktset, &hint);
  if (t3 == t1)
    success ("shishi_tkts_find() for server OK\n");
  else
    fail ("shishi_tkts_find() for server failed\n");

  /* shishi_tkts_remove () */
  res = shishi_tkts_remove (tktset, 0);
  if (res == SHISHI_OK)
    success ("shishi_tkts_remove() OK\n");
  else
    fail ("shishi_tkts_remove() failed\n");

  /* shishi_tkts_remove () */
  res = shishi_tkts_remove (tktset, 0);
  if (res == SHISHI_OK)
    success ("shishi_tkts_remove() OK\n");
  else
    fail ("shishi_tkts_remove() failed\n");

  /* shishi_tkts_size () */
  n = shishi_tkts_size (tktset);
  if (debug)
    printf ("shishi_tkts_size () => `%d'.\n", n);
  if (n == 0)
    success ("shishi_tkts_size() OK\n");
  else
    fail ("shishi_tkts_size() failed\n");

  /* shishi_tkts_done () */
  shishi_tkts_done (&tktset);
  success ("shishi_tkts_done() OK\n");

  shishi_tkt_done (t1);
  success ("shishi_tkt_done (t1) OK\n");
  shishi_tkt_done (t2);
  success ("shishi_tkt_done (t2) OK\n");

  /* shishi_tkts_done () */
  shishi_tkts_done (NULL);
  success ("shishi_tkts_done() OK\n");

  /* shishi_tkts () */
  res = shishi_tkts (handle, &tktset);
  if (res == SHISHI_OK)
    success ("shishi_tkts() OK\n");
  else
    fail ("shishi_tkts() failed\n");

  /* shishi_tkts_from_file () */
  res = shishi_tkts_from_file (tktset, "tktset.tmp");
  if (res == SHISHI_OK)
    success ("shishi_tkts_from_file() OK\n");
  else
    fail ("shishi_tkts_from_file() failed\n");

  /* shishi_tkts_size () */
  n = shishi_tkts_size (tktset);
  if (debug)
    printf ("shishi_tkts_size () => `%d'.\n", n);
  if (n == 2)
    success ("shishi_tkts_size() OK\n");
  else
    fail ("shishi_tkts_size() failed\n");

  /* shishi_tkts_nth () */
  t1 = shishi_tkts_nth (tktset, 0);
  if (debug)
    shishi_tkt_pretty_print (t1, stdout);
  if (t1)
    success ("shishi_tkts_nth() OK\n");
  else
    fail ("shishi_tkts_nth() failed\n");

  /* shishi_tkts_nth () */
  t2 = shishi_tkts_nth (tktset, 1);
  if (debug)
    shishi_tkt_pretty_print (t2, stdout);
  if (t2)
    success ("shishi_tkts_nth() OK\n");
  else
    fail ("shishi_tkts_nth() failed\n");

  /* DER encode and compare tkt1 ticket */
  res = shishi_asn1_to_der (handle, shishi_tkt_ticket (t1), &buf, &n);
  if (res == SHISHI_OK)
    success ("shishi_asn1_to_der() OK\n");
  else
    n = 0, fail ("shishi_asn1_to_der() failed\n");

  base64_encode (buf, n, buffer2, BUFSIZE);
  free (buf);
  if (strlen (buffer2) == strlen (tkt1ticketb64) &&
      memcmp (buffer2, tkt1ticketb64, strlen (tkt1ticketb64)) == 0)
    success ("Ticket read OK\n");
  else
    fail ("Ticket read failed\n");

  /* DER encode and compare tkt1 enckdcreppart */
  res = shishi_asn1_to_der (handle, shishi_tkt_enckdcreppart (t1), &buf, &n);
  if (res == SHISHI_OK)
    success ("shishi_asn1_to_der() OK\n");
  else
    n = 0, fail ("shishi_asn1_to_der() failed\n");

  base64_encode (buf, n, buffer2, BUFSIZE);
  free (buf);
  if (strlen (buffer2) == strlen (tkt1enckdcreppartb64) &&
      memcmp (buffer2, tkt1enckdcreppartb64,
	      strlen (tkt1enckdcreppartb64)) == 0)
    success ("EncKDCRepPart read OK\n");
  else
    fail ("EncKDCRepPart read failed\n");

  /* DER encode and compare tkt1 kdcrep */
  res = shishi_asn1_to_der (handle, shishi_tkt_kdcrep (t1), &buf, &n);
  if (res == SHISHI_OK)
    success ("shishi_asn1_to_der() OK\n");
  else
    n = 0, fail ("shishi_asn1_to_der() failed\n");

  base64_encode (buf, n, buffer2, BUFSIZE);
  free (buf);
  if (strlen (buffer2) == strlen (tkt1kdcrepb64) &&
      memcmp (buffer2, tkt1kdcrepb64, strlen (tkt1kdcrepb64)) == 0)
    success ("KDC-REP read OK\n");
  else
    fail ("KDC-REP read failed\n");

  /* DER encode and compare tkt2 ticket */
  res = shishi_asn1_to_der (handle, shishi_tkt_ticket (t2), &buf, &n);
  if (res == SHISHI_OK)
    success ("shishi_asn1_to_der() OK\n");
  else
    n = 0, fail ("shishi_asn1_to_der() failed\n");

  base64_encode (buf, n, buffer2, BUFSIZE);
  free (buf);
  if (strlen (buffer2) == strlen (tkt2ticketb64) &&
      memcmp (buffer2, tkt2ticketb64, strlen (tkt2ticketb64)) == 0)
    success ("Ticket 2 read OK\n");
  else
    fail ("Ticket 2 read failed\n");

  /* DER encode and compare tkt2 enckdcreppart */
  res = shishi_asn1_to_der (handle, shishi_tkt_enckdcreppart (t2), &buf, &n);
  if (res == SHISHI_OK)
    success ("shishi_asn1_to_der() OK\n");
  else
    n = 0, fail ("shishi_asn1_to_der() failed\n");

  base64_encode (buf, n, buffer2, BUFSIZE);
  free (buf);
  if (strlen (buffer2) == strlen (tkt2enckdcreppartb64) &&
      memcmp (buffer2, tkt2enckdcreppartb64,
	      strlen (tkt2enckdcreppartb64)) == 0)
    success ("EncKDCRepPart 2 read OK\n");
  else
    fail ("EncKDCRepPart 2 read failed\n");

  /* DER encode and compare tkt2 kdcrep */
  res = shishi_asn1_to_der (handle, shishi_tkt_kdcrep (t2), &buf, &n);
  if (res == SHISHI_OK)
    success ("shishi_asn1_to_der() OK\n");
  else
    n = 0, fail ("shishi_asn1_to_der() failed\n");

  base64_encode (buf, n, buffer2, BUFSIZE);
  free (buf);
  if (strlen (buffer2) == strlen (tkt2kdcrepb64) &&
      memcmp (buffer2, tkt2kdcrepb64, strlen (tkt2kdcrepb64)) == 0)
    success ("KDC-REP 2 read OK\n");
  else
    fail ("KDC-REP 2 read failed\n");

  res = unlink ("tktset.tmp");
  if (res == 0)
    success ("unlink() OK\n");
  else
    fail ("unlink() failed\n");

  shishi_tkt_done (t1);
  success ("shishi_tkt_done (t1) OK\n");
  shishi_tkt_done (t2);
  success ("shishi_tkt_done (t2) OK\n");

  /* shishi_tkts_done () */
  shishi_tkts_done (&tktset);
  success ("shishi_tkts_done() OK\n");

  shishi_asn1_done (handle, tkt1asn1);
  shishi_asn1_done (handle, tkt1asn2);
  shishi_asn1_done (handle, tkt1asn3);
  shishi_asn1_done (handle, tkt2asn1);
  shishi_asn1_done (handle, tkt2asn2);
  shishi_asn1_done (handle, tkt2asn3);
}
