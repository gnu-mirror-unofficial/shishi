/* tkts.c	Shishi ticketset self tests.
 * Copyright (C) 2002, 2003  Simon Josefsson
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

int
main (int argc, char *argv[])
{
  Shishi *handle;
  Shishi_tkts *tktset;
  Shishi_tkt *t1, *t2, *t3;
  ASN1_TYPE n1, n2, n3;
  char buffer[BUFSIZ];
  char buffer2[BUFSIZ];
  char *p, *q;
  int n, res;

  do
    if (strcmp (argv[argc - 1], "-v") == 0 ||
	strcmp (argv[argc - 1], "--verbose") == 0)
      verbose = 1;
    else if (strcmp (argv[argc - 1], "-d") == 0 ||
	     strcmp (argv[argc - 1], "--debug") == 0)
      debug = 1;
    else if (strcmp (argv[argc - 1], "-b") == 0 ||
	     strcmp (argv[argc - 1], "--break-on-error") == 0)
      break_on_error = 1;
    else if (strcmp (argv[argc - 1], "-h") == 0 ||
	     strcmp (argv[argc - 1], "-?") == 0 ||
	     strcmp (argv[argc - 1], "--help") == 0)
      {
	printf ("Usage: %s [-vdbh?] [--verbose] [--debug] "
		"[--break-on-error] [--help]\n", argv[0]);
	return 1;
      }
  while (argc-- > 1);

  handle = shishi ();
  if (handle == NULL)
    {
      fail ("Could not initialize shishi\n");
      return 1;
    }

  if (debug)
    shishi_cfg (handle, strdup ("verbose"));

  /* shishi_tkts_default_file() */
  p = shishi_tkts_default_file (handle);
  if (debug)
    printf ("shishi_tkts_default_file () => `%s'.\n", p ? p : "<null>");
  if (p)
    success ("shishi_tkts_default_file() OK\n");
  else
    fail ("shishi_tkts_default_file() failed\n");
  p = strdup (p);

  /* shishi_tkts_default_file_set() */
  shishi_tkts_default_file_set (handle, "foo");
  q = shishi_tkts_default_file (handle);
  if (debug)
    printf ("shishi_tkts_default_file () => `%s'.\n", q ? q : "<null>");
  if (q && strcmp (q, "foo") == 0)
    success ("shishi_tkts_default_file_set() OK\n");
  else
    fail ("shishi_tkts_default_file_set() failed\n");

  /* shishi_tkts_default_file_set() */
  shishi_tkts_default_file_set (handle, NULL);
  q = shishi_tkts_default_file (handle);
  if (debug)
    printf ("shishi_tkts_default_file () => `%s'.\n", q ? q : "<null>");
  if (p && q && strcmp (p, q) == 0)
    success ("shishi_tkts_default_file_set() OK\n");
  else
    fail ("shishi_tkts_default_file_set() failed\n");
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

  /* shishi_tkts_get () */
  t1 = shishi_tkts_get (tktset, 0);
  if (t1 == NULL)
    success ("shishi_tkts_get() OK\n");
  else
    fail ("shishi_tkts_get() failed\n");

  /* shishi_tkts_get () */
  t1 = shishi_tkts_get (tktset, 42);
  if (t1 == NULL)
    success ("shishi_tkts_get() OK\n");
  else
    fail ("shishi_tkts_get() failed\n");

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
  n = shishi_from_base64 (buffer, tkt1ticketb64);
  if (n == -1)
    die ("shishi_from_base64() failed\n");
  n1 = shishi_d2a_ticket (handle, buffer, n);
  if (n1 == ASN1_TYPE_EMPTY)
    die ("shishi_d2a_ticket() failed\n");

  n = shishi_from_base64 (buffer, tkt1enckdcreppartb64);
  if (n == -1)
    die ("shishi_from_base64() failed\n");
  n2 = shishi_d2a_encasreppart (handle, buffer, n);
  if (n2 == ASN1_TYPE_EMPTY)
    die ("shishi_d2a_encasreppart() failed\n");

  n = shishi_from_base64 (buffer, tkt1kdcrepb64);
  if (n == -1)
    die ("shishi_from_base64() failed\n");
  n3 = shishi_d2a_asrep (handle, buffer, n);
  if (n3 == ASN1_TYPE_EMPTY)
    die ("shishi_d2a_asrep() failed\n");

  /* shishi_tkts_new() */
  res = shishi_tkts_new (tktset, n1, n2, n3);
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

  /* shishi_tkts_get () */
  t1 = shishi_tkts_get (tktset, 0);
  if (debug)
    {
      shishi_tkt_pretty_print (t1, stdout);
      printf ("t1=%p\n", t1);
    }
  if (t1)
    success ("shishi_tkts_get() OK\n");
  else
    fail ("shishi_tkts_get() failed\n");

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

  /* shishi_tkts_get () */
  t2 = shishi_tkts_get (tktset, 0);
  if (t2 == NULL)
    success ("shishi_tkts_get() OK\n");
  else
    fail ("shishi_tkts_get() failed\n");

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
  n = shishi_from_base64 (buffer, tkt2ticketb64);
  if (n == -1)
    die ("shishi_from_base64() failed\n");
  n1 = shishi_d2a_ticket (handle, buffer, n);
  if (n1 == ASN1_TYPE_EMPTY)
    die ("shishi_d2a_ticket() failed\n");

  n = shishi_from_base64 (buffer, tkt2enckdcreppartb64);
  if (n == -1)
    die ("shishi_from_base64() failed\n");
  n2 = shishi_d2a_enctgsreppart (handle, buffer, n);
  if (n2 == ASN1_TYPE_EMPTY)
    die ("shishi_d2a_enctgsreppart() failed\n");

  n = shishi_from_base64 (buffer, tkt2kdcrepb64);
  if (n == -1)
    die ("shishi_from_base64() failed\n");
  n3 = shishi_d2a_tgsrep (handle, buffer, n);
  if (n3 == ASN1_TYPE_EMPTY)
    die ("shishi_d2a_kdcrep() failed\n");

  /* shishi_tkts_new() */
  res = shishi_tkts_new (tktset, n1, n2, n3);
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

  /* shishi_tkts_get () */
  t2 = shishi_tkts_get (tktset, 1);
  if (debug)
    {
      shishi_tkt_pretty_print (t2, stdout);
      printf ("t2=%p\n", t2);
    }
  if (t2)
    success ("shishi_tkts_get() OK\n");
  else
    fail ("shishi_tkts_get() failed\n");

  /* shishi_tkts_find_for_server_all () */
  t3 = shishi_tkts_find_for_server_all (tktset, "host/latte.josefsson.org");
  if (debug)
    printf ("t3=%p\n", t3);
  if (t3 == t2)
    success ("shishi_tkts_find_ticket_for_server() OK\n");
  else
    fail ("shishi_tkts_find_ticket_for_server() failed\n");

  /* shishi_tkts_find_for_server_all () */
  t3 = shishi_tkts_find_for_server_all (tktset, "krbtgt/JOSEFSSON.ORG");
  if (t3 == t1)
    success ("shishi_tkts_find_ticket_for_server() OK\n");
  else
    fail ("shishi_tkts_find_ticket_for_server() failed\n");

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

  t3 = shishi_tkts_find_for_server_all (tktset, "host/latte.josefsson.org");
  if (t3 == NULL)
    success ("shishi_tkts_find_ticket_for_server() OK\n");
  else
    fail ("shishi_tkts_find_ticket_for_server() failed\n");

  t3 = shishi_tkts_find_for_server_all (tktset, "krbtgt/JOSEFSSON.ORG");
  if (t3 == t1)
    success ("shishi_tkts_find_ticket_for_server() OK\n");
  else
    fail ("shishi_tkts_find_ticket_for_server() failed\n");

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
    success ("shishi_tkts_to_file() OK\n");
  else
    fail ("shishi_tkts_to_file() failed\n");

  /* shishi_tkts_size () */
  n = shishi_tkts_size (tktset);
  if (debug)
    printf ("shishi_tkts_size () => `%d'.\n", n);
  if (n == 2)
    success ("shishi_tkts_size() OK\n");
  else
    fail ("shishi_tkts_size() failed\n");

  /* shishi_tkts_get () */
  t1 = shishi_tkts_get (tktset, 0);
  if (debug)
    shishi_tkt_pretty_print (t1, stdout);
  if (t1)
    success ("shishi_tkts_get() OK\n");
  else
    fail ("shishi_tkts_get() failed\n");

  /* shishi_tkts_get () */
  t2 = shishi_tkts_get (tktset, 1);
  if (debug)
    shishi_tkt_pretty_print (t2, stdout);
  if (t2)
    success ("shishi_tkts_get() OK\n");
  else
    fail ("shishi_tkts_get() failed\n");

  /* DER encode and compare tkt1 ticket */
  res = shishi_a2d (handle, shishi_tkt_ticket (t1), buffer, &n);
  if (res == SHISHI_OK)
    success ("shishi_a2d() OK\n");
  else
    n = 0, fail ("shishi_a2d() failed\n");

  shishi_to_base64 (buffer2, buffer, n, BUFSIZ);
  if (strlen (buffer2) == strlen (tkt1ticketb64) &&
      memcmp (buffer2, tkt1ticketb64, strlen (tkt1ticketb64)) == 0)
    success ("Ticket read OK\n");
  else
    fail ("Ticket read failed\n");

  /* DER encode and compare tkt1 enckdcreppart */
  res = shishi_a2d (handle, shishi_tkt_enckdcreppart (t1), buffer, &n);
  if (res == SHISHI_OK)
    success ("shishi_a2d() OK\n");
  else
    n = 0, fail ("shishi_a2d() failed\n");

  shishi_to_base64 (buffer2, buffer, n, BUFSIZ);
  if (strlen (buffer2) == strlen (tkt1enckdcreppartb64) &&
      memcmp (buffer2, tkt1enckdcreppartb64,
	      strlen (tkt1enckdcreppartb64)) == 0)
    success ("EncKDCRepPart read OK\n");
  else
    fail ("EncKDCRepPart read failed\n");

  /* DER encode and compare tkt1 kdcrep */
  res = shishi_a2d (handle, shishi_tkt_kdcrep (t1), buffer, &n);
  if (res == SHISHI_OK)
    success ("shishi_a2d() OK\n");
  else
    n = 0, fail ("shishi_a2d() failed\n");

  shishi_to_base64 (buffer2, buffer, n, BUFSIZ);
  if (strlen (buffer2) == strlen (tkt1kdcrepb64) &&
      memcmp (buffer2, tkt1kdcrepb64, strlen (tkt1kdcrepb64)) == 0)
    success ("KDC-REP read OK\n");
  else
    fail ("KDC-REP read failed\n");

  /* DER encode and compare tkt2 ticket */
  res = shishi_a2d (handle, shishi_tkt_ticket (t2), buffer, &n);
  if (res == SHISHI_OK)
    success ("shishi_a2d() OK\n");
  else
    n = 0, fail ("shishi_a2d() failed\n");

  shishi_to_base64 (buffer2, buffer, n, BUFSIZ);
  if (strlen (buffer2) == strlen (tkt2ticketb64) &&
      memcmp (buffer2, tkt2ticketb64, strlen (tkt2ticketb64)) == 0)
    success ("Ticket 2 read OK\n");
  else
    fail ("Ticket 2 read failed\n");

  /* DER encode and compare tkt2 enckdcreppart */
  res = shishi_a2d (handle, shishi_tkt_enckdcreppart (t2), buffer, &n);
  if (res == SHISHI_OK)
    success ("shishi_a2d() OK\n");
  else
    n = 0, fail ("shishi_a2d() failed\n");

  shishi_to_base64 (buffer2, buffer, n, BUFSIZ);
  if (strlen (buffer2) == strlen (tkt2enckdcreppartb64) &&
      memcmp (buffer2, tkt2enckdcreppartb64,
	      strlen (tkt2enckdcreppartb64)) == 0)
    success ("EncKDCRepPart 2 read OK\n");
  else
    fail ("EncKDCRepPart 2 read failed\n");

  /* DER encode and compare tkt2 kdcrep */
  res = shishi_a2d (handle, shishi_tkt_kdcrep (t2), buffer, &n);
  if (res == SHISHI_OK)
    success ("shishi_a2d() OK\n");
  else
    n = 0, fail ("shishi_a2d() failed\n");

  shishi_to_base64 (buffer2, buffer, n, BUFSIZ);
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

  shishi_done (handle);

  if (verbose)
    printf ("Ticket set self tests done with %d errors\n", error_count);

  return error_count ? 1 : 0;
}
