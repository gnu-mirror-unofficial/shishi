/* ap.c	AP functions
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

#define APOPTION_RESERVED "reserved"
#define APOPTION_USE_SESSION_KEY "use-session-key"
#define APOPTION_MUTUAL_REQUIRED "mutual-required"
#define APOPTION_UNKNOWN "unknown"

char *
shishi_ap_option2string (int option)
{
  char *str;

  switch (option)
    {
    case SHISHI_APOPTIONS_RESERVED:
      str = APOPTION_RESERVED;
      break;

    case SHISHI_APOPTIONS_USE_SESSION_KEY:
      str = APOPTION_USE_SESSION_KEY;
      break;

    case SHISHI_APOPTIONS_MUTUAL_REQUIRED:
      str = APOPTION_MUTUAL_REQUIRED;
      break;

    default:
      str = APOPTION_UNKNOWN;
      break;
    }

  return str;
}

int
shishi_ap_string2option (char *str)
{
  int option;

  if (strcasecmp(str, APOPTION_RESERVED) == 0)
    option = SHISHI_APOPTIONS_RESERVED;
  else if (strcasecmp(str, APOPTION_USE_SESSION_KEY) == 0)
    option = SHISHI_APOPTIONS_USE_SESSION_KEY;
  else if (strcasecmp(str, APOPTION_MUTUAL_REQUIRED) == 0)
    option = SHISHI_APOPTIONS_MUTUAL_REQUIRED;
  else
    option = strtol(str, (char **)NULL, 0);

  return option;
}

