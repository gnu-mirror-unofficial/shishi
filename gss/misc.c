/* misc.c	Implementation of GSS-API Miscellaneous functions.
 * Copyright (C) 2003  Simon Josefsson
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

OM_uint32
gss_add_oid_set_member (OM_uint32 * minor_status,
			const gss_OID member_oid, gss_OID_set * oid_set)
{
}

OM_uint32
gss_create_empty_oid_set (OM_uint32 * minor_status, gss_OID_set * oid_set)
{
}

OM_uint32
gss_display_status (OM_uint32 * minor_status,
		    OM_uint32 status_value,
		    int status_type,
		    const gss_OID mech_type,
		    OM_uint32 * message_context, gss_buffer_t status_string)
{
}

OM_uint32
gss_indicate_mechs (OM_uint32 * minor_status, gss_OID_set * mech_set)
{
}

OM_uint32
gss_release_buffer (OM_uint32 * minor_status, gss_buffer_t buffer)
{
}

OM_uint32
gss_release_oid_set (OM_uint32 * minor_status, gss_OID_set * set)
{
}

OM_uint32
gss_test_oid_set_member (OM_uint32 * minor_status,
			 const gss_OID member,
			 const gss_OID_set set, int *present)
{
}
