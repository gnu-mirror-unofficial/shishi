/* name.c	Implementation of GSS-API Name Manipulation functions.
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

/**
 * gss_import_name:
 * @minor_status: Mechanism specific status code
 * @input_name_buffer: buffer containing contiguous string name to convert
 * @input_name_type: Optional Object ID specifying type of printable
 *   name.  Applications may specify either GSS_C_NO_OID to use a
 *   mechanism-specific default printable syntax, or an OID recognized
 *   by the GSS-API implementation to name a specific namespace.
 * @output_name: returned name in internal form.  Storage associated
 *   with this name must be freed by the application after use with a call
 *   to gss_release_name().
 *
 * Convert a contiguous string name to internal form.  In general, the
 * internal name returned (via the <output_name> parameter) will not
 * be an MN; the exception to this is if the <input_name_type>
 * indicates that the contiguous string provided via the
 * <input_name_buffer> parameter is of type GSS_C_NT_EXPORT_NAME, in
 * which case the returned internal name will be an MN for the
 * mechanism that exported the name.
 *
 * Return value: Returns GSS_S_COMPLETE for successful completion,
 *   GSS_S_BAD_NAMETYPE when the input_name_type was unrecognized,
 *   GSS_S_BAD_NAME when the input_name parameter could not be
 *   interpreted as a name of the specified type, and GSS_S_BAD_MECH
 *   when the input name-type was GSS_C_NT_EXPORT_NAME, but the
 *   mechanism contained within the input-name is not supported.
 **/
OM_uint32
gss_import_name (OM_uint32 * minor_status,
		 const gss_buffer_t input_name_buffer,
		 const gss_OID input_name_type, gss_name_t * output_name)
{
  if (!output_name)
    return GSS_S_FAILURE;

  *output_name = malloc (sizeof (*output_name));
  if (!*output_name)
    return GSS_S_FAILURE;

  (*output_name)->length = input_name_buffer->length;
  (*output_name)->value = malloc (input_name_buffer->length);
  if (!(*output_name)->value)
    return GSS_S_FAILURE;

  memcpy ((*output_name)->value, input_name_buffer->value,
	  input_name_buffer->length);

  if (minor_status)
    *minor_status = 0;
  return GSS_S_COMPLETE;
}

/**
 * gss_display_name:
 * @minor_status: Mechanism specific status code.
 * @input_name: Name to be displayed
 * @output_name_buffer: Buffer to receive textual name string.  The
 *   application must free storage associated with this name after use
 *   with a call to gss_release_buffer().
 * @output_name_type: Optional type of the returned name.  The
 *   returned gss_OID will be a pointer into static storage, and should
 *   be treated as read-only by the caller (in particular, the
 *   application should not attempt to free it). Specify NULL if not
 *   required.
 *
 * Allows an application to obtain a textual representation of an
 * opaque internal-form name for display purposes.  The syntax of a
 * printable name is defined by the GSS-API implementation.
 *
 * If input_name denotes an anonymous principal, the implementation
 * should return the gss_OID value GSS_C_NT_ANONYMOUS as the
 * output_name_type, and a textual name that is syntactically distinct
 * from all valid supported printable names in output_name_buffer.
 *
 * If input_name was created by a call to gss_import_name, specifying
 * GSS_C_NO_OID as the name-type, implementations that employ lazy
 * conversion between name types may return GSS_C_NO_OID via the
 * output_name_type parameter.
 *
 * Return value: Returns GSS_S_COMPLETE for successful completion,
 *   GSS_S_BAD_NAME when input_name was ill-formed.
 **/
OM_uint32
gss_display_name (OM_uint32 * minor_status,
		  const gss_name_t input_name,
		  gss_buffer_t output_name_buffer, gss_OID * output_name_type)
{
  if (!input_name)
    return GSS_S_BAD_NAME;

  output_name_buffer->length = input_name->length;
  output_name_buffer->value = malloc (input_name->length);
  if (!output_name_buffer->value)
    return GSS_S_FAILURE;
  memcpy (output_name_buffer->value, input_name->value, input_name->length);

  if (output_name_type)
    *output_name_type = &input_name->type;

  if (minor_status)
    *minor_status = 0;
  return GSS_S_COMPLETE;
}

OM_uint32
gss_compare_name (OM_uint32 * minor_status,
		  const gss_name_t name1,
		  const gss_name_t name2, int *name_equal)
{
  return GSS_S_FAILURE;
}

OM_uint32
gss_release_name (OM_uint32 * minor_status, gss_name_t * input_name)
{
  return GSS_S_FAILURE;
}

OM_uint32
gss_inquire_names_for_mech (OM_uint32 * minor_status,
			    const gss_OID mechanism, gss_OID_set * name_types)
{
  return GSS_S_FAILURE;
}

OM_uint32
gss_inquire_mechs_for_name (OM_uint32 * minor_status,
			    const gss_name_t input_name,
			    gss_OID_set * mech_types)
{
  return GSS_S_FAILURE;
}

OM_uint32
gss_export_name (OM_uint32 * minor_status,
		 const gss_name_t input_name, gss_buffer_t exported_name)
{
  return GSS_S_FAILURE;
}

OM_uint32
gss_canonicalize_name (OM_uint32 * minor_status,
		       const gss_name_t input_name,
		       const gss_OID mech_type, gss_name_t * output_name)
{
  return GSS_S_FAILURE;
}

OM_uint32
gss_duplicate_name (OM_uint32 * minor_status,
		    const gss_name_t src_name, gss_name_t * dest_name)
{
  return GSS_S_FAILURE;
}
