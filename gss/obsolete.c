/* obsolete.c	Obsolete GSS-API v1 compatibility mappings.
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

#define WARN(msg) fprintf(stderr, "warning: " msg "\n");

OM_uint32
gss_sign (OM_uint32 * minor_status,
	  gss_ctx_id_t context_handle,
	  int qop_req,
	  gss_buffer_t message_buffer, gss_buffer_t message_token)
{
  WARN ("gss_sign() is obsolete, use gss_get_mic() instead.");

  return gss_get_mic (minor_status, context_handle,
		      qop_req, message_buffer, message_token);
}


OM_uint32
gss_verify (OM_uint32 * minor_status,
	    gss_ctx_id_t context_handle,
	    gss_buffer_t message_buffer,
	    gss_buffer_t token_buffer, int *qop_state)
{
  WARN ("gss_verify() is obsolete, use gss_verify_mic() instead.");

  return gss_verify_mic (minor_status, context_handle, message_buffer,
			 token_buffer, qop_state);
}

OM_uint32
gss_seal (OM_uint32 * minor_status,
	  gss_ctx_id_t context_handle,
	  int conf_req_flag,
	  int qop_req,
	  gss_buffer_t input_message_buffer,
	  int *conf_state, gss_buffer_t output_message_buffer)
{
  WARN ("gss_seal() is obsolete, use gss_wap() instead.");

  return gss_wrap (minor_status, context_handle, conf_req_flag, qop_req,
		   input_message_buffer, conf_state, output_message_buffer);
}


OM_uint32
gss_unseal (OM_uint32 * minor_status,
	    gss_ctx_id_t context_handle,
	    gss_buffer_t input_message_buffer,
	    gss_buffer_t output_message_buffer,
	    int *conf_state, int *qop_state)
{
  WARN ("gss_unseal() is obsolete, use gss_unwrap() instead.");

  return gss_unwrap (minor_status, context_handle, input_message_buffer,
		     output_message_buffer, conf_state, qop_state);
}
