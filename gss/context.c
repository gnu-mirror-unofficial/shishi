/* context.c	Implementation of GSS-API Context functions.
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
 * gss_init_sec_context:
 * @minor_status: Mechanism specific status code.
 * @initiator_cred_handle: Optional handle for credentials claimed.
 *   Supply GSS_C_NO_CREDENTIAL to act as a default initiator principal.
 *   If no default initiator is defined, the function will return
 *   GSS_S_NO_CRED.
 * @context_handle: Context handle for new context.  Supply
 *   GSS_C_NO_CONTEXT for first call; use value returned by first call
 *   in continuation calls.  Resources associated with this
 *   context-handle must be released by the application after use with a
 *   call to gss_delete_sec_context().
 * @target_name: Name of target.
 * @mech_type: Optional object ID of desired mechanism. Supply
 *   GSS_C_NO_OID to obtain an implementation specific default
 * @req_flags: Contains various independent flags, each of which
 *   requests that the context support a specific service option.
 *   Symbolic names are provided for each flag, and the symbolic names
 *   corresponding to the required flags should be logically-ORed
 *   together to form the bit-mask value.  See below for details.
 * @time_req: Optional Desired number of seconds for which context
 *   should remain valid.  Supply 0 to request a default validity
 *   period.
 * @input_chan_bindings: Optional Application-specified bindings.
 *   Allows application to securely bind channel identification
 *   information to the security context.  Specify
 *   GSS_C_NO_CHANNEL_BINDINGS if channel bindings are not used.
 * @input_token: Optional (see text) Token received from peer
 *   application.  Supply GSS_C_NO_BUFFER, or a pointer to a buffer
 *   containing the value GSS_C_EMPTY_BUFFER on initial call.
 * @actual_mech_type: Optional actual mechanism used.  The OID
 *   returned via this parameter will be a pointer to static storage
 *   that should be treated as read-only; In particular the application
 *   should not attempt to free it.  Specify NULL if not required.
 * @output_token: Token to be sent to peer application.  If the length
 *   field of the returned buffer is zero, no token need be sent to the
 *   peer application.  Storage associated with this buffer must be
 *   freed by the application after use with a call to
 *   gss_release_buffer().
 * @ret_flags: Optional various independent flags, each of which
 *   indicates that the context supports a specific service option.
 *   Specify NULL if not required.  Symbolic names are provided for each
 *   flag, and the symbolic names corresponding to the required flags
 *   should be logically-ANDed with the ret_flags value to test whether
 *   a given option is supported by the context. See below for details.
 * @time_rec: Optional number of seconds for which the context will
 *   remain valid. If the implementation does not support context
 *   expiration, the value GSS_C_INDEFINITE will be returned.  Specify
 *   NULL if not required.
 *
 * Initiates the establishment of a security context between the
 * application and a remote peer.  Initially, the input_token
 * parameter should be specified either as GSS_C_NO_BUFFER, or as a
 * pointer to a gss_buffer_desc object whose length field contains the
 * value zero.  The routine may return a output_token which should be
 * transferred to the peer application, where the peer application
 * will present it to gss_accept_sec_context.  If no token need be
 * sent, gss_init_sec_context will indicate this by setting the length
 * field of the output_token argument to zero. To complete the context
 * establishment, one or more reply tokens may be required from the
 * peer application; if so, gss_init_sec_context will return a status
 * containing the supplementary information bit GSS_S_CONTINUE_NEEDED.
 * In this case, gss_init_sec_context should be called again when the
 * reply token is received from the peer application, passing the
 * reply token to gss_init_sec_context via the input_token parameters.
 *
 * Portable applications should be constructed to use the token length
 * and return status to determine whether a token needs to be sent or
 * waited for.  Thus a typical portable caller should always invoke
 * gss_init_sec_context within a loop:
 *
 * int context_established = 0;
 * gss_ctx_id_t context_hdl = GSS_C_NO_CONTEXT;
 * ...
 * input_token->length = 0;
 *
 * while (!context_established) {
 *   maj_stat = gss_init_sec_context(&min_stat, cred_hdl, &context_hdl,
 *                                   target_name, desired_mech,
 *                                   desired_services, desired_time,
 *                                   input_bindings, input_token, &actual_mech,
 *                                   output_token, &actual_services,
 *                                   &actual_time);
 *   if (GSS_ERROR(maj_stat)) {
 *     report_error(maj_stat, min_stat);
 *   };
 *
 *   if (output_token->length != 0) {
 *     send_token_to_peer(output_token);
 *     gss_release_buffer(&min_stat, output_token)
 *   };
 *   if (GSS_ERROR(maj_stat)) {
 *
 *     if (context_hdl != GSS_C_NO_CONTEXT)
 *       gss_delete_sec_context(&min_stat, &context_hdl, GSS_C_NO_BUFFER);
 *      break;
 *   };
 *
 *   if (maj_stat & GSS_S_CONTINUE_NEEDED) {
 *     receive_token_from_peer(input_token);
 *   } else {
 *     context_established = 1;
 *   };
 * };
 *
 * Whenever the routine returns a major status that includes the value
 * GSS_S_CONTINUE_NEEDED, the context is not fully established and the
 * following restrictions apply to the output parameters:
 *
 * The value returned via the time_rec parameter is undefined Unless
 * the accompanying ret_flags parameter contains the bit
 * GSS_C_PROT_READY_FLAG, indicating that per-message services may be
 * applied in advance of a successful completion status, the value
 * returned via the actual_mech_type parameter is undefined until the
 * routine returns a major status value of GSS_S_COMPLETE.
 *
 * The values of the GSS_C_DELEG_FLAG, GSS_C_MUTUAL_FLAG,
 * GSS_C_REPLAY_FLAG, GSS_C_SEQUENCE_FLAG, GSS_C_CONF_FLAG,
 * GSS_C_INTEG_FLAG and GSS_C_ANON_FLAG bits returned via the
 * ret_flags parameter should contain the values that the
 * implementation expects would be valid if context establishment were
 * to succeed.  In particular, if the application has requested a
 * service such as delegation or anonymous authentication via the
 * req_flags argument, and such a service is unavailable from the
 * underlying mechanism, gss_init_sec_context should generate a token
 * that will not provide the service, and indicate via the ret_flags
 * argument that the service will not be supported.  The application
 * may choose to abort the context establishment by calling
 * gss_delete_sec_context (if it cannot continue in the absence of the
 * service), or it may choose to transmit the token and continue
 * context establishment (if the service was merely desired but not
 * mandatory).
 *
 * The values of the GSS_C_PROT_READY_FLAG and GSS_C_TRANS_FLAG bits
 * within ret_flags should indicate the actual state at the time
 * gss_init_sec_context returns, whether or not the context is fully
 * established.
 *
 * GSS-API implementations that support per-message protection are
 * encouraged to set the GSS_C_PROT_READY_FLAG in the final ret_flags
 * returned to a caller (i.e. when accompanied by a GSS_S_COMPLETE
 * status code).  However, applications should not rely on this
 * behavior as the flag was not defined in Version 1 of the GSS-API.
 * Instead, applications should determine what per-message services
 * are available after a successful context establishment according to
 * the GSS_C_INTEG_FLAG and GSS_C_CONF_FLAG values.
 *
 * All other bits within the ret_flags argument should be set to
 * zero.
 *
 * If the initial call of gss_init_sec_context() fails, the
 * implementation should not create a context object, and should leave
 * the value of the context_handle parameter set to GSS_C_NO_CONTEXT
 * to indicate this.  In the event of a failure on a subsequent call,
 * the implementation is permitted to delete the "half-built" security
 * context (in which case it should set the context_handle parameter
 * to GSS_C_NO_CONTEXT), but the preferred behavior is to leave the
 * security context untouched for the application to delete (using
 * gss_delete_sec_context).
 *
 * During context establishment, the informational status bits
 * GSS_S_OLD_TOKEN and GSS_S_DUPLICATE_TOKEN indicate fatal errors,
 * and GSS-API mechanisms should always return them in association
 * with a routine error of GSS_S_FAILURE.  This requirement for
 * pairing did not exist in version 1 of the GSS-API specification, so
 * applications that wish to run over version 1 implementations must
 * special-case these codes.
 *
 * The req_flags flags are:
 *
 * GSS_C_DELEG_FLAG
 * True - Delegate credentials to remote peer
 * False - Don't delegate
 *
 * GSS_C_MUTUAL_FLAG
 * True - Request that remote peer authenticate itself
 * False - Authenticate self to remote peer only
 *
 * GSS_C_REPLAY_FLAG
 * True - Enable replay detection for messages protected with gss_wrap
 *   or gss_get_mic
 * False - Don't attempt to detect replayed messages
 *
 * GSS_C_SEQUENCE_FLAG
 * True - Enable detection of out-of-sequence protected messages
 * False - Don't attempt to detect out-of-sequence messages
 *
 * GSS_C_CONF_FLAG
 * True - Request that confidentiality service be made available (via gss_wrap)
 * False - No per-message confidentiality service is required.
 *
 * GSS_C_INTEG_FLAG
 * True - Request that integrity service be made available (via gss_wrap or
 *   gss_get_mic)
 * False - No per-message integrity service is required.
 *
 * GSS_C_ANON_FLAG
 * True - Do not reveal the initiator's identity to the acceptor.
 * False - Authenticate normally.
 *
 * The ret_flags flags are:
 *
 * GSS_C_DELEG_FLAG
 * True - Credentials were delegated to the remote peer
 * False - No credentials were delegated
 *
 * GSS_C_MUTUAL_FLAG
 * True - The remote peer has authenticated itself.
 * False - Remote peer has not authenticated itself.
 *
 * GSS_C_REPLAY_FLAG
 * True - replay of protected messages will be detected
 * False - replayed messages will not be detected
 *
 * GSS_C_SEQUENCE_FLAG
 * True - out-of-sequence protected messages will be detected
 * False - out-of-sequence messages will not be detected
 *
 * GSS_C_CONF_FLAG
 * True - Confidentiality service may be invoked by calling gss_wrap routine
 * False - No confidentiality service (via gss_wrap) available. gss_wrap will
 *   provide message encapsulation, data-origin authentication and
 *   integrity services only.
 *
 * GSS_C_INTEG_FLAG
 * True - Integrity service may be invoked by calling either gss_get_mic
 *   or gss_wrap routines.
 * False - Per-message integrity service unavailable.
 *
 * GSS_C_ANON_FLAG
 * True - The initiator's identity has not been revealed, and will not
 *   be revealed if any emitted token is passed to the acceptor.
 * False - The initiator's identity has been or will be authenticated normally.
 *
 * GSS_C_PROT_READY_FLAG
 * True - Protection services (as specified by the states of the
 *   GSS_C_CONF_FLAG and GSS_C_INTEG_FLAG) are available for use if the
 *   accompanying major status return value is either GSS_S_COMPLETE or
 *   GSS_S_CONTINUE_NEEDED.
 * False - Protection services (as specified by the states of the
 *   GSS_C_CONF_FLAG and GSS_C_INTEG_FLAG) are available only if the
 *   accompanying major status return value is GSS_S_COMPLETE.
 *
 * GSS_C_TRANS_FLAG
 * True - The resultant security context may be transferred to other
 *   processes via a call to gss_export_sec_context().
 * False - The security context is not transferable.
 *
 * All other bits should be set to zero.
 *
 * Return value: Returns:
 *
 * GSS_S_COMPLETE    Successful completion
 *
 * GSS_S_CONTINUE_NEEDED Indicates that a token from the peer
 * application is required to complete the
 * context, and that gss_init_sec_context
 * must be called again with that token.
 *
 * GSS_S_DEFECTIVE_TOKEN Indicates that consistency checks performed
 * on the input_token failed
 *
 * GSS_S_DEFECTIVE_CREDENTIAL Indicates that consistency checks
 * performed on the credential failed.
 *
 * GSS_S_NO_CRED     The supplied credentials were not valid for
 * context initiation, or the credential handle
 * did not reference any credentials.
 *
 * GSS_S_CREDENTIALS_EXPIRED The referenced credentials have expired
 *
 * GSS_S_BAD_BINDINGS The input_token contains different channel
 * bindings to those specified via the
 * input_chan_bindings parameter
 *
 * GSS_S_BAD_SIG     The input_token contains an invalid MIC, or a MIC
 * that could not be verified
 *
 * GSS_S_OLD_TOKEN   The input_token was too old.  This is a fatal
 * error during context establishment
 *
 * GSS_S_DUPLICATE_TOKEN The input_token is valid, but is a duplicate
 * of a token already processed.  This is a
 * fatal error during context establishment.
 *
 * GSS_S_NO_CONTEXT  Indicates that the supplied context handle did
 * not refer to a valid context
 *
 * GSS_S_BAD_NAMETYPE The provided target_name parameter contained an
 * invalid or unsupported type of name
 *
 * GSS_S_BAD_NAME    The provided target_name parameter was ill-formed.
 *
 * GSS_S_BAD_MECH    The specified mechanism is not supported by the
 * provided credential, or is unrecognized by the
 * implementation.
 *
 **/
OM_uint32
gss_init_sec_context (OM_uint32 * minor_status,
		      const gss_cred_id_t initiator_cred_handle,
		      gss_ctx_id_t * context_handle,
		      const gss_name_t target_name,
		      const gss_OID mech_type,
		      OM_uint32 req_flags,
		      OM_uint32 time_req,
		      const gss_channel_bindings_t input_chan_bindings,
		      const gss_buffer_t input_token,
		      gss_OID * actual_mech_type,
		      gss_buffer_t output_token,
		      OM_uint32 * ret_flags, OM_uint32 * time_rec)
{
  return GSS_S_FAILURE;
}

OM_uint32
gss_accept_sec_context (OM_uint32 * minor_status,
			gss_ctx_id_t * context_handle,
			const gss_cred_id_t acceptor_cred_handle,
			const gss_buffer_t input_token_buffer,
			const gss_channel_bindings_t input_chan_bindings,
			gss_name_t * src_name,
			gss_OID * mech_type,
			gss_buffer_t output_token,
			OM_uint32 * ret_flags,
			OM_uint32 * time_rec,
			gss_cred_id_t * delegated_cred_handle)
{
  return GSS_S_FAILURE;
}

/**
 * gss_delete_sec_context:
 * @minor_status: Mechanism specific status code.
 * @context_handle: Context handle identifying context to delete.
 *   After deleting the context, the GSS-API will set this context
 *   handle to GSS_C_NO_CONTEXT.
 * @output_token: Optional token to be sent to remote application to
 *   instruct it to also delete the context.  It is recommended that
 *   applications specify GSS_C_NO_BUFFER for this parameter, requesting
 *   local deletion only.  If a buffer parameter is provided by the
 *   application, the mechanism may return a token in it; mechanisms
 *   that implement only local deletion should set the length field of
 *   this token to zero to indicate to the application that no token is
 *   to be sent to the peer.
 *
 * Delete a security context.  gss_delete_sec_context() will delete
 * the local data structures associated with the specified security
 * context, and may generate an output_token, which when passed to the
 * peer gss_process_context_token() will instruct it to do likewise.
 * If no token is required by the mechanism, the GSS-API should set
 * the length field of the output_token (if provided) to zero.  No
 * further security services may be obtained using the context
 * specified by context_handle.
 *
 * In addition to deleting established security contexts,
 * gss_delete_sec_context() must also be able to delete "half-built"
 * security contexts resulting from an incomplete sequence of
 * gss_init_sec_context()/gss_accept_sec_context() calls.
 *
 * The output_token parameter is retained for compatibility with
 * version 1 of the GSS-API.  It is recommended that both peer
 * applications invoke gss_delete_sec_context() passing the value
 * GSS_C_NO_BUFFER for the output_token parameter, indicating that no
 * token is required, and that gss_delete_sec_context() should simply
 * delete local context data structures.  If the application does pass
 * a valid buffer to gss_delete_sec_context(), mechanisms are
 * encouraged to return a zero-length token, indicating that no peer
 * action is necessary, and that no token should be transferred by the
 * application.
 *
 * Return value: Returns GSS_S_COMPLETE for successful completion, and
 *   GSS_S_NO_CONTEXT if no valid context was supplied.
 **/
OM_uint32
gss_delete_sec_context (OM_uint32 * minor_status,
			gss_ctx_id_t * context_handle,
			gss_buffer_t output_token)
{
  if (!context_handle || *context_handle == GSS_C_NO_CONTEXT)
    return GSS_S_NO_CONTEXT;

  if (output_token != GSS_C_NO_BUFFER)
    output_token->length = 0;

  free (*context_handle);
  *context_handle = GSS_C_NO_CONTEXT;

  return GSS_S_COMPLETE;
}

OM_uint32
gss_process_context_token (OM_uint32 * minor_status,
			   const gss_ctx_id_t context_handle,
			   const gss_buffer_t token_buffer)
{
  return GSS_S_FAILURE;
}

OM_uint32
gss_context_time (OM_uint32 * minor_status,
		  const gss_ctx_id_t context_handle, OM_uint32 * time_rec)
{
  return GSS_S_FAILURE;
}

OM_uint32
gss_inquire_context (OM_uint32 * minor_status,
		     const gss_ctx_id_t context_handle,
		     gss_name_t * src_name,
		     gss_name_t * targ_name,
		     OM_uint32 * lifetime_rec,
		     gss_OID * mech_type,
		     OM_uint32 * ctx_flags, int *locally_initiated, int *open)
{
  return GSS_S_FAILURE;
}

OM_uint32
gss_wrap_size_limit (OM_uint32 * minor_status,
		     const gss_ctx_id_t context_handle,
		     int conf_req_flag,
		     gss_qop_t qop_req,
		     OM_uint32 req_output_size, OM_uint32 * max_input_size)
{
  return GSS_S_FAILURE;
}

OM_uint32
gss_export_sec_context (OM_uint32 * minor_status,
			gss_ctx_id_t * context_handle,
			gss_buffer_t interprocess_token)
{
  return GSS_S_UNAVAILABLE;
}

OM_uint32
gss_import_sec_context (OM_uint32 * minor_status,
			const gss_buffer_t interprocess_token,
			gss_ctx_id_t * context_handle)
{
  return GSS_S_UNAVAILABLE;
}
