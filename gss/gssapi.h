#ifndef GSSAPI_H_
#define GSSAPI_H_



/*
 * First, include stddef.h to get size_t defined.
 */
#include <stddef.h>

/*
 * If the platform supports the xom.h header file, it should be
 * included here.
 */
#include <xom.h>


/*
 * Now define the three implementation-dependent types.
 */
typedef <platform-specific> gss_ctx_id_t;
typedef <platform-specific> gss_cred_id_t;
typedef <platform-specific> gss_name_t;

/*
 * The following type must be defined as the smallest natural
 * unsigned integer supported by the platform that has at least
 * 32 bits of precision.
 */
typedef <platform-specific> gss_uint32;


#ifdef OM_STRING
/*
 * We have included the xom.h header file.  Verify that OM_uint32
 * is defined correctly.
 */

#if sizeof(gss_uint32) != sizeof(OM_uint32)
#error Incompatible definition of OM_uint32 from xom.h
#endif

typedef OM_object_identifier gss_OID_desc, *gss_OID;
#else

/*
 * We can't use X/Open definitions, so roll our own.
 */

typedef gss_uint32 OM_uint32;

typedef struct gss_OID_desc_struct {
  OM_uint32 length;
  void      *elements;
} gss_OID_desc, *gss_OID;

#endif

typedef struct gss_OID_set_desc_struct  {
  size_t     count;
  gss_OID    elements;
} gss_OID_set_desc, *gss_OID_set;

typedef struct gss_buffer_desc_struct {
  size_t length;
  void *value;
} gss_buffer_desc, *gss_buffer_t;

typedef struct gss_channel_bindings_struct {
  OM_uint32 initiator_addrtype;
  gss_buffer_desc initiator_address;
  OM_uint32 acceptor_addrtype;
  gss_buffer_desc acceptor_address;
  gss_buffer_desc application_data;
} *gss_channel_bindings_t;

/*
 * For now, define a QOP-type as an OM_uint32
 */
typedef OM_uint32 gss_qop_t;

typedef int gss_cred_usage_t;

/*
 * Flag bits for context-level services.
 */





#define GSS_C_DELEG_FLAG      1
#define GSS_C_MUTUAL_FLAG     2
#define GSS_C_REPLAY_FLAG     4
#define GSS_C_SEQUENCE_FLAG   8
#define GSS_C_CONF_FLAG       16
#define GSS_C_INTEG_FLAG      32
#define GSS_C_ANON_FLAG       64
#define GSS_C_PROT_READY_FLAG 128
#define GSS_C_TRANS_FLAG      256

/*
 * Credential usage options
 */
#define GSS_C_BOTH     0
#define GSS_C_INITIATE 1
#define GSS_C_ACCEPT   2

/*
 * Status code types for gss_display_status
 */
#define GSS_C_GSS_CODE  1
#define GSS_C_MECH_CODE 2

/*
 * The constant definitions for channel-bindings address families
 */
#define GSS_C_AF_UNSPEC     0
#define GSS_C_AF_LOCAL      1
#define GSS_C_AF_INET       2
#define GSS_C_AF_IMPLINK    3
#define GSS_C_AF_PUP        4
#define GSS_C_AF_CHAOS      5
#define GSS_C_AF_NS         6
#define GSS_C_AF_NBS        7
#define GSS_C_AF_ECMA       8
#define GSS_C_AF_DATAKIT    9
#define GSS_C_AF_CCITT      10
#define GSS_C_AF_SNA        11
#define GSS_C_AF_DECnet     12
#define GSS_C_AF_DLI        13
#define GSS_C_AF_LAT        14
#define GSS_C_AF_HYLINK     15
#define GSS_C_AF_APPLETALK  16
#define GSS_C_AF_BSC        17
#define GSS_C_AF_DSS        18
#define GSS_C_AF_OSI        19
#define GSS_C_AF_X25        21

#define GSS_C_AF_NULLADDR   255

/*
 * Various Null values
 */
#define GSS_C_NO_NAME ((gss_name_t) 0)
#define GSS_C_NO_BUFFER ((gss_buffer_t) 0)
#define GSS_C_NO_OID ((gss_OID) 0)
#define GSS_C_NO_OID_SET ((gss_OID_set) 0)
#define GSS_C_NO_CONTEXT ((gss_ctx_id_t) 0)
#define GSS_C_NO_CREDENTIAL ((gss_cred_id_t) 0)
#define GSS_C_NO_CHANNEL_BINDINGS ((gss_channel_bindings_t) 0)
#define GSS_C_EMPTY_BUFFER {0, NULL}

/*
 * Some alternate names for a couple of the above
 * values.  These are defined for V1 compatibility.
 */
#define GSS_C_NULL_OID GSS_C_NO_OID
#define GSS_C_NULL_OID_SET GSS_C_NO_OID_SET

/*
 * Define the default Quality of Protection for per-message
 * services.  Note that an implementation that offers multiple
 * levels of QOP may define GSS_C_QOP_DEFAULT to be either zero
 * (as done here) to mean "default protection", or to a specific
 * explicit QOP value.  However, a value of 0 should always be
 * interpreted by a GSS-API implementation as a request for the
 * default protection level.
 */
#define GSS_C_QOP_DEFAULT 0

/*
 * Expiration time of 2^32-1 seconds means infinite lifetime for a
 * cred
               gss_OID *               /* output_name_type */
              );

OM_uint32 gss_import_name
              (OM_uint32 ,             /* minor_status */
               const gss_buffer_t,     /* input_name_buffer */
               const gss_OID,          /* input_name_type */
               gss_name_t *            /* output_name */
              );



OM_uint32 gss_export_name
              (OM_uint32,              /* minor_status */
               const gss_name_t,       /* input_name */
               gss_buffer_t            /* exported_name */
              );

OM_uint32 gss_release_name
              (OM_uint32 *,            /* minor_status */
               gss_name_t *            /* input_name */
              );

OM_uint32 gss_release_buffer
              (OM_uint32 ,             /* minor_status */
               gss_buffer_t            /* buffer */
              );

OM_uint32 gss_release_oid_set
              (OM_uint32 ,             /* minor_status */
               gss_OID_set *           /* set */
              );

OM_uint32 gss_inquire_cred
              (OM_uint32 ,             /* minor_status */
               const gss_cred_id_t,    /* cred_handle */
               gss_name_t ,            /* name */
               OM_uint32 ,             /* lifetime */
               gss_cred_usage_t ,      /* cred_usage */
               gss_OID_set *           /* mechanisms */
              );

OM_uint32 gss_inquire_context (
               OM_uint32 ,             /* minor_status */
               const gss_ctx_id_t,     /* context_handle */
               gss_name_t ,            /* src_name */
               gss_name_t ,            /* targ_name */
               OM_uint32 ,             /* lifetime_rec */
               gss_OID ,               /* mech_type */
               OM_uint32 ,             /* ctx_flags */
               int ,                   /* locally_initiated */
               int *                   /* open */
              );







OM_uint32 gss_wrap_size_limit (
               OM_uint32 ,             /* minor_status */
               const gss_ctx_id_t,     /* context_handle */
               int,                    /* conf_req_flag */
               gss_qop_t,              /* qop_req */
               OM_uint32,              /* req_output_size */
               OM_uint32 *             /* max_input_size */
              );

OM_uint32 gss_add_cred (
               OM_uint32 ,             /* minor_status */
               const gss_cred_id_t,    /* input_cred_handle */
               const gss_name_t,       /* desired_name */
               const gss_OID,          /* desired_mech */
               gss_cred_usage_t,       /* cred_usage */
               OM_uint32,              /* initiator_time_req */
               OM_uint32,              /* acceptor_time_req */
               gss_cred_id_t ,         /* output_cred_handle */
               gss_OID_set ,           /* actual_mechs */
               OM_uint32 ,             /* initiator_time_rec */
               OM_uint32 *             /* acceptor_time_rec */
              );

OM_uint32 gss_inquire_cred_by_mech (
               OM_uint32 ,             /* minor_status */
               const gss_cred_id_t,    /* cred_handle */
               const gss_OID,          /* mech_type */
               gss_name_t ,            /* name */
               OM_uint32 ,             /* initiator_lifetime */
               OM_uint32 ,             /* acceptor_lifetime */
               gss_cred_usage_t *      /* cred_usage */
              );

OM_uint32 gss_export_sec_context (
               OM_uint32 ,             /* minor_status */
               gss_ctx_id_t ,          /* context_handle */
               gss_buffer_t            /* interprocess_token */
              );

OM_uint32 gss_import_sec_context (
               OM_uint32 ,             /* minor_status */
               const gss_buffer_t,     /* interprocess_token */
               gss_ctx_id_t *          /* context_handle */
              );




OM_uint32 gss_create_empty_oid_set (
               OM_uint32 ,             /* minor_status */
               gss_OID_set *           /* oid_set */
              );

OM_uint32 gss_add_oid_set_member (
               OM_uint32 ,             /* minor_status */
               const gss_OID,          /* member_oid */
               gss_OID_set *           /* oid_set */
              );

OM_uint32 gss_test_oid_set_member (
               OM_uint32 ,             /* minor_status */
               const gss_OID,          /* member */
               const gss_OID_set,      /* set */
               int *                   /* present */
              );

OM_uint32 gss_inquire_names_for_mech (
               OM_uint32 ,             /* minor_status */
               const gss_OID,          /* mechanism */
               gss_OID_set *           /* name_types */
              );

OM_uint32 gss_inquire_mechs_for_name (
               OM_uint32 ,             /* minor_status */
               const gss_name_t,       /* input_name */
               gss_OID_set *           /* mech_types */
              );

OM_uint32 gss_canonicalize_name (
               OM_uint32 ,             /* minor_status */
               const gss_name_t,       /* input_name */
               const gss_OID,          /* mech_type */
               gss_name_t *            /* output_name */
              );

OM_uint32 gss_duplicate_name (
               OM_uint32 ,             /* minor_status */
               const gss_name_t,       /* src_name */
               gss_name_t *            /* dest_name */
              );

/*
 * The following routines are obsolete variants of gss_get_mic,
 * gss_verify_mic, gss_wrap and gss_unwrap.  They should be
 * provided by GSS-API V2 implementations for backwards
 * compatibility with V1 applications.  Distinct entrypoints
 * (as opposed to #defines) should be provided, both to allow
 * GSS-API V1 applications to link against GSS-API V2
   implementations,
 * and to retain the slight parameter type differences between the
 * obsolete versions of these routines and their current forms.
 */

OM_uint32 gss_sign
              (OM_uint32 ,        /* minor_status */
               gss_ctx_id_t,      /* context_handle */
               int,               /* qop_req */
               gss_buffer_t,      /* message_buffer */
               gss_buffer_t       /* message_token */
              );


OM_uint32 gss_verify
              (OM_uint32 ,        /* minor_status */
               gss_ctx_id_t,      /* context_handle */
               gss_buffer_t,      /* message_buffer */
               gss_buffer_t,      /* token_buffer */
               int *              /* qop_state */
              );

OM_uint32 gss_seal
              (OM_uint32 ,        /* minor_status */
               gss_ctx_id_t,      /* context_handle */
               int,               /* conf_req_flag */
               int,               /* qop_req */
               gss_buffer_t,      /* input_message_buffer */
               int ,              /* conf_state */
               gss_buffer_t       /* output_message_buffer */
              );


OM_uint32 gss_unseal
              (OM_uint32 ,        /* minor_status */
               gss_ctx_id_t,      /* context_handle */
               gss_buffer_t,      /* input_message_buffer */
               gss_buffer_t,      /* output_message_buffer */
               int ,              /* conf_state */
               int *              /* qop_state */
              );

#endif /* GSSAPI_H_ */
