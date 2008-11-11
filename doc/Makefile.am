## Process this file with automake to produce Makefile.in
# Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008 Simon Josefsson.
#
# This file is part of Shishi.
#
# Shishi is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# Shishi is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Shishi; if not, see http://www.gnu.org/licenses or write
# to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
# Floor, Boston, MA 02110-1301, USA.

if ENABLE_GTK_DOC
SUBDIRS = . reference
endif

EXTRA_DIST = gdoc gdoc-error shishi.html shishi.pdf shishi.ps components.dia

components.png: components.dia
	$(DIA) --export=$@ --filter=png $<

info_TEXINFOS = shishi.texi
shishi_TEXINFOS = gpl-3.0.texi fdl-1.3.texi $(gdoc_TEXINFOS) \
	shishi-api-error-labels.texi getdate.texi \
	texinfo.css components.png keytab.txt ccache.txt

AM_MAKEINFOHTMLFLAGS = --no-split --number-sections --css-include=texinfo.css

dist_man_MANS = shishi.1 shisa.1 shishid.1 keytab2shishi.1 ccache2shishi.1 \
	$(gdoc_MANS)
MAINTAINERCLEANFILES = $(dist_man_MANS)

shishi.1: $(top_srcdir)/src/shishi.c $(top_srcdir)/src/shishi.ggo \
		$(top_srcdir)/configure.ac
	$(HELP2MAN) \
		--name="Shishi client tool" \
		--output=$@ $(top_builddir)/src/shishi$(EXEEXT)

shisa.1: $(top_srcdir)/src/shisa.c $(top_srcdir)/src/shisa.ggo \
		$(top_srcdir)/configure.ac
	$(HELP2MAN) \
		--name="Shishi database interface" \
		--info-page=shishi \
		--output=$@ $(top_builddir)/src/shisa$(EXEEXT)

shishid.1: $(top_srcdir)/src/shishid.c $(top_srcdir)/src/shishid.ggo \
		$(top_srcdir)/configure.ac
	$(HELP2MAN) \
		--name="Shishi KDC server" \
		--output=$@ $(top_builddir)/src/shishid$(EXEEXT)

keytab2shishi.1: $(top_srcdir)/src/keytab2shishi.c \
	$(top_srcdir)/src/keytab2shishi.ggo $(top_srcdir)/configure.ac
	$(HELP2MAN) \
		--name="Shishi host key conversion tool" \
		--output=$@ $(top_builddir)/src/keytab2shishi$(EXEEXT)

ccache2shishi.1: $(top_srcdir)/src/ccache2shishi.c \
	$(top_srcdir)/src/ccache2shishi.ggo $(top_srcdir)/configure.ac
	$(HELP2MAN) \
		--name="Shishi user ticket conversion tool" \
		--output=$@ $(top_builddir)/src/ccache2shishi$(EXEEXT)

shishi-api-error-labels.texi: $(top_srcdir)/lib/error.c
	$(PERL) $(srcdir)/gdoc-error $^ > $@

gdoc_MANS =
gdoc_MANS += man/shishi_ap.3
gdoc_MANS += man/shishi_ap_etype.3
gdoc_MANS += man/shishi_ap_nosubkey.3
gdoc_MANS += man/shishi_ap_done.3
gdoc_MANS += man/shishi_ap_set_tktoptions.3
gdoc_MANS += man/shishi_ap_set_tktoptionsdata.3
gdoc_MANS += man/shishi_ap_set_tktoptionsraw.3
gdoc_MANS += man/shishi_ap_set_tktoptionsasn1usage.3
gdoc_MANS += man/shishi_ap_tktoptions.3
gdoc_MANS += man/shishi_ap_tktoptionsdata.3
gdoc_MANS += man/shishi_ap_tktoptionsraw.3
gdoc_MANS += man/shishi_ap_etype_tktoptionsdata.3
gdoc_MANS += man/shishi_ap_tktoptionsasn1usage.3
gdoc_MANS += man/shishi_ap_tkt.3
gdoc_MANS += man/shishi_ap_tkt_set.3
gdoc_MANS += man/shishi_ap_authenticator_cksumdata.3
gdoc_MANS += man/shishi_ap_authenticator_cksumdata_set.3
gdoc_MANS += man/shishi_ap_authenticator_cksumraw_set.3
gdoc_MANS += man/shishi_ap_authenticator_cksumtype.3
gdoc_MANS += man/shishi_ap_authenticator_cksumtype_set.3
gdoc_MANS += man/shishi_ap_authenticator.3
gdoc_MANS += man/shishi_ap_authenticator_set.3
gdoc_MANS += man/shishi_ap_req.3
gdoc_MANS += man/shishi_ap_req_set.3
gdoc_MANS += man/shishi_ap_req_der.3
gdoc_MANS += man/shishi_ap_req_der_set.3
gdoc_MANS += man/shishi_ap_req_build.3
gdoc_MANS += man/shishi_ap_req_decode.3
gdoc_MANS += man/shishi_ap_req_process_keyusage.3
gdoc_MANS += man/shishi_ap_req_process.3
gdoc_MANS += man/shishi_ap_req_asn1.3
gdoc_MANS += man/shishi_ap_key.3
gdoc_MANS += man/shishi_ap_rep.3
gdoc_MANS += man/shishi_ap_rep_set.3
gdoc_MANS += man/shishi_ap_rep_der.3
gdoc_MANS += man/shishi_ap_rep_der_set.3
gdoc_MANS += man/shishi_ap_rep_build.3
gdoc_MANS += man/shishi_ap_rep_asn1.3
gdoc_MANS += man/shishi_ap_rep_verify.3
gdoc_MANS += man/shishi_ap_rep_verify_der.3
gdoc_MANS += man/shishi_ap_rep_verify_asn1.3
gdoc_MANS += man/shishi_ap_encapreppart.3
gdoc_MANS += man/shishi_ap_encapreppart_set.3
gdoc_MANS += man/shishi_ap_option2string.3
gdoc_MANS += man/shishi_ap_string2option.3
gdoc_MANS += man/shishi_aprep.3
gdoc_MANS += man/shishi_aprep_print.3
gdoc_MANS += man/shishi_aprep_save.3
gdoc_MANS += man/shishi_aprep_to_file.3
gdoc_MANS += man/shishi_aprep_parse.3
gdoc_MANS += man/shishi_aprep_read.3
gdoc_MANS += man/shishi_aprep_from_file.3
gdoc_MANS += man/shishi_aprep_get_enc_part_etype.3
gdoc_MANS += man/shishi_apreq.3
gdoc_MANS += man/shishi_apreq_print.3
gdoc_MANS += man/shishi_apreq_save.3
gdoc_MANS += man/shishi_apreq_to_file.3
gdoc_MANS += man/shishi_apreq_parse.3
gdoc_MANS += man/shishi_apreq_read.3
gdoc_MANS += man/shishi_apreq_from_file.3
gdoc_MANS += man/shishi_apreq_set_authenticator.3
gdoc_MANS += man/shishi_apreq_add_authenticator.3
gdoc_MANS += man/shishi_apreq_set_ticket.3
gdoc_MANS += man/shishi_apreq_options.3
gdoc_MANS += man/shishi_apreq_use_session_key_p.3
gdoc_MANS += man/shishi_apreq_mutual_required_p.3
gdoc_MANS += man/shishi_apreq_options_set.3
gdoc_MANS += man/shishi_apreq_options_add.3
gdoc_MANS += man/shishi_apreq_options_remove.3
gdoc_MANS += man/shishi_apreq_get_authenticator_etype.3
gdoc_MANS += man/shishi_apreq_get_ticket.3
gdoc_MANS += man/shishi_as.3
gdoc_MANS += man/shishi_as_done.3
gdoc_MANS += man/shishi_as_req.3
gdoc_MANS += man/shishi_as_req_build.3
gdoc_MANS += man/shishi_as_req_set.3
gdoc_MANS += man/shishi_as_req_der.3
gdoc_MANS += man/shishi_as_req_der_set.3
gdoc_MANS += man/shishi_as_rep.3
gdoc_MANS += man/shishi_as_rep_process.3
gdoc_MANS += man/shishi_as_rep_build.3
gdoc_MANS += man/shishi_as_rep_der.3
gdoc_MANS += man/shishi_as_rep_set.3
gdoc_MANS += man/shishi_as_rep_der_set.3
gdoc_MANS += man/shishi_as_krberror.3
gdoc_MANS += man/shishi_as_krberror_der.3
gdoc_MANS += man/shishi_as_krberror_set.3
gdoc_MANS += man/shishi_as_tkt.3
gdoc_MANS += man/shishi_as_tkt_set.3
gdoc_MANS += man/shishi_as_sendrecv_hint.3
gdoc_MANS += man/shishi_as_sendrecv.3
gdoc_MANS += man/shishi_asn1_read_inline.3
gdoc_MANS += man/shishi_asn1_read.3
gdoc_MANS += man/shishi_asn1_read_optional.3
gdoc_MANS += man/shishi_asn1_done.3
gdoc_MANS += man/shishi_asn1_pa_enc_ts_enc.3
gdoc_MANS += man/shishi_asn1_encrypteddata.3
gdoc_MANS += man/shishi_asn1_padata.3
gdoc_MANS += man/shishi_asn1_methoddata.3
gdoc_MANS += man/shishi_asn1_etype_info.3
gdoc_MANS += man/shishi_asn1_etype_info2.3
gdoc_MANS += man/shishi_asn1_asreq.3
gdoc_MANS += man/shishi_asn1_asrep.3
gdoc_MANS += man/shishi_asn1_tgsreq.3
gdoc_MANS += man/shishi_asn1_tgsrep.3
gdoc_MANS += man/shishi_asn1_apreq.3
gdoc_MANS += man/shishi_asn1_aprep.3
gdoc_MANS += man/shishi_asn1_encapreppart.3
gdoc_MANS += man/shishi_asn1_ticket.3
gdoc_MANS += man/shishi_asn1_encticketpart.3
gdoc_MANS += man/shishi_asn1_authenticator.3
gdoc_MANS += man/shishi_asn1_enckdcreppart.3
gdoc_MANS += man/shishi_asn1_encasreppart.3
gdoc_MANS += man/shishi_asn1_krberror.3
gdoc_MANS += man/shishi_asn1_krbsafe.3
gdoc_MANS += man/shishi_asn1_priv.3
gdoc_MANS += man/shishi_asn1_encprivpart.3
gdoc_MANS += man/shishi_asn1_to_der_field.3
gdoc_MANS += man/shishi_asn1_to_der.3
gdoc_MANS += man/shishi_asn1_msgtype.3
gdoc_MANS += man/shishi_der_msgtype.3
gdoc_MANS += man/shishi_der2asn1.3
gdoc_MANS += man/shishi_der2asn1_padata.3
gdoc_MANS += man/shishi_der2asn1_methoddata.3
gdoc_MANS += man/shishi_der2asn1_etype_info.3
gdoc_MANS += man/shishi_der2asn1_etype_info2.3
gdoc_MANS += man/shishi_der2asn1_ticket.3
gdoc_MANS += man/shishi_der2asn1_encticketpart.3
gdoc_MANS += man/shishi_der2asn1_asreq.3
gdoc_MANS += man/shishi_der2asn1_tgsreq.3
gdoc_MANS += man/shishi_der2asn1_asrep.3
gdoc_MANS += man/shishi_der2asn1_tgsrep.3
gdoc_MANS += man/shishi_der2asn1_kdcrep.3
gdoc_MANS += man/shishi_der2asn1_encasreppart.3
gdoc_MANS += man/shishi_der2asn1_enctgsreppart.3
gdoc_MANS += man/shishi_der2asn1_enckdcreppart.3
gdoc_MANS += man/shishi_der2asn1_authenticator.3
gdoc_MANS += man/shishi_der2asn1_krberror.3
gdoc_MANS += man/shishi_der2asn1_krbsafe.3
gdoc_MANS += man/shishi_der2asn1_priv.3
gdoc_MANS += man/shishi_der2asn1_encprivpart.3
gdoc_MANS += man/shishi_der2asn1_apreq.3
gdoc_MANS += man/shishi_der2asn1_aprep.3
gdoc_MANS += man/shishi_der2asn1_encapreppart.3
gdoc_MANS += man/shishi_der2asn1_kdcreq.3
gdoc_MANS += man/shishi_asn1_print.3
gdoc_MANS += man/shishi_authenticator.3
gdoc_MANS += man/shishi_authenticator_subkey.3
gdoc_MANS += man/shishi_authenticator_print.3
gdoc_MANS += man/shishi_authenticator_save.3
gdoc_MANS += man/shishi_authenticator_to_file.3
gdoc_MANS += man/shishi_authenticator_parse.3
gdoc_MANS += man/shishi_authenticator_read.3
gdoc_MANS += man/shishi_authenticator_from_file.3
gdoc_MANS += man/shishi_authenticator_set_crealm.3
gdoc_MANS += man/shishi_authenticator_set_cname.3
gdoc_MANS += man/shishi_authenticator_client_set.3
gdoc_MANS += man/shishi_authenticator_ctime.3
gdoc_MANS += man/shishi_authenticator_ctime_set.3
gdoc_MANS += man/shishi_authenticator_cusec_get.3
gdoc_MANS += man/shishi_authenticator_cusec_set.3
gdoc_MANS += man/shishi_authenticator_seqnumber_get.3
gdoc_MANS += man/shishi_authenticator_seqnumber_remove.3
gdoc_MANS += man/shishi_authenticator_seqnumber_set.3
gdoc_MANS += man/shishi_authenticator_client.3
gdoc_MANS += man/shishi_authenticator_clientrealm.3
gdoc_MANS += man/shishi_authenticator_cksum.3
gdoc_MANS += man/shishi_authenticator_set_cksum.3
gdoc_MANS += man/shishi_authenticator_add_cksum.3
gdoc_MANS += man/shishi_authenticator_add_cksum_type.3
gdoc_MANS += man/shishi_authenticator_clear_authorizationdata.3
gdoc_MANS += man/shishi_authenticator_add_authorizationdata.3
gdoc_MANS += man/shishi_authenticator_authorizationdata.3
gdoc_MANS += man/shishi_authenticator_remove_subkey.3
gdoc_MANS += man/shishi_authenticator_get_subkey.3
gdoc_MANS += man/shishi_authenticator_set_subkey.3
gdoc_MANS += man/shishi_authenticator_add_random_subkey.3
gdoc_MANS += man/shishi_authenticator_add_random_subkey_etype.3
gdoc_MANS += man/shishi_authenticator_add_subkey.3
gdoc_MANS += man/shishi_authorization_parse.3
gdoc_MANS += man/shishi_authorized_p.3
gdoc_MANS += man/shishi_cfg.3
gdoc_MANS += man/shishi_cfg_from_file.3
gdoc_MANS += man/shishi_cfg_print.3
gdoc_MANS += man/shishi_cfg_default_systemfile.3
gdoc_MANS += man/shishi_cfg_default_userdirectory.3
gdoc_MANS += man/shishi_cfg_userdirectory_file.3
gdoc_MANS += man/shishi_cfg_default_userfile.3
gdoc_MANS += man/shishi_cfg_clientkdcetype.3
gdoc_MANS += man/shishi_cfg_clientkdcetype_fast.3
gdoc_MANS += man/shishi_cfg_clientkdcetype_set.3
gdoc_MANS += man/shishi_cfg_authorizationtype_set.3
gdoc_MANS += man/shishi_crypto.3
gdoc_MANS += man/shishi_crypto_encrypt.3
gdoc_MANS += man/shishi_crypto_decrypt.3
gdoc_MANS += man/shishi_crypto_close.3
gdoc_MANS += man/shishi_cipher_supported_p.3
gdoc_MANS += man/shishi_cipher_name.3
gdoc_MANS += man/shishi_cipher_blocksize.3
gdoc_MANS += man/shishi_cipher_confoundersize.3
gdoc_MANS += man/shishi_cipher_keylen.3
gdoc_MANS += man/shishi_cipher_randomlen.3
gdoc_MANS += man/shishi_cipher_defaultcksumtype.3
gdoc_MANS += man/shishi_cipher_parse.3
gdoc_MANS += man/shishi_checksum_supported_p.3
gdoc_MANS += man/shishi_checksum_name.3
gdoc_MANS += man/shishi_checksum_cksumlen.3
gdoc_MANS += man/shishi_checksum_parse.3
gdoc_MANS += man/shishi_string_to_key.3
gdoc_MANS += man/shishi_random_to_key.3
gdoc_MANS += man/shishi_checksum.3
gdoc_MANS += man/shishi_verify.3
gdoc_MANS += man/shishi_encrypt_ivupdate_etype.3
gdoc_MANS += man/shishi_encrypt_iv_etype.3
gdoc_MANS += man/shishi_encrypt_etype.3
gdoc_MANS += man/shishi_encrypt_ivupdate.3
gdoc_MANS += man/shishi_encrypt_iv.3
gdoc_MANS += man/shishi_encrypt.3
gdoc_MANS += man/shishi_decrypt_ivupdate_etype.3
gdoc_MANS += man/shishi_decrypt_iv_etype.3
gdoc_MANS += man/shishi_decrypt_etype.3
gdoc_MANS += man/shishi_decrypt_ivupdate.3
gdoc_MANS += man/shishi_decrypt_iv.3
gdoc_MANS += man/shishi_decrypt.3
gdoc_MANS += man/shishi_n_fold.3
gdoc_MANS += man/shishi_dr.3
gdoc_MANS += man/shishi_dk.3
gdoc_MANS += man/shishi_key_print.3
gdoc_MANS += man/shishi_key_to_file.3
gdoc_MANS += man/shishi_encapreppart.3
gdoc_MANS += man/shishi_encapreppart_print.3
gdoc_MANS += man/shishi_encapreppart_save.3
gdoc_MANS += man/shishi_encapreppart_to_file.3
gdoc_MANS += man/shishi_encapreppart_parse.3
gdoc_MANS += man/shishi_encapreppart_read.3
gdoc_MANS += man/shishi_encapreppart_from_file.3
gdoc_MANS += man/shishi_encapreppart_get_key.3
gdoc_MANS += man/shishi_encapreppart_ctime.3
gdoc_MANS += man/shishi_encapreppart_ctime_set.3
gdoc_MANS += man/shishi_encapreppart_cusec_get.3
gdoc_MANS += man/shishi_encapreppart_cusec_set.3
gdoc_MANS += man/shishi_encapreppart_seqnumber_get.3
gdoc_MANS += man/shishi_encapreppart_seqnumber_remove.3
gdoc_MANS += man/shishi_encapreppart_seqnumber_set.3
gdoc_MANS += man/shishi_encapreppart_time_copy.3
gdoc_MANS += man/shishi_enckdcreppart_get_key.3
gdoc_MANS += man/shishi_enckdcreppart_key_set.3
gdoc_MANS += man/shishi_enckdcreppart_nonce_set.3
gdoc_MANS += man/shishi_enckdcreppart_flags_set.3
gdoc_MANS += man/shishi_enckdcreppart_authtime_set.3
gdoc_MANS += man/shishi_enckdcreppart_starttime_set.3
gdoc_MANS += man/shishi_enckdcreppart_endtime_set.3
gdoc_MANS += man/shishi_enckdcreppart_renew_till_set.3
gdoc_MANS += man/shishi_enckdcreppart_srealm_set.3
gdoc_MANS += man/shishi_enckdcreppart_sname_set.3
gdoc_MANS += man/shishi_enckdcreppart_populate_encticketpart.3
gdoc_MANS += man/shishi_encticketpart_get_key.3
gdoc_MANS += man/shishi_encticketpart_key_set.3
gdoc_MANS += man/shishi_encticketpart_flags_set.3
gdoc_MANS += man/shishi_encticketpart_crealm_set.3
gdoc_MANS += man/shishi_encticketpart_cname_set.3
gdoc_MANS += man/shishi_encticketpart_transited_set.3
gdoc_MANS += man/shishi_encticketpart_authtime_set.3
gdoc_MANS += man/shishi_encticketpart_endtime_set.3
gdoc_MANS += man/shishi_encticketpart_client.3
gdoc_MANS += man/shishi_encticketpart_clientrealm.3
gdoc_MANS += man/shishi_strerror.3
gdoc_MANS += man/shishi_error.3
gdoc_MANS += man/shishi_error_clear.3
gdoc_MANS += man/shishi_error_set.3
gdoc_MANS += man/shishi_error_printf.3
gdoc_MANS += man/shishi_error_outputtype.3
gdoc_MANS += man/shishi_error_set_outputtype.3
gdoc_MANS += man/shishi_info.3
gdoc_MANS += man/shishi_warn.3
gdoc_MANS += man/shishi_verbose.3
gdoc_MANS += man/shishi_generalize_time.3
gdoc_MANS += man/shishi_generalize_now.3
gdoc_MANS += man/shishi_generalize_ctime.3
gdoc_MANS += man/shishi_time.3
gdoc_MANS += man/shishi_ctime.3
gdoc_MANS += man/shishi_hostkeys_default_file.3
gdoc_MANS += man/shishi_hostkeys_default_file_set.3
gdoc_MANS += man/shishi_hostkeys_for_server.3
gdoc_MANS += man/shishi_hostkeys_for_serverrealm.3
gdoc_MANS += man/shishi_hostkeys_for_localservicerealm.3
gdoc_MANS += man/shishi_hostkeys_for_localservice.3
gdoc_MANS += man/shishi.3
gdoc_MANS += man/shishi_server.3
gdoc_MANS += man/shishi_done.3
gdoc_MANS += man/shishi_init.3
gdoc_MANS += man/shishi_init_with_paths.3
gdoc_MANS += man/shishi_init_server.3
gdoc_MANS += man/shishi_init_server_with_paths.3
gdoc_MANS += man/shishi_as_derive_salt.3
gdoc_MANS += man/shishi_kdc_copy_crealm.3
gdoc_MANS += man/shishi_as_check_crealm.3
gdoc_MANS += man/shishi_kdc_copy_cname.3
gdoc_MANS += man/shishi_as_check_cname.3
gdoc_MANS += man/shishi_kdc_copy_nonce.3
gdoc_MANS += man/shishi_kdc_check_nonce.3
gdoc_MANS += man/shishi_tgs_process.3
gdoc_MANS += man/shishi_as_process.3
gdoc_MANS += man/shishi_kdc_process.3
gdoc_MANS += man/shishi_asrep.3
gdoc_MANS += man/shishi_tgsrep.3
gdoc_MANS += man/shishi_kdcrep_print.3
gdoc_MANS += man/shishi_kdcrep_save.3
gdoc_MANS += man/shishi_kdcrep_to_file.3
gdoc_MANS += man/shishi_kdcrep_parse.3
gdoc_MANS += man/shishi_kdcrep_read.3
gdoc_MANS += man/shishi_kdcrep_from_file.3
gdoc_MANS += man/shishi_kdcrep_crealm_set.3
gdoc_MANS += man/shishi_kdcrep_cname_set.3
gdoc_MANS += man/shishi_kdcrep_client_set.3
gdoc_MANS += man/shishi_kdcrep_get_enc_part_etype.3
gdoc_MANS += man/shishi_kdcrep_get_ticket.3
gdoc_MANS += man/shishi_kdcrep_set_ticket.3
gdoc_MANS += man/shishi_kdcrep_set_enc_part.3
gdoc_MANS += man/shishi_kdcrep_add_enc_part.3
gdoc_MANS += man/shishi_kdcrep_clear_padata.3
gdoc_MANS += man/shishi_asreq.3
gdoc_MANS += man/shishi_tgsreq.3
gdoc_MANS += man/shishi_kdcreq_print.3
gdoc_MANS += man/shishi_kdcreq_save.3
gdoc_MANS += man/shishi_kdcreq_to_file.3
gdoc_MANS += man/shishi_kdcreq_parse.3
gdoc_MANS += man/shishi_kdcreq_read.3
gdoc_MANS += man/shishi_kdcreq_from_file.3
gdoc_MANS += man/shishi_kdcreq_nonce_set.3
gdoc_MANS += man/shishi_kdcreq_set_cname.3
gdoc_MANS += man/shishi_kdcreq_client.3
gdoc_MANS += man/shishi_asreq_clientrealm.3
gdoc_MANS += man/shishi_kdcreq_realm.3
gdoc_MANS += man/shishi_kdcreq_set_realm.3
gdoc_MANS += man/shishi_kdcreq_server.3
gdoc_MANS += man/shishi_kdcreq_set_sname.3
gdoc_MANS += man/shishi_kdcreq_till.3
gdoc_MANS += man/shishi_kdcreq_tillc.3
gdoc_MANS += man/shishi_kdcreq_etype.3
gdoc_MANS += man/shishi_kdcreq_set_etype.3
gdoc_MANS += man/shishi_kdcreq_options.3
gdoc_MANS += man/shishi_kdcreq_forwardable_p.3
gdoc_MANS += man/shishi_kdcreq_forwarded_p.3
gdoc_MANS += man/shishi_kdcreq_proxiable_p.3
gdoc_MANS += man/shishi_kdcreq_proxy_p.3
gdoc_MANS += man/shishi_kdcreq_allow_postdate_p.3
gdoc_MANS += man/shishi_kdcreq_postdated_p.3
gdoc_MANS += man/shishi_kdcreq_renewable_p.3
gdoc_MANS += man/shishi_kdcreq_disable_transited_check_p.3
gdoc_MANS += man/shishi_kdcreq_renewable_ok_p.3
gdoc_MANS += man/shishi_kdcreq_enc_tkt_in_skey_p.3
gdoc_MANS += man/shishi_kdcreq_renew_p.3
gdoc_MANS += man/shishi_kdcreq_validate_p.3
gdoc_MANS += man/shishi_kdcreq_options_set.3
gdoc_MANS += man/shishi_kdcreq_options_add.3
gdoc_MANS += man/shishi_kdcreq_clear_padata.3
gdoc_MANS += man/shishi_kdcreq_get_padata.3
gdoc_MANS += man/shishi_kdcreq_get_padata_tgs.3
gdoc_MANS += man/shishi_kdcreq_add_padata.3
gdoc_MANS += man/shishi_kdcreq_add_padata_tgs.3
gdoc_MANS += man/shishi_kdcreq_add_padata_preauth.3
gdoc_MANS += man/shishi_key_principal.3
gdoc_MANS += man/shishi_key_principal_set.3
gdoc_MANS += man/shishi_key_realm.3
gdoc_MANS += man/shishi_key_realm_set.3
gdoc_MANS += man/shishi_key_type.3
gdoc_MANS += man/shishi_key_type_set.3
gdoc_MANS += man/shishi_key_value.3
gdoc_MANS += man/shishi_key_value_set.3
gdoc_MANS += man/shishi_key_version.3
gdoc_MANS += man/shishi_key_version_set.3
gdoc_MANS += man/shishi_key_name.3
gdoc_MANS += man/shishi_key_length.3
gdoc_MANS += man/shishi_key.3
gdoc_MANS += man/shishi_key_done.3
gdoc_MANS += man/shishi_key_copy.3
gdoc_MANS += man/shishi_key_from_value.3
gdoc_MANS += man/shishi_key_from_base64.3
gdoc_MANS += man/shishi_key_random.3
gdoc_MANS += man/shishi_key_from_random.3
gdoc_MANS += man/shishi_key_from_string.3
gdoc_MANS += man/shishi_key_from_name.3
gdoc_MANS += man/shishi_keys.3
gdoc_MANS += man/shishi_keys_done.3
gdoc_MANS += man/shishi_keys_size.3
gdoc_MANS += man/shishi_keys_nth.3
gdoc_MANS += man/shishi_keys_remove.3
gdoc_MANS += man/shishi_keys_add.3
gdoc_MANS += man/shishi_keys_print.3
gdoc_MANS += man/shishi_keys_to_file.3
gdoc_MANS += man/shishi_keys_for_serverrealm_in_file.3
gdoc_MANS += man/shishi_keys_for_server_in_file.3
gdoc_MANS += man/shishi_keys_for_localservicerealm_in_file.3
gdoc_MANS += man/shishi_keys_add_keytab_mem.3
gdoc_MANS += man/shishi_keys_add_keytab_file.3
gdoc_MANS += man/shishi_keys_from_keytab_mem.3
gdoc_MANS += man/shishi_keys_from_keytab_file.3
gdoc_MANS += man/shishi_krberror.3
gdoc_MANS += man/shishi_krberror_print.3
gdoc_MANS += man/shishi_krberror_save.3
gdoc_MANS += man/shishi_krberror_to_file.3
gdoc_MANS += man/shishi_krberror_parse.3
gdoc_MANS += man/shishi_krberror_read.3
gdoc_MANS += man/shishi_krberror_from_file.3
gdoc_MANS += man/shishi_krberror_build.3
gdoc_MANS += man/shishi_krberror_der.3
gdoc_MANS += man/shishi_krberror_crealm.3
gdoc_MANS += man/shishi_krberror_remove_crealm.3
gdoc_MANS += man/shishi_krberror_set_crealm.3
gdoc_MANS += man/shishi_krberror_client.3
gdoc_MANS += man/shishi_krberror_set_cname.3
gdoc_MANS += man/shishi_krberror_remove_cname.3
gdoc_MANS += man/shishi_krberror_client_set.3
gdoc_MANS += man/shishi_krberror_realm.3
gdoc_MANS += man/shishi_krberror_set_realm.3
gdoc_MANS += man/shishi_krberror_server.3
gdoc_MANS += man/shishi_krberror_remove_sname.3
gdoc_MANS += man/shishi_krberror_set_sname.3
gdoc_MANS += man/shishi_krberror_server_set.3
gdoc_MANS += man/shishi_krberror_ctime.3
gdoc_MANS += man/shishi_krberror_ctime_set.3
gdoc_MANS += man/shishi_krberror_remove_ctime.3
gdoc_MANS += man/shishi_krberror_cusec.3
gdoc_MANS += man/shishi_krberror_cusec_set.3
gdoc_MANS += man/shishi_krberror_remove_cusec.3
gdoc_MANS += man/shishi_krberror_stime.3
gdoc_MANS += man/shishi_krberror_stime_set.3
gdoc_MANS += man/shishi_krberror_susec.3
gdoc_MANS += man/shishi_krberror_susec_set.3
gdoc_MANS += man/shishi_krberror_errorcode.3
gdoc_MANS += man/shishi_krberror_errorcode_fast.3
gdoc_MANS += man/shishi_krberror_errorcode_set.3
gdoc_MANS += man/shishi_krberror_etext.3
gdoc_MANS += man/shishi_krberror_set_etext.3
gdoc_MANS += man/shishi_krberror_remove_etext.3
gdoc_MANS += man/shishi_krberror_edata.3
gdoc_MANS += man/shishi_krberror_methoddata.3
gdoc_MANS += man/shishi_krberror_set_edata.3
gdoc_MANS += man/shishi_krberror_remove_edata.3
gdoc_MANS += man/shishi_krberror_pretty_print.3
gdoc_MANS += man/shishi_krberror_errorcode_message.3
gdoc_MANS += man/shishi_krberror_message.3
gdoc_MANS += man/shishi_randomize.3
gdoc_MANS += man/shishi_crc.3
gdoc_MANS += man/shishi_md4.3
gdoc_MANS += man/shishi_md5.3
gdoc_MANS += man/shishi_hmac_md5.3
gdoc_MANS += man/shishi_hmac_sha1.3
gdoc_MANS += man/shishi_des_cbc_mac.3
gdoc_MANS += man/shishi_arcfour.3
gdoc_MANS += man/shishi_des.3
gdoc_MANS += man/shishi_3des.3
gdoc_MANS += man/shishi_aes_cts.3
gdoc_MANS += man/shishi_pbkdf2_sha1.3
gdoc_MANS += man/shishi_prompt_password_callback_set.3
gdoc_MANS += man/shishi_prompt_password_callback_get.3
gdoc_MANS += man/shishi_prompt_password.3
gdoc_MANS += man/shishi_x509ca_default_file_guess.3
gdoc_MANS += man/shishi_x509ca_default_file_set.3
gdoc_MANS += man/shishi_x509ca_default_file.3
gdoc_MANS += man/shishi_x509cert_default_file_guess.3
gdoc_MANS += man/shishi_x509cert_default_file_set.3
gdoc_MANS += man/shishi_x509cert_default_file.3
gdoc_MANS += man/shishi_x509key_default_file_guess.3
gdoc_MANS += man/shishi_x509key_default_file_set.3
gdoc_MANS += man/shishi_x509key_default_file.3
gdoc_MANS += man/shishi_principal_default_guess.3
gdoc_MANS += man/shishi_principal_default.3
gdoc_MANS += man/shishi_principal_default_set.3
gdoc_MANS += man/shishi_parse_name.3
gdoc_MANS += man/shishi_principal_name.3
gdoc_MANS += man/shishi_principal_name_realm.3
gdoc_MANS += man/shishi_principal_name_set.3
gdoc_MANS += man/shishi_principal_set.3
gdoc_MANS += man/shishi_derive_default_salt.3
gdoc_MANS += man/shishi_server_for_local_service.3
gdoc_MANS += man/shishi_priv.3
gdoc_MANS += man/shishi_priv_done.3
gdoc_MANS += man/shishi_priv_key.3
gdoc_MANS += man/shishi_priv_key_set.3
gdoc_MANS += man/shishi_priv_priv.3
gdoc_MANS += man/shishi_priv_priv_set.3
gdoc_MANS += man/shishi_priv_priv_der.3
gdoc_MANS += man/shishi_priv_priv_der_set.3
gdoc_MANS += man/shishi_priv_encprivpart.3
gdoc_MANS += man/shishi_priv_encprivpart_set.3
gdoc_MANS += man/shishi_priv_encprivpart_der.3
gdoc_MANS += man/shishi_priv_encprivpart_der_set.3
gdoc_MANS += man/shishi_priv_print.3
gdoc_MANS += man/shishi_priv_save.3
gdoc_MANS += man/shishi_priv_to_file.3
gdoc_MANS += man/shishi_priv_parse.3
gdoc_MANS += man/shishi_priv_read.3
gdoc_MANS += man/shishi_priv_from_file.3
gdoc_MANS += man/shishi_priv_enc_part_etype.3
gdoc_MANS += man/shishi_priv_set_enc_part.3
gdoc_MANS += man/shishi_encprivpart_user_data.3
gdoc_MANS += man/shishi_encprivpart_set_user_data.3
gdoc_MANS += man/shishi_priv_build.3
gdoc_MANS += man/shishi_priv_process.3
gdoc_MANS += man/shishi_realm_default_guess.3
gdoc_MANS += man/shishi_realm_default.3
gdoc_MANS += man/shishi_realm_default_set.3
gdoc_MANS += man/shishi_realm_for_server_file.3
gdoc_MANS += man/shishi_realm_for_server_dns.3
gdoc_MANS += man/shishi_realm_for_server.3
gdoc_MANS += man/shishi_resolv.3
gdoc_MANS += man/shishi_resolv_free.3
gdoc_MANS += man/shishi_safe.3
gdoc_MANS += man/shishi_safe_done.3
gdoc_MANS += man/shishi_safe_key.3
gdoc_MANS += man/shishi_safe_key_set.3
gdoc_MANS += man/shishi_safe_safe.3
gdoc_MANS += man/shishi_safe_safe_set.3
gdoc_MANS += man/shishi_safe_safe_der.3
gdoc_MANS += man/shishi_safe_safe_der_set.3
gdoc_MANS += man/shishi_safe_print.3
gdoc_MANS += man/shishi_safe_save.3
gdoc_MANS += man/shishi_safe_to_file.3
gdoc_MANS += man/shishi_safe_parse.3
gdoc_MANS += man/shishi_safe_read.3
gdoc_MANS += man/shishi_safe_from_file.3
gdoc_MANS += man/shishi_safe_cksum.3
gdoc_MANS += man/shishi_safe_set_cksum.3
gdoc_MANS += man/shishi_safe_user_data.3
gdoc_MANS += man/shishi_safe_set_user_data.3
gdoc_MANS += man/shishi_safe_build.3
gdoc_MANS += man/shishi_safe_verify.3
gdoc_MANS += man/shishi_tgs.3
gdoc_MANS += man/shishi_tgs_done.3
gdoc_MANS += man/shishi_tgs_tgtkt.3
gdoc_MANS += man/shishi_tgs_tgtkt_set.3
gdoc_MANS += man/shishi_tgs_ap.3
gdoc_MANS += man/shishi_tgs_req.3
gdoc_MANS += man/shishi_tgs_req_set.3
gdoc_MANS += man/shishi_tgs_req_der.3
gdoc_MANS += man/shishi_tgs_req_der_set.3
gdoc_MANS += man/shishi_tgs_req_process.3
gdoc_MANS += man/shishi_tgs_req_build.3
gdoc_MANS += man/shishi_tgs_rep.3
gdoc_MANS += man/shishi_tgs_rep_der.3
gdoc_MANS += man/shishi_tgs_rep_process.3
gdoc_MANS += man/shishi_tgs_rep_build.3
gdoc_MANS += man/shishi_tgs_krberror.3
gdoc_MANS += man/shishi_tgs_krberror_der.3
gdoc_MANS += man/shishi_tgs_krberror_set.3
gdoc_MANS += man/shishi_tgs_tkt.3
gdoc_MANS += man/shishi_tgs_tkt_set.3
gdoc_MANS += man/shishi_tgs_sendrecv_hint.3
gdoc_MANS += man/shishi_tgs_sendrecv.3
gdoc_MANS += man/shishi_tgs_set_server.3
gdoc_MANS += man/shishi_tgs_set_realm.3
gdoc_MANS += man/shishi_tgs_set_realmserver.3
gdoc_MANS += man/shishi_ticket.3
gdoc_MANS += man/shishi_ticket_realm_get.3
gdoc_MANS += man/shishi_ticket_realm_set.3
gdoc_MANS += man/shishi_ticket_server.3
gdoc_MANS += man/shishi_ticket_sname_set.3
gdoc_MANS += man/shishi_ticket_get_enc_part_etype.3
gdoc_MANS += man/shishi_ticket_set_enc_part.3
gdoc_MANS += man/shishi_ticket_add_enc_part.3
gdoc_MANS += man/shishi_tkt.3
gdoc_MANS += man/shishi_tkt2.3
gdoc_MANS += man/shishi_tkt_done.3
gdoc_MANS += man/shishi_tkt_ticket.3
gdoc_MANS += man/shishi_tkt_ticket_set.3
gdoc_MANS += man/shishi_tkt_enckdcreppart.3
gdoc_MANS += man/shishi_tkt_enckdcreppart_set.3
gdoc_MANS += man/shishi_tkt_kdcrep.3
gdoc_MANS += man/shishi_tkt_encticketpart.3
gdoc_MANS += man/shishi_tkt_encticketpart_set.3
gdoc_MANS += man/shishi_tkt_key.3
gdoc_MANS += man/shishi_tkt_key_set.3
gdoc_MANS += man/shishi_tkt_client.3
gdoc_MANS += man/shishi_tkt_client_p.3
gdoc_MANS += man/shishi_tkt_clientrealm.3
gdoc_MANS += man/shishi_tkt_clientrealm_p.3
gdoc_MANS += man/shishi_tkt_realm.3
gdoc_MANS += man/shishi_tkt_server.3
gdoc_MANS += man/shishi_tkt_server_p.3
gdoc_MANS += man/shishi_tkt_flags.3
gdoc_MANS += man/shishi_tkt_flags_set.3
gdoc_MANS += man/shishi_tkt_flags_add.3
gdoc_MANS += man/shishi_tkt_forwardable_p.3
gdoc_MANS += man/shishi_tkt_forwarded_p.3
gdoc_MANS += man/shishi_tkt_proxiable_p.3
gdoc_MANS += man/shishi_tkt_proxy_p.3
gdoc_MANS += man/shishi_tkt_may_postdate_p.3
gdoc_MANS += man/shishi_tkt_postdated_p.3
gdoc_MANS += man/shishi_tkt_invalid_p.3
gdoc_MANS += man/shishi_tkt_renewable_p.3
gdoc_MANS += man/shishi_tkt_initial_p.3
gdoc_MANS += man/shishi_tkt_pre_authent_p.3
gdoc_MANS += man/shishi_tkt_hw_authent_p.3
gdoc_MANS += man/shishi_tkt_transited_policy_checked_p.3
gdoc_MANS += man/shishi_tkt_ok_as_delegate_p.3
gdoc_MANS += man/shishi_tkt_keytype.3
gdoc_MANS += man/shishi_tkt_keytype_fast.3
gdoc_MANS += man/shishi_tkt_keytype_p.3
gdoc_MANS += man/shishi_tkt_lastreqc.3
gdoc_MANS += man/shishi_tkt_authctime.3
gdoc_MANS += man/shishi_tkt_startctime.3
gdoc_MANS += man/shishi_tkt_endctime.3
gdoc_MANS += man/shishi_tkt_renew_tillc.3
gdoc_MANS += man/shishi_tkt_valid_at_time_p.3
gdoc_MANS += man/shishi_tkt_valid_now_p.3
gdoc_MANS += man/shishi_tkt_expired_p.3
gdoc_MANS += man/shishi_tkt_lastreq_pretty_print.3
gdoc_MANS += man/shishi_tkt_pretty_print.3
gdoc_MANS += man/shishi_tkts_default_ccache_guess.3
gdoc_MANS += man/shishi_tkts_default_ccache.3
gdoc_MANS += man/shishi_tkts_default_ccache_set.3
gdoc_MANS += man/shishi_tkts_add_ccache_mem.3
gdoc_MANS += man/shishi_tkts_add_ccache_file.3
gdoc_MANS += man/shishi_tkts_from_ccache_mem.3
gdoc_MANS += man/shishi_tkts_from_ccache_file.3
gdoc_MANS += man/shishi_tkts_default_file_guess.3
gdoc_MANS += man/shishi_tkts_default_file.3
gdoc_MANS += man/shishi_tkts_default_file_set.3
gdoc_MANS += man/shishi_tkts_default.3
gdoc_MANS += man/shishi_tkts.3
gdoc_MANS += man/shishi_tkts_done.3
gdoc_MANS += man/shishi_tkts_size.3
gdoc_MANS += man/shishi_tkts_nth.3
gdoc_MANS += man/shishi_tkts_remove.3
gdoc_MANS += man/shishi_tkts_add.3
gdoc_MANS += man/shishi_tkts_new.3
gdoc_MANS += man/shishi_tkts_read.3
gdoc_MANS += man/shishi_tkts_from_file.3
gdoc_MANS += man/shishi_tkts_write.3
gdoc_MANS += man/shishi_tkts_expire.3
gdoc_MANS += man/shishi_tkts_to_file.3
gdoc_MANS += man/shishi_tkts_print_for_service.3
gdoc_MANS += man/shishi_tkts_print.3
gdoc_MANS += man/shishi_tkt_match_p.3
gdoc_MANS += man/shishi_tkts_find.3
gdoc_MANS += man/shishi_tkts_find_for_clientserver.3
gdoc_MANS += man/shishi_tkts_find_for_server.3
gdoc_MANS += man/shishi_tkts_get_tgt.3
gdoc_MANS += man/shishi_tkts_get_tgs.3
gdoc_MANS += man/shishi_tkts_get.3
gdoc_MANS += man/shishi_tkts_get_for_clientserver.3
gdoc_MANS += man/shishi_tkts_get_for_server.3
gdoc_MANS += man/shishi_check_version.3
gdoc_MANS += man/shisa_cfg_db.3
gdoc_MANS += man/shisa_cfg.3
gdoc_MANS += man/shisa_cfg_from_file.3
gdoc_MANS += man/shisa_cfg_default_systemfile.3
gdoc_MANS += man/shisa_enumerate_realms.3
gdoc_MANS += man/shisa_enumerate_principals.3
gdoc_MANS += man/shisa_principal_find.3
gdoc_MANS += man/shisa_principal_update.3
gdoc_MANS += man/shisa_principal_add.3
gdoc_MANS += man/shisa_principal_remove.3
gdoc_MANS += man/shisa_keys_find.3
gdoc_MANS += man/shisa_key_add.3
gdoc_MANS += man/shisa_key_update.3
gdoc_MANS += man/shisa_key_remove.3
gdoc_MANS += man/shisa_key_free.3
gdoc_MANS += man/shisa_keys_free.3
gdoc_MANS += man/shisa_strerror.3
gdoc_MANS += man/shisa_info.3
gdoc_MANS += man/shisa.3
gdoc_MANS += man/shisa_done.3
gdoc_MANS += man/shisa_init.3
gdoc_MANS += man/shisa_init_with_paths.3
gdoc_TEXINFOS =
gdoc_TEXINFOS += texi/ap.c.texi
gdoc_TEXINFOS += texi/aprep.c.texi
gdoc_TEXINFOS += texi/apreq.c.texi
gdoc_TEXINFOS += texi/as.c.texi
gdoc_TEXINFOS += texi/asn1.c.texi
gdoc_TEXINFOS += texi/authenticator.c.texi
gdoc_TEXINFOS += texi/authorize.c.texi
gdoc_TEXINFOS += texi/ccache.c.texi
gdoc_TEXINFOS += texi/cfg.c.texi
gdoc_TEXINFOS += texi/crypto-3des.c.texi
gdoc_TEXINFOS += texi/crypto-aes.c.texi
gdoc_TEXINFOS += texi/crypto-ctx.c.texi
gdoc_TEXINFOS += texi/crypto-des.c.texi
gdoc_TEXINFOS += texi/crypto-md.c.texi
gdoc_TEXINFOS += texi/crypto-null.c.texi
gdoc_TEXINFOS += texi/crypto-rc4.c.texi
gdoc_TEXINFOS += texi/crypto.c.texi
gdoc_TEXINFOS += texi/diskio.c.texi
gdoc_TEXINFOS += texi/encapreppart.c.texi
gdoc_TEXINFOS += texi/enckdcreppart.c.texi
gdoc_TEXINFOS += texi/encticketpart.c.texi
gdoc_TEXINFOS += texi/error.c.texi
gdoc_TEXINFOS += texi/gztime.c.texi
gdoc_TEXINFOS += texi/hostkeys.c.texi
gdoc_TEXINFOS += texi/init.c.texi
gdoc_TEXINFOS += texi/kdc.c.texi
gdoc_TEXINFOS += texi/kdcrep.c.texi
gdoc_TEXINFOS += texi/kdcreq.c.texi
gdoc_TEXINFOS += texi/kerberos5.c.texi
gdoc_TEXINFOS += texi/key.c.texi
gdoc_TEXINFOS += texi/keys.c.texi
gdoc_TEXINFOS += texi/keytab.c.texi
gdoc_TEXINFOS += texi/krberror.c.texi
gdoc_TEXINFOS += texi/low-crypto.c.texi
gdoc_TEXINFOS += texi/netio.c.texi
gdoc_TEXINFOS += texi/password.c.texi
gdoc_TEXINFOS += texi/pki.c.texi
gdoc_TEXINFOS += texi/principal.c.texi
gdoc_TEXINFOS += texi/priv.c.texi
gdoc_TEXINFOS += texi/realm.c.texi
gdoc_TEXINFOS += texi/resolv.c.texi
gdoc_TEXINFOS += texi/safe.c.texi
gdoc_TEXINFOS += texi/starttls.c.texi
gdoc_TEXINFOS += texi/tgs.c.texi
gdoc_TEXINFOS += texi/ticket.c.texi
gdoc_TEXINFOS += texi/tkt.c.texi
gdoc_TEXINFOS += texi/tktccache.c.texi
gdoc_TEXINFOS += texi/tkts.c.texi
gdoc_TEXINFOS += texi/utils.c.texi
gdoc_TEXINFOS += texi/version.c.texi
gdoc_TEXINFOS += texi/config.c.texi
gdoc_TEXINFOS += texi/core.c.texi
gdoc_TEXINFOS += texi/db.c.texi
gdoc_TEXINFOS += texi/err.c.texi
gdoc_TEXINFOS += texi/file.c.texi
gdoc_TEXINFOS += texi/fileutil.c.texi
gdoc_TEXINFOS += texi/setup.c.texi

$(gdoc_MANS) $(gdoc_TEXINFOS):
	make update-makefile
	make Makefile
	make doit

GDOC_SRC = $(top_srcdir)/lib/*.c $(top_srcdir)/db/*.c

update-makefile:
	MANS=""; \
	TEXINFOS=""; \
	for i in $(GDOC_SRC); do \
		BASE=`basename $$i`; \
		TEXINFOS="$$TEXINFOS\ngdoc_TEXINFOS += texi/$$BASE.texi"; \
	done; \
	FUNCS=`./gdoc -listfunc $(GDOC_SRC)`; \
	for i in $$FUNCS; do \
		MANS="$$MANS\ngdoc_MANS += man/$$i.3"; \
	done; \
	grep -v -e '^gdoc_MANS += ' -e '^gdoc_TEXINFOS += ' Makefile.am | \
		perl -p -e "s,^gdoc_MANS =,gdoc_MANS =$$MANS," | \
		perl -p -e "s,^gdoc_TEXINFOS =,gdoc_TEXINFOS =$$TEXINFOS,;" \
		> Makefile.am.new && \
	mv Makefile.am.new Makefile.am

doit:
	@$(mkdir_p) man texi; \
	echo -n "Creating function documentation" && \
	for i in `./gdoc -listfunc $(GDOC_SRC)`; do \
		./gdoc -man \
			-module $(PACKAGE) -sourceversion $(VERSION) \
			-bugsto $(PACKAGE_BUGREPORT) \
			-includefuncprefix \
			-seeinfo $(PACKAGE) -verbatimcopying \
			-copyright "2002-2008 Simon Josefsson" \
			-function $$i \
			$(GDOC_SRC) >> man/$$i.3 && \
		echo -n "."; \
	done; \
	echo ""; \
	echo -n "Creating file documentation" && \
	for i in $(GDOC_SRC); do \
		BASE=`basename $$i`; \
		./gdoc -texinfo $$i >> texi/$$BASE.texi && \
		echo -n "."; \
	done; \
	echo ""

.PHONY: update-makefile doit
