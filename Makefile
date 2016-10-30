#################################################
#          IncludeOS SERVICE makefile           #
#################################################

# The name of your service
SERVICE = IncludeOS_service
SERVICE_NAME = My IncludeOS Service

# Your service parts
FILES = empty.cpp

# Your disk image
DISK=

# Additional drivers (virtionet, virtioblk etc)
DRIVERS=virtionet

#-whole-archive infinit/lib/libinfinit.a -no-whole-archive
#	  infinit/elle/cryptography/lib/libcryptography.a \
#	  infinit/elle/protocol/lib/libprotocol.a \
#-whole-archive infinit/elle/reactor/lib/libreactor.a --no-whole-archive \
# -whole-archive infinit/elle/elle/lib/libelle.a -no-whole-archive\ 
#	  infinit/elle/reactor/lib/libreactor.a \
#	  infinit/elle/reactor/libutp/lib/libutp.a \
#	  infinit/elle/reactor/lib/reactor/libbackend_boost_context.a \
#	  infinit/elle/reactor/lib/reactor/libbackend.a \
#	  infinit/elle/openssl/lib/libssl.a \
#	  infinit/elle/openssl/lib/libcrypto.a \

# 2.7M : ok
# 5,2M/sock : bad
# 4.4M: bad
EXTRA_LIBS =  \
    -whole-archive infinit/lib/libinfinit.a -no-whole-archive \
    -whole-archive infinit/elle/cryptography/lib/libcryptography.a -no-whole-archive \
    infinit/elle/protocol/lib/libprotocol.a \
    -whole-archive infinit/elle/reactor/lib/libreactor.a -no-whole-archive \
    infinit/elle/reactor/libutp/lib/libutp.a \
	  infinit/elle/reactor/lib/reactor/libbackend_boost_context.a \
	  infinit/elle/reactor/lib/reactor/libbackend.a \
    infinit/elle/elle/lib/libelle.a \
	  infinit/elle/boost/1.60.0/lib/libboost_system.a \
	  infinit/elle/boost/1.60.0/lib/libboost_filesystem.a \
	  infinit/elle/boost/1.60.0/lib/libboost_context.a \
	  infinit/elle/openssl/lib/libssl.a \
	  infinit/elle/openssl/lib/libcrypto.a \
	  
	  #ssl/a_bitstr.o ssl/a_bool.o ssl/a_bytes.o ssl/a_d2i_fp.o ssl/a_digest.o ssl/a_dup.o ssl/a_enum.o ssl/aes_cbc.o ssl/aes_cfb.o ssl/aes_core.o ssl/aes_ctr.o ssl/aes_ecb.o ssl/aes_ige.o ssl/aes_misc.o ssl/aes_ofb.o ssl/aes_wrap.o ssl/a_gentm.o ssl/a_i2d_fp.o ssl/a_int.o ssl/a_mbstr.o ssl/ameth_lib.o ssl/a_object.o ssl/a_octet.o ssl/a_print.o ssl/a_set.o ssl/a_sign.o ssl/asn1_err.o ssl/asn1_gen.o ssl/asn1_lib.o ssl/asn1_par.o ssl/asn_mime.o ssl/asn_moid.o ssl/asn_pack.o ssl/a_strex.o ssl/a_strnid.o ssl/a_time.o ssl/a_type.o ssl/a_utctm.o ssl/a_utf8.o ssl/a_verify.o ssl/b_dump.o ssl/bf_buff.o ssl/bf_cfb64.o ssl/bf_ecb.o ssl/bf_enc.o ssl/bf_nbio.o ssl/bf_null.o ssl/bf_ofb64.o ssl/bf_skey.o ssl/bio_asn1.o ssl/bio_b64.o ssl/bio_cb.o ssl/bio_enc.o ssl/bio_err.o ssl/bio_lib.o ssl/bio_md.o ssl/bio_ndef.o ssl/bio_ok.o ssl/bio_pk7.o ssl/bio_ssl.o ssl/bn_add.o ssl/bn_asm.o ssl/bn_blind.o ssl/bn_const.o ssl/bn_ctx.o ssl/bn_depr.o ssl/bn_div.o ssl/bn_err.o ssl/bn_exp2.o ssl/bn_exp.o ssl/bn_gcd.o ssl/bn_gf2m.o ssl/bn_kron.o ssl/bn_lib.o ssl/bn_mod.o ssl/bn_mont.o ssl/bn_mpi.o ssl/bn_mul.o ssl/bn_nist.o ssl/bn_prime.o ssl/bn_print.o ssl/bn_rand.o ssl/bn_recp.o ssl/bn_shift.o ssl/bn_sqr.o ssl/bn_sqrt.o ssl/bn_word.o ssl/bn_x931p.o ssl/b_print.o ssl/b_sock.o ssl/bss_acpt.o ssl/bss_bio.o ssl/bss_conn.o ssl/bss_dgram.o ssl/bss_fd.o ssl/bss_file.o ssl/bss_log.o ssl/bss_mem.o ssl/bss_null.o ssl/bss_sock.o ssl/buf_err.o ssl/buffer.o ssl/buf_str.o ssl/by_dir.o ssl/by_file.o ssl/c_allc.o ssl/c_alld.o ssl/c_all.o ssl/camellia.o ssl/cbc128.o ssl/cbc_cksm.o ssl/cbc_enc.o ssl/c_cfb64.o ssl/ccm128.o ssl/c_ecb.o ssl/c_enc.o ssl/cfb128.o ssl/cfb64ede.o ssl/cfb64enc.o ssl/cfb_enc.o ssl/cmac.o ssl/cm_ameth.o ssl/cmll_cbc.o ssl/cmll_cfb.o ssl/cmll_ctr.o ssl/cmll_ecb.o ssl/cmll_misc.o ssl/cmll_ofb.o ssl/cmll_utl.o ssl/cm_pmeth.o ssl/cms_asn1.o ssl/cms_att.o ssl/cms_cd.o ssl/cms_dd.o ssl/cms_enc.o ssl/cms_env.o ssl/cms_err.o ssl/cms_ess.o ssl/cms_io.o ssl/cms_kari.o ssl/cms_lib.o ssl/cms_pwri.o ssl/cms_sd.o ssl/cms_smime.o ssl/c_ofb64.o ssl/comp_err.o ssl/comp_lib.o ssl/conf_api.o ssl/conf_def.o ssl/conf_err.o ssl/conf_lib.o ssl/conf_mall.o ssl/conf_mod.o ssl/conf_sap.o ssl/cpt_err.o ssl/c_rle.o ssl/cryptlib.o ssl/c_skey.o ssl/ctr128.o ssl/cts128.o ssl/cversion.o ssl/c_zlib.o ssl/d1_both.o ssl/d1_clnt.o ssl/d1_lib.o ssl/d1_meth.o ssl/d1_pkt.o ssl/d1_srtp.o ssl/d1_srvr.o ssl/d2i_pr.o ssl/d2i_pu.o ssl/des_enc.o ssl/des_old2.o ssl/des_old.o ssl/dh_ameth.o ssl/dh_asn1.o ssl/dh_check.o ssl/dh_depr.o ssl/dh_err.o ssl/dh_gen.o ssl/dh_kdf.o ssl/dh_key.o ssl/dh_lib.o ssl/dh_pmeth.o ssl/dh_prn.o ssl/dh_rfc5114.o ssl/digest.o ssl/dsa_ameth.o ssl/dsa_asn1.o ssl/dsa_depr.o ssl/dsa_err.o ssl/dsa_gen.o ssl/dsa_key.o ssl/dsa_lib.o ssl/dsa_ossl.o ssl/dsa_pmeth.o ssl/dsa_prn.o ssl/dsa_sign.o ssl/dsa_vrf.o ssl/dso_beos.o ssl/dso_dlfcn.o ssl/dso_dl.o ssl/dso_err.o ssl/dso_lib.o ssl/dso_null.o ssl/dso_openssl.o ssl/dso_vms.o ssl/dso_win32.o ssl/e_4758cca.o ssl/e_aep.o ssl/e_aes_cbc_hmac_sha1.o ssl/e_aes_cbc_hmac_sha256.o ssl/e_aes.o ssl/e_atalla.o ssl/ebcdic.o ssl/e_bf.o ssl/ec2_mult.o ssl/ec2_oct.o ssl/ec2_smpl.o ssl/e_camellia.o ssl/ec_ameth.o ssl/e_capi.o ssl/ec_asn1.o ssl/e_cast.o ssl/ecb3_enc.o ssl/ecb_enc.o ssl/ec_check.o ssl/ec_curve.o ssl/ec_cvt.o ssl/ec_err.o ssl/ech_err.o ssl/e_chil.o ssl/ech_kdf.o ssl/ech_key.o ssl/ech_lib.o ssl/ech_ossl.o ssl/ec_key.o ssl/eck_prn.o ssl/ec_lib.o ssl/ec_mult.o ssl/ec_oct.o ssl/ec_pmeth.o ssl/ecp_mont.o ssl/ecp_nist.o ssl/ecp_nistp224.o ssl/ecp_nistp256.o ssl/ecp_nistp521.o ssl/ecp_nistputil.o ssl/ecp_oct.o ssl/ec_print.o ssl/ecp_smpl.o ssl/ecs_asn1.o ssl/ecs_err.o ssl/ecs_lib.o ssl/ecs_ossl.o ssl/ecs_sign.o ssl/ecs_vrf.o ssl/e_cswift.o ssl/ede_cbcm_enc.o ssl/e_des3.o ssl/e_des.o ssl/e_gmp.o ssl/e_gost_err.o ssl/e_idea.o ssl/encode.o ssl/enc_read.o ssl/enc_writ.o ssl/eng_all.o ssl/eng_cnf.o ssl/eng_cryptodev.o ssl/eng_ctrl.o ssl/eng_dyn.o ssl/eng_err.o ssl/eng_fat.o ssl/eng_init.o ssl/eng_lib.o ssl/eng_list.o ssl/eng_openssl.o ssl/eng_pkey.o ssl/eng_rdrand.o ssl/eng_table.o ssl/e_null.o ssl/e_nuron.o ssl/e_old.o ssl/e_padlock.o ssl/e_rc2.o ssl/e_rc4_hmac_md5.o ssl/e_rc4.o ssl/e_rc5.o ssl/err_all.o ssl/err.o ssl/err_prn.o ssl/e_seed.o ssl/e_sureware.o ssl/e_ubsec.o ssl/evp_acnf.o ssl/evp_asn1.o ssl/evp_cnf.o ssl/evp_enc.o ssl/evp_err.o ssl/evp_key.o ssl/evp_lib.o ssl/evp_pbe.o ssl/evp_pkey.o ssl/e_xcbc_d.o ssl/ex_data.o ssl/fcrypt_b.o ssl/fcrypt.o ssl/f_enum.o ssl/f_int.o ssl/fips_ers.o ssl/f_string.o ssl/gcm128.o ssl/gost2001_keyx.o ssl/gost2001.o ssl/gost89.o ssl/gost94_keyx.o ssl/gost_ameth.o ssl/gost_asn1.o ssl/gost_crypt.o ssl/gost_ctl.o ssl/gost_eng.o ssl/gosthash.o ssl/gost_keywrap.o ssl/gost_md.o ssl/gost_params.o ssl/gost_pmeth.o ssl/gost_sign.o ssl/hmac.o ssl/hm_ameth.o ssl/hm_pmeth.o ssl/i2d_pr.o ssl/i2d_pu.o ssl/i_cbc.o ssl/i_cfb64.o ssl/i_ecb.o ssl/i_ofb64.o ssl/i_skey.o ssl/krb5_asn.o ssl/kssl.o ssl/lhash.o ssl/lh_stats.o ssl/md4_dgst.o ssl/md4_one.o ssl/md5_dgst.o ssl/md5_one.o ssl/mdc2dgst.o ssl/mdc2_one.o ssl/md_rand.o ssl/m_dss1.o ssl/m_dss.o ssl/m_ecdsa.o ssl/mem_clr.o ssl/mem_dbg.o ssl/mem.o ssl/m_md2.o ssl/m_md4.o ssl/m_md5.o ssl/m_mdc2.o ssl/m_null.o ssl/m_ripemd.o ssl/m_sha1.o ssl/m_sha.o ssl/m_sigver.o ssl/m_wp.o ssl/names.o ssl/n_pkey.o ssl/nsseq.o ssl/obj_dat.o ssl/obj_err.o ssl/obj_lib.o ssl/obj_xref.o ssl/ocsp_asn.o ssl/ocsp_cl.o ssl/ocsp_err.o ssl/ocsp_ext.o ssl/ocsp_ht.o ssl/ocsp_lib.o ssl/ocsp_prn.o ssl/ocsp_srv.o ssl/ocsp_vfy.o ssl/o_dir.o ssl/ofb128.o ssl/ofb64ede.o ssl/ofb64enc.o ssl/ofb_enc.o ssl/o_fips.o ssl/o_init.o ssl/o_names.o ssl/o_str.o ssl/o_time.o ssl/p12_add.o ssl/p12_asn.o ssl/p12_attr.o ssl/p12_crpt.o ssl/p12_crt.o ssl/p12_decr.o ssl/p12_init.o ssl/p12_key.o ssl/p12_kiss.o ssl/p12_mutl.o ssl/p12_npas.o ssl/p12_p8d.o ssl/p12_p8e.o ssl/p12_utl.o ssl/p5_crpt2.o ssl/p5_crpt.o ssl/p5_pbe.o ssl/p5_pbev2.o ssl/p8_pkey.o ssl/pcbc_enc.o ssl/pcy_cache.o ssl/pcy_data.o ssl/pcy_lib.o ssl/pcy_map.o ssl/pcy_node.o ssl/pcy_tree.o ssl/p_dec.o ssl/pem_all.o ssl/pem_err.o ssl/pem_info.o ssl/pem_lib.o ssl/pem_oth.o ssl/pem_pk8.o ssl/pem_pkey.o ssl/pem_seal.o ssl/pem_sign.o ssl/pem_x509.o ssl/pem_xaux.o ssl/p_enc.o ssl/pk12err.o ssl/pk7_asn1.o ssl/pk7_attr.o ssl/pk7_doit.o ssl/pk7_lib.o ssl/pk7_mime.o ssl/pk7_smime.o ssl/pkcs7err.o ssl/p_lib.o ssl/pmeth_fn.o ssl/pmeth_gn.o ssl/pmeth_lib.o ssl/p_open.o ssl/pqueue.o ssl/p_seal.o ssl/p_sign.o ssl/p_verify.o ssl/pvkfmt.o ssl/qud_cksm.o ssl/rand_egd.o ssl/rand_err.o ssl/randfile.o ssl/rand_key.o ssl/rand_lib.o ssl/rand_nw.o ssl/rand_os2.o ssl/rand_unix.o ssl/rand_win.o ssl/rc2_cbc.o ssl/rc2cfb64.o ssl/rc2_ecb.o ssl/rc2ofb64.o ssl/rc2_skey.o ssl/rc4_enc.o ssl/rc4_skey.o ssl/rc4_utl.o ssl/read2pwd.o ssl/rmd_dgst.o ssl/rmd_one.o ssl/rpc_enc.o ssl/rsa_ameth.o ssl/rsa_asn1.o ssl/rsa_chk.o ssl/rsa_crpt.o ssl/rsa_depr.o ssl/rsa_eay.o ssl/rsa_err.o ssl/rsa_gen.o ssl/rsa_lib.o ssl/rsa_none.o ssl/rsa_null.o ssl/rsa_oaep.o ssl/rsa_pk1.o ssl/rsa_pmeth.o ssl/rsa_prn.o ssl/rsa_pss.o ssl/rsa_saos.o ssl/rsa_sign.o ssl/rsa_ssl.o ssl/rsa_x931.o ssl/s23_clnt.o ssl/s23_lib.o ssl/s23_meth.o ssl/s23_pkt.o ssl/s23_srvr.o ssl/s2_clnt.o ssl/s2_enc.o ssl/s2_lib.o ssl/s2_meth.o ssl/s2_pkt.o ssl/s2_srvr.o ssl/s3_both.o ssl/s3_cbc.o ssl/s3_clnt.o ssl/s3_enc.o ssl/s3_lib.o ssl/s3_meth.o ssl/s3_pkt.o ssl/s3_srvr.o ssl/seed_cbc.o ssl/seed_cfb.o ssl/seed_ecb.o ssl/seed.o ssl/seed_ofb.o ssl/set_key.o ssl/sha1dgst.o ssl/sha1_one.o ssl/sha256.o ssl/sha512.o ssl/sha_dgst.o ssl/sha_one.o ssl/srp_lib.o ssl/srp_vfy.o ssl/ssl_algs.o ssl/ssl_asn1.o ssl/ssl_cert.o ssl/ssl_ciph.o ssl/ssl_conf.o ssl/ssl_err2.o ssl/ssl_err.o ssl/ssl_lib.o ssl/ssl_rsa.o ssl/ssl_sess.o ssl/ssl_stat.o ssl/ssl_txt.o ssl/ssl_utst.o ssl/stack.o ssl/str2key.o ssl/t1_clnt.o ssl/t1_enc.o ssl/t1_ext.o ssl/t1_lib.o ssl/t1_meth.o ssl/t1_reneg.o ssl/t1_srvr.o ssl/t1_trce.o ssl/tasn_dec.o ssl/tasn_enc.o ssl/tasn_fre.o ssl/tasn_new.o ssl/tasn_prn.o ssl/tasn_typ.o ssl/tasn_utl.o ssl/tb_asnmth.o ssl/tb_cipher.o ssl/tb_dh.o ssl/tb_digest.o ssl/tb_dsa.o ssl/tb_ecdh.o ssl/tb_ecdsa.o ssl/t_bitst.o ssl/tb_pkmeth.o ssl/tb_rand.o ssl/tb_rsa.o ssl/tb_store.o ssl/t_crl.o ssl/tls_srp.o ssl/t_pkey.o ssl/t_req.o ssl/ts_asn1.o ssl/ts_conf.o ssl/ts_err.o ssl/ts_lib.o ssl/t_spki.o ssl/ts_req_print.o ssl/ts_req_utils.o ssl/ts_rsp_print.o ssl/ts_rsp_sign.o ssl/ts_rsp_utils.o ssl/ts_rsp_verify.o ssl/ts_verify_ctx.o ssl/t_x509a.o ssl/t_x509.o ssl/txt_db.o ssl/ui_compat.o ssl/uid.o ssl/ui_err.o ssl/ui_lib.o ssl/ui_openssl.o ssl/ui_util.o ssl/v3_addr.o ssl/v3_akeya.o ssl/v3_akey.o ssl/v3_alt.o ssl/v3_asid.o ssl/v3_bcons.o ssl/v3_bitst.o ssl/v3_conf.o ssl/v3_cpols.o ssl/v3_crld.o ssl/v3_enum.o ssl/v3err.o ssl/v3_extku.o ssl/v3_genn.o ssl/v3_ia5.o ssl/v3_info.o ssl/v3_int.o ssl/v3_lib.o ssl/v3_ncons.o ssl/v3_ocsp.o ssl/v3_pcia.o ssl/v3_pci.o ssl/v3_pcons.o ssl/v3_pku.o ssl/v3_pmaps.o ssl/v3_prn.o ssl/v3_purp.o ssl/v3_scts.o ssl/v3_skey.o ssl/v3_sxnet.o ssl/v3_utl.o ssl/wp_block.o ssl/wp_dgst.o ssl/wrap128.o ssl/x509_att.o ssl/x509_cmp.o ssl/x509cset.o ssl/x509_d2.o ssl/x509_def.o ssl/x509_err.o ssl/x509_ext.o ssl/x509_lu.o ssl/x509name.o ssl/x509_obj.o ssl/x509_r2x.o ssl/x509_req.o ssl/x509rset.o ssl/x509_set.o ssl/x509spki.o ssl/x509_trs.o ssl/x509_txt.o ssl/x509type.o ssl/x509_v3.o ssl/x509_vfy.o ssl/x509_vpm.o ssl/x_algor.o ssl/x_all.o ssl/x_attrib.o ssl/x_bignum.o ssl/xcbc_enc.o ssl/x_crl.o ssl/x_exten.o ssl/x_info.o ssl/x_long.o ssl/x_name.o ssl/x_nx509.o ssl/x_pkey.o ssl/x_pubkey.o ssl/x_req.o ssl/x_sig.o ssl/x_spki.o ssl/xts128.o ssl/x_val.o ssl/x_x509a.o ssl/x_x509.o

	  
#FAIL sslssl/a_bitstr.o ssl/a_bool.o ssl/a_bytes.o ssl/a_d2i_fp.o ssl/a_digest.o ssl/a_dup.o ssl/a_enum.o ssl/aes_cbc.o ssl/aes_cfb.o ssl/aes_core.o ssl/aes_ctr.o ssl/aes_ecb.o ssl/aes_ige.o ssl/aes_misc.o ssl/aes_ofb.o ssl/aes_wrap.o ssl/a_gentm.o ssl/a_i2d_fp.o ssl/a_int.o ssl/a_mbstr.o ssl/ameth_lib.o ssl/a_object.o ssl/a_octet.o ssl/a_print.o ssl/a_set.o ssl/a_sign.o ssl/asn1_err.o ssl/asn1_gen.o ssl/asn1_lib.o ssl/asn1_par.o ssl/asn_mime.o ssl/asn_moid.o ssl/asn_pack.o ssl/a_strex.o ssl/a_strnid.o ssl/a_time.o ssl/a_type.o ssl/a_utctm.o ssl/a_utf8.o ssl/a_verify.o ssl/b_dump.o ssl/bf_buff.o ssl/bf_cfb64.o ssl/bf_ecb.o ssl/bf_enc.o ssl/bf_nbio.o ssl/bf_null.o ssl/bf_ofb64.o ssl/bf_skey.o ssl/bio_asn1.o ssl/bio_b64.o ssl/bio_cb.o ssl/bio_enc.o ssl/bio_err.o ssl/bio_lib.o ssl/bio_md.o ssl/bio_ndef.o ssl/bio_ok.o ssl/bio_pk7.o ssl/bio_ssl.o ssl/bn_add.o ssl/bn_asm.o ssl/bn_blind.o ssl/bn_const.o ssl/bn_ctx.o ssl/bn_depr.o ssl/bn_div.o ssl/bn_err.o ssl/bn_exp2.o ssl/bn_exp.o ssl/bn_gcd.o ssl/bn_gf2m.o ssl/bn_kron.o ssl/bn_lib.o ssl/bn_mod.o ssl/bn_mont.o ssl/bn_mpi.o ssl/bn_mul.o ssl/bn_nist.o ssl/bn_prime.o ssl/bn_print.o ssl/bn_rand.o ssl/bn_recp.o ssl/bn_shift.o ssl/bn_sqr.o ssl/bn_sqrt.o ssl/bn_word.o ssl/bn_x931p.o ssl/b_print.o ssl/b_sock.o ssl/bss_acpt.o ssl/bss_bio.o ssl/bss_conn.o ssl/bss_dgram.o ssl/bss_fd.o ssl/bss_file.o ssl/bss_log.o ssl/bss_mem.o ssl/bss_null.o ssl/bss_sock.o ssl/buf_err.o ssl/buffer.o ssl/buf_str.o ssl/by_dir.o ssl/by_file.o ssl/c_allc.o ssl/c_alld.o ssl/c_all.o ssl/camellia.o ssl/cbc128.o ssl/cbc_cksm.o ssl/cbc_enc.o ssl/c_cfb64.o ssl/ccm128.o ssl/c_ecb.o ssl/c_enc.o ssl/cfb128.o ssl/cfb64ede.o ssl/cfb64enc.o ssl/cfb_enc.o ssl/cmac.o ssl/cm_ameth.o ssl/cmll_cbc.o ssl/cmll_cfb.o ssl/cmll_ctr.o ssl/cmll_ecb.o ssl/cmll_misc.o ssl/cmll_ofb.o ssl/cmll_utl.o ssl/cm_pmeth.o ssl/cms_asn1.o ssl/cms_att.o ssl/cms_cd.o ssl/cms_dd.o ssl/cms_enc.o ssl/cms_env.o ssl/cms_err.o ssl/cms_ess.o ssl/cms_io.o ssl/cms_kari.o ssl/cms_lib.o ssl/cms_pwri.o ssl/cms_sd.o ssl/cms_smime.o ssl/c_ofb64.o ssl/comp_err.o ssl/comp_lib.o ssl/conf_api.o ssl/conf_def.o ssl/conf_err.o ssl/conf_lib.o ssl/conf_mall.o ssl/conf_mod.o ssl/conf_sap.o ssl/cpt_err.o ssl/c_rle.o ssl/cryptlib.o ssl/c_skey.o ssl/ctr128.o ssl/cts128.o ssl/cversion.o ssl/c_zlib.o ssl/d1_both.o ssl/d1_clnt.o ssl/d1_lib.o ssl/d1_meth.o ssl/d1_pkt.o ssl/d1_srtp.o ssl/d1_srvr.o ssl/d2i_pr.o ssl/d2i_pu.o ssl/des_enc.o ssl/des_old2.o ssl/des_old.o ssl/dh_ameth.o ssl/dh_asn1.o ssl/dh_check.o ssl/dh_depr.o ssl/dh_err.o ssl/dh_gen.o ssl/dh_kdf.o ssl/dh_key.o ssl/dh_lib.o ssl/dh_pmeth.o ssl/dh_prn.o ssl/dh_rfc5114.o ssl/digest.o ssl/dsa_ameth.o ssl/dsa_asn1.o ssl/dsa_depr.o ssl/dsa_err.o ssl/dsa_gen.o ssl/dsa_key.o ssl/dsa_lib.o ssl/dsa_ossl.o ssl/dsa_pmeth.o ssl/dsa_prn.o ssl/dsa_sign.o ssl/dsa_vrf.o ssl/dso_beos.o ssl/dso_dlfcn.o ssl/dso_dl.o ssl/dso_err.o ssl/dso_lib.o ssl/dso_null.o ssl/dso_openssl.o ssl/dso_vms.o ssl/dso_win32.o ssl/e_4758cca.o ssl/e_aep.o ssl/e_aes_cbc_hmac_sha1.o ssl/e_aes_cbc_hmac_sha256.o ssl/e_aes.o ssl/e_atalla.o ssl/ebcdic.o ssl/e_bf.o ssl/ec2_mult.o ssl/ec2_oct.o ssl/ec2_smpl.o ssl/e_camellia.o ssl/ec_ameth.o ssl/e_capi.o ssl/ec_asn1.o ssl/e_cast.o ssl/ecb3_enc.o ssl/ecb_enc.o ssl/ec_check.o ssl/ec_curve.o ssl/ec_cvt.o ssl/ec_err.o ssl/ech_err.o ssl/e_chil.o ssl/ech_kdf.o ssl/ech_key.o ssl/ech_lib.o ssl/ech_ossl.o ssl/ec_key.o ssl/eck_prn.o ssl/ec_lib.o ssl/ec_mult.o ssl/ec_oct.o ssl/ec_pmeth.o ssl/ecp_mont.o ssl/ecp_nist.o ssl/ecp_nistp224.o ssl/ecp_nistp256.o ssl/ecp_nistp521.o ssl/ecp_nistputil.o ssl/ecp_oct.o ssl/ec_print.o ssl/ecp_smpl.o ssl/ecs_asn1.o ssl/ecs_err.o ssl/ecs_lib.o ssl/ecs_ossl.o ssl/ecs_sign.o ssl/ecs_vrf.o ssl/e_cswift.o ssl/ede_cbcm_enc.o ssl/e_des3.o ssl/e_des.o ssl/e_gmp.o ssl/e_gost_err.o ssl/e_idea.o ssl/encode.o ssl/enc_read.o ssl/enc_writ.o ssl/eng_all.o ssl/eng_cnf.o ssl/eng_cryptodev.o ssl/eng_ctrl.o ssl/eng_dyn.o ssl/eng_err.o ssl/eng_fat.o ssl/eng_init.o ssl/eng_lib.o ssl/eng_list.o ssl/eng_openssl.o ssl/eng_pkey.o ssl/eng_rdrand.o ssl/eng_table.o ssl/e_null.o ssl/e_nuron.o ssl/e_old.o ssl/e_padlock.o ssl/e_rc2.o ssl/e_rc4_hmac_md5.o ssl/e_rc4.o ssl/e_rc5.o ssl/err_all.o ssl/err.o ssl/err_prn.o ssl/e_seed.o ssl/e_sureware.o ssl/e_ubsec.o ssl/evp_acnf.o ssl/evp_asn1.o ssl/evp_cnf.o ssl/evp_enc.o ssl/evp_err.o ssl/evp_key.o ssl/evp_lib.o ssl/evp_pbe.o ssl/evp_pkey.o ssl/e_xcbc_d.o ssl/ex_data.o ssl/fcrypt_b.o ssl/fcrypt.o ssl/f_enum.o ssl/f_int.o ssl/fips_ers.o ssl/f_string.o ssl/gcm128.o ssl/gost2001_keyx.o ssl/gost2001.o ssl/gost89.o ssl/gost94_keyx.o ssl/gost_ameth.o ssl/gost_asn1.o ssl/gost_crypt.o ssl/gost_ctl.o ssl/gost_eng.o ssl/gosthash.o ssl/gost_keywrap.o ssl/gost_md.o ssl/gost_params.o ssl/gost_pmeth.o ssl/gost_sign.o ssl/hmac.o ssl/hm_ameth.o ssl/hm_pmeth.o ssl/i2d_pr.o ssl/i2d_pu.o ssl/i_cbc.o ssl/i_cfb64.o ssl/i_ecb.o ssl/i_ofb64.o ssl/i_skey.o ssl/krb5_asn.o ssl/kssl.o ssl/lhash.o ssl/lh_stats.o ssl/md4_dgst.o ssl/md4_one.o ssl/md5_dgst.o ssl/md5_one.o ssl/mdc2dgst.o ssl/mdc2_one.o ssl/md_rand.o ssl/m_dss1.o ssl/m_dss.o ssl/m_ecdsa.o ssl/mem_clr.o ssl/mem_dbg.o ssl/mem.o ssl/m_md2.o ssl/m_md4.o ssl/m_md5.o ssl/m_mdc2.o ssl/m_null.o ssl/m_ripemd.o ssl/m_sha1.o ssl/m_sha.o ssl/m_sigver.o ssl/m_wp.o ssl/names.o ssl/n_pkey.o ssl/nsseq.o ssl/obj_dat.o ssl/obj_err.o ssl/obj_lib.o ssl/obj_xref.o ssl/ocsp_asn.o ssl/ocsp_cl.o ssl/ocsp_err.o ssl/ocsp_ext.o ssl/ocsp_ht.o ssl/ocsp_lib.o ssl/ocsp_prn.o ssl/ocsp_srv.o ssl/ocsp_vfy.o ssl/o_dir.o ssl/ofb128.o ssl/ofb64ede.o ssl/ofb64enc.o ssl/ofb_enc.o ssl/o_fips.o ssl/o_init.o ssl/o_names.o ssl/o_str.o ssl/o_time.o ssl/p12_add.o ssl/p12_asn.o ssl/p12_attr.o ssl/p12_crpt.o ssl/p12_crt.o ssl/p12_decr.o ssl/p12_init.o ssl/p12_key.o ssl/p12_kiss.o ssl/p12_mutl.o ssl/p12_npas.o ssl/p12_p8d.o ssl/p12_p8e.o ssl/p12_utl.o ssl/p5_crpt2.o ssl/p5_crpt.o ssl/p5_pbe.o ssl/p5_pbev2.o ssl/p8_pkey.o ssl/pcbc_enc.o ssl/pcy_cache.o ssl/pcy_data.o ssl/pcy_lib.o ssl/pcy_map.o ssl/pcy_node.o ssl/pcy_tree.o ssl/p_dec.o ssl/pem_all.o ssl/pem_err.o ssl/pem_info.o ssl/pem_lib.o ssl/pem_oth.o ssl/pem_pk8.o ssl/pem_pkey.o ssl/pem_seal.o ssl/pem_sign.o ssl/pem_x509.o ssl/pem_xaux.o ssl/p_enc.o ssl/pk12err.o ssl/pk7_asn1.o ssl/pk7_attr.o ssl/pk7_doit.o ssl/pk7_lib.o ssl/pk7_mime.o ssl/pk7_smime.o ssl/pkcs7err.o ssl/p_lib.o ssl/pmeth_fn.o ssl/pmeth_gn.o ssl/pmeth_lib.o ssl/p_open.o ssl/pqueue.o ssl/p_seal.o ssl/p_sign.o ssl/p_verify.o ssl/pvkfmt.o ssl/qud_cksm.o ssl/rand_egd.o ssl/rand_err.o ssl/randfile.o ssl/rand_key.o ssl/rand_lib.o ssl/rand_nw.o ssl/rand_os2.o ssl/rand_unix.o ssl/rand_win.o ssl/rc2_cbc.o ssl/rc2cfb64.o ssl/rc2_ecb.o ssl/rc2ofb64.o ssl/rc2_skey.o ssl/rc4_enc.o ssl/rc4_skey.o ssl/rc4_utl.o ssl/read2pwd.o ssl/rmd_dgst.o ssl/rmd_one.o ssl/rpc_enc.o ssl/rsa_ameth.o ssl/rsa_asn1.o ssl/rsa_chk.o ssl/rsa_crpt.o ssl/rsa_depr.o ssl/rsa_eay.o ssl/rsa_err.o ssl/rsa_gen.o ssl/rsa_lib.o ssl/rsa_none.o ssl/rsa_null.o ssl/rsa_oaep.o ssl/rsa_pk1.o ssl/rsa_pmeth.o ssl/rsa_prn.o ssl/rsa_pss.o ssl/rsa_saos.o ssl/rsa_sign.o ssl/rsa_ssl.o ssl/rsa_x931.o ssl/s23_clnt.o ssl/s23_lib.o ssl/s23_meth.o ssl/s23_pkt.o ssl/s23_srvr.o ssl/s2_clnt.o ssl/s2_enc.o ssl/s2_lib.o ssl/s2_meth.o ssl/s2_pkt.o ssl/s2_srvr.o ssl/s3_both.o ssl/s3_cbc.o ssl/s3_clnt.o ssl/s3_enc.o ssl/s3_lib.o ssl/s3_meth.o ssl/s3_pkt.o ssl/s3_srvr.o ssl/seed_cbc.o ssl/seed_cfb.o ssl/seed_ecb.o ssl/seed.o ssl/seed_ofb.o ssl/set_key.o ssl/sha1dgst.o ssl/sha1_one.o ssl/sha256.o ssl/sha512.o ssl/sha_dgst.o ssl/sha_one.o ssl/srp_lib.o ssl/srp_vfy.o ssl/ssl_algs.o ssl/ssl_asn1.o ssl/ssl_cert.o ssl/ssl_ciph.o ssl/ssl_conf.o ssl/ssl_err2.o ssl/ssl_err.o ssl/ssl_lib.o ssl/ssl_rsa.o ssl/ssl_sess.o ssl/ssl_stat.o ssl/ssl_txt.o ssl/ssl_utst.o ssl/stack.o ssl/str2key.o ssl/t1_clnt.o ssl/t1_enc.o ssl/t1_ext.o ssl/t1_lib.o ssl/t1_meth.o ssl/t1_reneg.o ssl/t1_srvr.o ssl/t1_trce.o ssl/tasn_dec.o ssl/tasn_enc.o ssl/tasn_fre.o ssl/tasn_new.o ssl/tasn_prn.o ssl/tasn_typ.o ssl/tasn_utl.o ssl/tb_asnmth.o ssl/tb_cipher.o ssl/tb_dh.o ssl/tb_digest.o ssl/tb_dsa.o ssl/tb_ecdh.o ssl/tb_ecdsa.o ssl/t_bitst.o ssl/tb_pkmeth.o ssl/tb_rand.o ssl/tb_rsa.o ssl/tb_store.o ssl/t_crl.o ssl/tls_srp.o ssl/t_pkey.o ssl/t_req.o ssl/ts_asn1.o ssl/ts_conf.o ssl/ts_err.o ssl/ts_lib.o ssl/t_spki.o ssl/ts_req_print.o ssl/ts_req_utils.o ssl/ts_rsp_print.o ssl/ts_rsp_sign.o ssl/ts_rsp_utils.o ssl/ts_rsp_verify.o ssl/ts_verify_ctx.o ssl/t_x509a.o ssl/t_x509.o ssl/txt_db.o ssl/ui_compat.o ssl/uid.o ssl/ui_err.o ssl/ui_lib.o ssl/ui_openssl.o ssl/ui_util.o ssl/v3_addr.o ssl/v3_akeya.o ssl/v3_akey.o ssl/v3_alt.o ssl/v3_asid.o ssl/v3_bcons.o ssl/v3_bitst.o ssl/v3_conf.o ssl/v3_cpols.o ssl/v3_crld.o ssl/v3_enum.o ssl/v3err.o ssl/v3_extku.o ssl/v3_genn.o ssl/v3_ia5.o ssl/v3_info.o ssl/v3_int.o ssl/v3_lib.o ssl/v3_ncons.o ssl/v3_ocsp.o ssl/v3_pcia.o ssl/v3_pci.o ssl/v3_pcons.o ssl/v3_pku.o ssl/v3_pmaps.o ssl/v3_prn.o ssl/v3_purp.o ssl/v3_scts.o ssl/v3_skey.o ssl/v3_sxnet.o ssl/v3_utl.o ssl/wp_block.o ssl/wp_dgst.o ssl/wrap128.o ssl/x509_att.o ssl/x509_cmp.o ssl/x509cset.o ssl/x509_d2.o ssl/x509_def.o ssl/x509_err.o ssl/x509_ext.o ssl/x509_lu.o ssl/x509name.o ssl/x509_obj.o ssl/x509_r2x.o ssl/x509_req.o ssl/x509rset.o ssl/x509_set.o ssl/x509spki.o ssl/x509_trs.o ssl/x509_txt.o ssl/x509type.o ssl/x509_v3.o ssl/x509_vfy.o ssl/x509_vpm.o ssl/x_algor.o ssl/x_all.o ssl/x_attrib.o ssl/x_bignum.o ssl/xcbc_enc.o ssl/x_crl.o ssl/x_exten.o ssl/x_info.o ssl/x_long.o ssl/x_name.o ssl/x_nx509.o ssl/x_pkey.o ssl/x_pubkey.o ssl/x_req.o ssl/x_sig.o ssl/x_spki.o ssl/xts128.o ssl/x_val.o ssl/x_x509a.o ssl/x_x509.o
#FAIL	  -whole-archive infinit/elle/openssl/lib/libssl.a \
#	  infinit/elle/openssl/lib/libcrypto.a -no-whole-archive
	  
# Your own include-path
LOCAL_INCLUDES= \
 -I. \
 -I/home/bearclaw/projects/fs/elle/elle/src \
 -I/home/bearclaw/projects/fs/elle/reactor/src \
 -I/home/bearclaw/projects/fs/elle/das/src \
 -I/home/bearclaw/projects/fs/elle/cryptography/src \
 -I/home/bearclaw/projects/fs/src \
 -I/home/bearclaw/projects/fs/elle/protocol/src \
 -I/home/bearclaw/projects/fs/elle/athena/src \
 -I/home/bearclaw/projects/fs/_build/mirage/elle/boost/1.60.0/include \
 -I/home/bearclaw/projects/fs/_build/mirage/elle/openssl/include \
 -DINCLUDEOS \
 -DMIRAGE \
 -DBOOST_ASIO_BASIC_SERIAL_PORT_HPP \
 -DBOOST_ASIO_SERIAL_PORT_BASE_HPP \
 -DBOOST_ASIO_SERIAL_PORT_HPP \
 -DBOOST_ASIO_SERIAL_PORT_SERVICE_HPP \
 -DELLE_LOG_DISABLE \
 -DELLE_TEST_NO_MEMFRY

# IncludeOS location
ifndef INCLUDEOS_INSTALL
INCLUDEOS_INSTALL=$(HOME)/IncludeOS_install
endif

# Include the installed seed makefile
include $(INCLUDEOS_INSTALL)/Makeseed
