const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const bearssl = b.addStaticLibrary(.{
        .name = "bearssl",
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    bearssl.addIncludePath(.{ .path = "BearSSL/inc" });
    bearssl.addIncludePath(.{ .path = "BearSSL/src" });
    bearssl.addCSourceFiles(.{ .files = &bearssl_sources, .root = .{ .path = "BearSSL/" } });
    bearssl.defineCMacro("BR_LE_UNALIGNED", "0");

    const exe = b.addExecutable(.{
        .name = "topaz",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });

    exe.linkLibC();
    exe.addIncludePath(.{ .path = "BearSSL/inc" });
    exe.linkLibrary(bearssl);
    const options = b.addOptions();
    options.addOption(usize, "max_path_len", b.option(usize, "pathLen", "maximum url path length (default: 1024)") orelse 1024);
    options.addOption(usize, "max_meta_len", b.option(usize, "metaLen", "maximum gemini meta length (default: 1024, guaranteed by the gemini spec)") orelse 1024);
    options.addOption(usize, "send_buf_len", b.option(usize, "sendBuf", "http send buffer size (default: 4096)") orelse 1 << 12);
    options.addOption(usize, "max_line_len", b.option(usize, "lineLen", "maximum gemtext line length (default: 64Ki)") orelse 1 << 16);
    options.addOption([]const u8, "template_dir", b.option([]const u8, "templateDir", "custom template directory to override the default (must have start.html, input.html, and style.css)") orelse "templates");
    exe.root_module.addOptions("options", options);

    b.installArtifact(exe);
    const run_cmd = b.addRunArtifact(exe);

    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| run_cmd.addArgs(args);

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    // const exe_unit_tests = b.addTest(.{
    //     .root_source_file = .{ .path = "src/main.zig" },
    //     .target = target,
    //     .optimize = optimize,
    // });

    // const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    // const test_step = b.step("test", "Run unit tests");
    // test_step.dependOn(&run_exe_unit_tests.step);
}

// taken from BearSSL/mk/mkrules.sh
const bearssl_sources = [_][]const u8{
    "src/settings.c",                      "src/aead/ccm.c",                      "src/aead/eax.c",                      "src/aead/gcm.c",
    "src/codec/ccopy.c",                   "src/codec/dec16be.c",                 "src/codec/dec16le.c",                 "src/codec/dec32be.c",
    "src/codec/dec32le.c",                 "src/codec/dec64be.c",                 "src/codec/dec64le.c",                 "src/codec/enc16be.c",
    "src/codec/enc16le.c",                 "src/codec/enc32be.c",                 "src/codec/enc32le.c",                 "src/codec/enc64be.c",
    "src/codec/enc64le.c",                 "src/codec/pemdec.c",                  "src/codec/pemenc.c",                  "src/ec/ec_all_m15.c",
    "src/ec/ec_all_m31.c",                 "src/ec/ec_c25519_i15.c",              "src/ec/ec_c25519_i31.c",              "src/ec/ec_c25519_m15.c",
    "src/ec/ec_c25519_m31.c",              "src/ec/ec_c25519_m62.c",              "src/ec/ec_c25519_m64.c",              "src/ec/ec_curve25519.c",
    "src/ec/ec_default.c",                 "src/ec/ec_keygen.c",                  "src/ec/ec_p256_m15.c",                "src/ec/ec_p256_m31.c",
    "src/ec/ec_p256_m62.c",                "src/ec/ec_p256_m64.c",                "src/ec/ec_prime_i15.c",               "src/ec/ec_prime_i31.c",
    "src/ec/ec_pubkey.c",                  "src/ec/ec_secp256r1.c",               "src/ec/ec_secp384r1.c",               "src/ec/ec_secp521r1.c",
    "src/ec/ecdsa_atr.c",                  "src/ec/ecdsa_default_sign_asn1.c",    "src/ec/ecdsa_default_sign_raw.c",     "src/ec/ecdsa_default_vrfy_asn1.c",
    "src/ec/ecdsa_default_vrfy_raw.c",     "src/ec/ecdsa_i15_bits.c",             "src/ec/ecdsa_i15_sign_asn1.c",        "src/ec/ecdsa_i15_sign_raw.c",
    "src/ec/ecdsa_i15_vrfy_asn1.c",        "src/ec/ecdsa_i15_vrfy_raw.c",         "src/ec/ecdsa_i31_bits.c",             "src/ec/ecdsa_i31_sign_asn1.c",
    "src/ec/ecdsa_i31_sign_raw.c",         "src/ec/ecdsa_i31_vrfy_asn1.c",        "src/ec/ecdsa_i31_vrfy_raw.c",         "src/ec/ecdsa_rta.c",
    "src/hash/dig_oid.c",                  "src/hash/dig_size.c",                 "src/hash/ghash_ctmul.c",              "src/hash/ghash_ctmul32.c",
    "src/hash/ghash_ctmul64.c",            "src/hash/ghash_pclmul.c",             "src/hash/ghash_pwr8.c",               "src/hash/md5.c",
    "src/hash/md5sha1.c",                  "src/hash/mgf1.c",                     "src/hash/multihash.c",                "src/hash/sha1.c",
    "src/hash/sha2big.c",                  "src/hash/sha2small.c",                "src/int/i15_add.c",                   "src/int/i15_bitlen.c",
    "src/int/i15_decmod.c",                "src/int/i15_decode.c",                "src/int/i15_decred.c",                "src/int/i15_encode.c",
    "src/int/i15_fmont.c",                 "src/int/i15_iszero.c",                "src/int/i15_moddiv.c",                "src/int/i15_modpow.c",
    "src/int/i15_modpow2.c",               "src/int/i15_montmul.c",               "src/int/i15_mulacc.c",                "src/int/i15_muladd.c",
    "src/int/i15_ninv15.c",                "src/int/i15_reduce.c",                "src/int/i15_rshift.c",                "src/int/i15_sub.c",
    "src/int/i15_tmont.c",                 "src/int/i31_add.c",                   "src/int/i31_bitlen.c",                "src/int/i31_decmod.c",
    "src/int/i31_decode.c",                "src/int/i31_decred.c",                "src/int/i31_encode.c",                "src/int/i31_fmont.c",
    "src/int/i31_iszero.c",                "src/int/i31_moddiv.c",                "src/int/i31_modpow.c",                "src/int/i31_modpow2.c",
    "src/int/i31_montmul.c",               "src/int/i31_mulacc.c",                "src/int/i31_muladd.c",                "src/int/i31_ninv31.c",
    "src/int/i31_reduce.c",                "src/int/i31_rshift.c",                "src/int/i31_sub.c",                   "src/int/i31_tmont.c",
    "src/int/i32_add.c",                   "src/int/i32_bitlen.c",                "src/int/i32_decmod.c",                "src/int/i32_decode.c",
    "src/int/i32_decred.c",                "src/int/i32_div32.c",                 "src/int/i32_encode.c",                "src/int/i32_fmont.c",
    "src/int/i32_iszero.c",                "src/int/i32_modpow.c",                "src/int/i32_montmul.c",               "src/int/i32_mulacc.c",
    "src/int/i32_muladd.c",                "src/int/i32_ninv32.c",                "src/int/i32_reduce.c",                "src/int/i32_sub.c",
    "src/int/i32_tmont.c",                 "src/int/i62_modpow2.c",               "src/kdf/hkdf.c",                      "src/kdf/shake.c",
    "src/mac/hmac.c",                      "src/mac/hmac_ct.c",                   "src/rand/aesctr_drbg.c",              "src/rand/hmac_drbg.c",
    "src/rand/sysrng.c",                   "src/rsa/rsa_default_keygen.c",        "src/rsa/rsa_default_modulus.c",       "src/rsa/rsa_default_oaep_decrypt.c",
    "src/rsa/rsa_default_oaep_encrypt.c",  "src/rsa/rsa_default_pkcs1_sign.c",    "src/rsa/rsa_default_pkcs1_vrfy.c",    "src/rsa/rsa_default_priv.c",
    "src/rsa/rsa_default_privexp.c",       "src/rsa/rsa_default_pss_sign.c",      "src/rsa/rsa_default_pss_vrfy.c",      "src/rsa/rsa_default_pub.c",
    "src/rsa/rsa_default_pubexp.c",        "src/rsa/rsa_i15_keygen.c",            "src/rsa/rsa_i15_modulus.c",           "src/rsa/rsa_i15_oaep_decrypt.c",
    "src/rsa/rsa_i15_oaep_encrypt.c",      "src/rsa/rsa_i15_pkcs1_sign.c",        "src/rsa/rsa_i15_pkcs1_vrfy.c",        "src/rsa/rsa_i15_priv.c",
    "src/rsa/rsa_i15_privexp.c",           "src/rsa/rsa_i15_pss_sign.c",          "src/rsa/rsa_i15_pss_vrfy.c",          "src/rsa/rsa_i15_pub.c",
    "src/rsa/rsa_i15_pubexp.c",            "src/rsa/rsa_i31_keygen.c",            "src/rsa/rsa_i31_keygen_inner.c",      "src/rsa/rsa_i31_modulus.c",
    "src/rsa/rsa_i31_oaep_decrypt.c",      "src/rsa/rsa_i31_oaep_encrypt.c",      "src/rsa/rsa_i31_pkcs1_sign.c",        "src/rsa/rsa_i31_pkcs1_vrfy.c",
    "src/rsa/rsa_i31_priv.c",              "src/rsa/rsa_i31_privexp.c",           "src/rsa/rsa_i31_pss_sign.c",          "src/rsa/rsa_i31_pss_vrfy.c",
    "src/rsa/rsa_i31_pub.c",               "src/rsa/rsa_i31_pubexp.c",            "src/rsa/rsa_i32_oaep_decrypt.c",      "src/rsa/rsa_i32_oaep_encrypt.c",
    "src/rsa/rsa_i32_pkcs1_sign.c",        "src/rsa/rsa_i32_pkcs1_vrfy.c",        "src/rsa/rsa_i32_priv.c",              "src/rsa/rsa_i32_pss_sign.c",
    "src/rsa/rsa_i32_pss_vrfy.c",          "src/rsa/rsa_i32_pub.c",               "src/rsa/rsa_i62_keygen.c",            "src/rsa/rsa_i62_oaep_decrypt.c",
    "src/rsa/rsa_i62_oaep_encrypt.c",      "src/rsa/rsa_i62_pkcs1_sign.c",        "src/rsa/rsa_i62_pkcs1_vrfy.c",        "src/rsa/rsa_i62_priv.c",
    "src/rsa/rsa_i62_pss_sign.c",          "src/rsa/rsa_i62_pss_vrfy.c",          "src/rsa/rsa_i62_pub.c",               "src/rsa/rsa_oaep_pad.c",
    "src/rsa/rsa_oaep_unpad.c",            "src/rsa/rsa_pkcs1_sig_pad.c",         "src/rsa/rsa_pkcs1_sig_unpad.c",       "src/rsa/rsa_pss_sig_pad.c",
    "src/rsa/rsa_pss_sig_unpad.c",         "src/rsa/rsa_ssl_decrypt.c",           "src/ssl/prf.c",                       "src/ssl/prf_md5sha1.c",
    "src/ssl/prf_sha256.c",                "src/ssl/prf_sha384.c",                "src/ssl/ssl_ccert_single_ec.c",       "src/ssl/ssl_ccert_single_rsa.c",
    "src/ssl/ssl_client.c",                "src/ssl/ssl_client_default_rsapub.c", "src/ssl/ssl_client_full.c",           "src/ssl/ssl_engine.c",
    "src/ssl/ssl_engine_default_aescbc.c", "src/ssl/ssl_engine_default_aesccm.c", "src/ssl/ssl_engine_default_aesgcm.c", "src/ssl/ssl_engine_default_chapol.c",
    "src/ssl/ssl_engine_default_descbc.c", "src/ssl/ssl_engine_default_ec.c",     "src/ssl/ssl_engine_default_ecdsa.c",  "src/ssl/ssl_engine_default_rsavrfy.c",
    "src/ssl/ssl_hashes.c",                "src/ssl/ssl_hs_client.c",             "src/ssl/ssl_hs_server.c",             "src/ssl/ssl_io.c",
    "src/ssl/ssl_keyexport.c",             "src/ssl/ssl_lru.c",                   "src/ssl/ssl_rec_cbc.c",               "src/ssl/ssl_rec_ccm.c",
    "src/ssl/ssl_rec_chapol.c",            "src/ssl/ssl_rec_gcm.c",               "src/ssl/ssl_scert_single_ec.c",       "src/ssl/ssl_scert_single_rsa.c",
    "src/ssl/ssl_server.c",                "src/ssl/ssl_server_full_ec.c",        "src/ssl/ssl_server_full_rsa.c",       "src/ssl/ssl_server_mine2c.c",
    "src/ssl/ssl_server_mine2g.c",         "src/ssl/ssl_server_minf2c.c",         "src/ssl/ssl_server_minf2g.c",         "src/ssl/ssl_server_minr2g.c",
    "src/ssl/ssl_server_minu2g.c",         "src/ssl/ssl_server_minv2g.c",         "src/symcipher/aes_big_cbcdec.c",      "src/symcipher/aes_big_cbcenc.c",
    "src/symcipher/aes_big_ctr.c",         "src/symcipher/aes_big_ctrcbc.c",      "src/symcipher/aes_big_dec.c",         "src/symcipher/aes_big_enc.c",
    "src/symcipher/aes_common.c",          "src/symcipher/aes_ct.c",              "src/symcipher/aes_ct64.c",            "src/symcipher/aes_ct64_cbcdec.c",
    "src/symcipher/aes_ct64_cbcenc.c",     "src/symcipher/aes_ct64_ctr.c",        "src/symcipher/aes_ct64_ctrcbc.c",     "src/symcipher/aes_ct64_dec.c",
    "src/symcipher/aes_ct64_enc.c",        "src/symcipher/aes_ct_cbcdec.c",       "src/symcipher/aes_ct_cbcenc.c",       "src/symcipher/aes_ct_ctr.c",
    "src/symcipher/aes_ct_ctrcbc.c",       "src/symcipher/aes_ct_dec.c",          "src/symcipher/aes_ct_enc.c",          "src/symcipher/aes_pwr8.c",
    "src/symcipher/aes_pwr8_cbcdec.c",     "src/symcipher/aes_pwr8_cbcenc.c",     "src/symcipher/aes_pwr8_ctr.c",        "src/symcipher/aes_pwr8_ctrcbc.c",
    "src/symcipher/aes_small_cbcdec.c",    "src/symcipher/aes_small_cbcenc.c",    "src/symcipher/aes_small_ctr.c",       "src/symcipher/aes_small_ctrcbc.c",
    "src/symcipher/aes_small_dec.c",       "src/symcipher/aes_small_enc.c",       "src/symcipher/aes_x86ni.c",           "src/symcipher/aes_x86ni_cbcdec.c",
    "src/symcipher/aes_x86ni_cbcenc.c",    "src/symcipher/aes_x86ni_ctr.c",       "src/symcipher/aes_x86ni_ctrcbc.c",    "src/symcipher/chacha20_ct.c",
    "src/symcipher/chacha20_sse2.c",       "src/symcipher/des_ct.c",              "src/symcipher/des_ct_cbcdec.c",       "src/symcipher/des_ct_cbcenc.c",
    "src/symcipher/des_support.c",         "src/symcipher/des_tab.c",             "src/symcipher/des_tab_cbcdec.c",      "src/symcipher/des_tab_cbcenc.c",
    "src/symcipher/poly1305_ctmul.c",      "src/symcipher/poly1305_ctmul32.c",    "src/symcipher/poly1305_ctmulq.c",     "src/symcipher/poly1305_i15.c",
    "src/x509/asn1enc.c",                  "src/x509/encode_ec_pk8der.c",         "src/x509/encode_ec_rawder.c",         "src/x509/encode_rsa_pk8der.c",
    "src/x509/encode_rsa_rawder.c",        "src/x509/skey_decoder.c",             "src/x509/x509_decoder.c",             "src/x509/x509_knownkey.c",
    "src/x509/x509_minimal.c",             "src/x509/x509_minimal_full.c",
};
