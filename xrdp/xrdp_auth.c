/**
 * xrdp: A Remote Desktop Protocol server.
 *
 * Copyright (C) Idan Freiberg 2012-2017
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Network Level Authentication
 *
 * [MS-CSSP] https://msdn.microsoft.com/en-us/library/cc226764.aspx
 */

#if defined(HAVE_CONFIG_H)
#include <config_ac.h>
#endif

#define LOG_LEVEL 11
#define LLOG(_level, _args) \
    do { if (_level < LOG_LEVEL) { g_write _args ; } } while (0)
#define LLOGLN(_level, _args) \
    do { if (_level < LOG_LEVEL) { g_writeln _args ; } } while (0)
#define LHEXDUMP(_level, _args) \
    do { if (_level < LOG_LEVEL) { g_hexdump _args ; } } while (0)


#define discard_const(ptr) ((void *)((uintptr_t)(ptr)))
#define TEST_USER_FILE "/tmp/ntlmusers"

/* NTLMSSP OID: 1.3.6.1.4.1.311.2.2.10 */
#define GSS_NTLMSSP_OID_STRING "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"
#define GSS_NTLMSSP_OID_LENGTH 10
static gss_OID_desc g_ntlmsspOID =
{
    GSS_NTLMSSP_OID_LENGTH,
    GSS_NTLMSSP_OID_STRING
};


/*****************************************************************************/
int
xrdp_nla_authenticate(struct xrdp_nla *self)
{
    LLOGLN(10, ("     in xrdp_nla_authenticate"));
    OM_uint32 actual_time, time_req, time_rec;
    OM_uint32 major_status, minor_status;
    OM_uint32 actual_services;
    gss_name_t target_name, gss_srvname;
    gss_OID desired_mech = &g_ntlmsspOID;
    gss_OID actual_mech;
    gss_OID_set actual_oid_set;
    gss_OID_set_desc desired_oid_set = { 0 };
    gss_cred_id_t cred, delegation_cred;
    gss_ctx_id_t gss_ctx;
    gss_buffer_desc input_tok, output_tok, nbuf;
    int context_established = 0;

    struct stream *ts_creds;
    struct stream token = { 0 };
    struct stream pubkey = { 0 };
    struct stream pubkey_cmp = { 0 };

    cssp_gss_mech_available(desired_mech);

    // Verify that system gss support spnego
    if (!cssp_gss_mech_available(desired_mech))
    {
        LLOGLN(0, ("xrdp_nla_authenticate: System doesn't have support for desired authentication mechanism."));
        return 1;
    }

    setenv("NTLM_USER_FILE", TEST_USER_FILE, 1);

//    const char *srvname = "test@testserver";
//
//    nbuf.value = discard_const(srvname);
//    nbuf.length = g_strlen(srvname);
//    major_status = gss_import_name(&minor_status, &nbuf,
//                              GSS_C_NT_HOSTBASED_SERVICE,
//                               &gss_srvname);
//    if (GSS_ERROR(major_status))
//    {
//      cssp_gss_report_error(GSS_C_GSS_CODE, "gssntlm_import_name failed",
//                    major_status, minor_status);
//      g_writeln("minor %x", minor_status);
//      return 1;
//    }
//
//    desired_oid_set.count = 1;
//    desired_oid_set.elements = desired_mech;

    g_writeln("gss_acquire_cred ...");
    major_status = gss_acquire_cred(&minor_status,
                                    GSS_C_NO_NAME,
                                    GSS_C_INDEFINITE,
                                    GSS_C_NO_OID_SET,
                                    GSS_C_ACCEPT, &cred,
                                    NULL,
                                    NULL);

    if (GSS_ERROR(major_status))
    {
        cssp_gss_report_error(GSS_C_GSS_CODE, "gss_acquire_cred failed",
                              major_status, minor_status);
        g_writeln("minor %x", minor_status);
        return 1;
    }


    gss_ctx = GSS_C_NO_CONTEXT;
//    cred = GSS_C_NO_CREDENTIAL;

    do
    {

        LLOGLN(10, ("xrdp_nla_authenticate: recv auth token"));
        xrdp_nla_recv_tsrequest(self);
        LHEXDUMP(0, (self->negoTokens->data, self->negoTokens->length));
        LLOGLN(10, ("xrdp_nla_authenticate: recv auth token done!"));

        input_tok.value = self->negoTokens->data;
        input_tok.length = self->negoTokens->length;

        if (input_tok.length <= 0)
        {
            LLOGLN(10, ("xrdp_nla_authenticate: input_tok.length <= 0"));
            return 1;
        }

        g_writeln("gss_accept_sec_context ...");
        major_status = gss_accept_sec_context(&minor_status,
                                              &gss_ctx,
                                              cred,
                                              &input_tok,
                                              GSS_C_NO_CHANNEL_BINDINGS,
                                              NULL,
                                              NULL,
                                              &output_tok,
                                              &actual_services,
                                              NULL,
                                              NULL);

        if (GSS_ERROR(major_status))
        {
            cssp_gss_report_error(GSS_C_GSS_CODE,
                                  "gss_accept_sec_context failed",
                                  major_status,
                                  minor_status);
            return 1;
        }

        if (GSS_S_CONTINUE_NEEDED & major_status)
        {
            g_writeln("gss_accept_sec_context: GSS_S_CONTINUE_NEEDED!");

            self->negoTokens->data = output_tok.value;
            self->negoTokens->length = output_tok.length;

            g_writeln(" >>> xrdp_nla_send_tsrequest...");
            LHEXDUMP(0, (self->negoTokens->data, self->negoTokens->length));
            xrdp_nla_send_tsrequest(self);
            g_writeln(" >>> xrdp_nla_send_tsrequest...done!");

            (void) gss_release_buffer(&minor_status, &output_tok);
        }
        else
        {
            context_established = 1;
            g_writeln("gss_accept_sec_context success!");
        }

    }
    while (!context_established);

    g_writeln("out of gssapi loop");

    // validate required services
    if (!(actual_services & GSS_C_CONF_FLAG))
    {
        LLOGLN(0, ("xrdp_nla_authenticate: Confidentiality service required but is not available."));
//        goto bail_out;
    }


    g_writeln("ENC PUBLIC KEY :");
    LHEXDUMP(0, (self->pubKeyAuth->data, self->pubKeyAuth->length));
    struct blob *decryptedPubKey = NULL;
    struct blob *finalPubKey = NULL;
    xrdp_nla_gss_unwrap(gss_ctx, self->pubKeyAuth, &decryptedPubKey);
    g_writeln("DEC PUBLIC KEY :");
    LHEXDUMP(0, (decryptedPubKey->data, decryptedPubKey->length));


    //todo: validate its really our pubkey

    ap_integer_increment_le(decryptedPubKey);
    xrdp_nla_gss_wrap(gss_ctx, decryptedPubKey, &finalPubKey);

    g_writeln(" >>> xrdp_nla_send_tsrequest...");
    self->pubKeyAuth = finalPubKey;
    self->negoTokens = NULL;
    self->authInfo = NULL;
    xrdp_nla_send_tsrequest(self);
    g_writeln(" >>> xrdp_nla_send_tsrequest...done!");

    LLOGLN(10, ("xrdp_nla_authenticate: recv authInfo token"));

    if (xrdp_nla_recv_tsrequest(self) != 0)
    {
        return 1;
    }

    LLOGLN(10, ("xrdp_nla_authenticate: recv authInfo done!"));
    g_writeln("ENC AUTH INFO :");
    LHEXDUMP(0, (self->authInfo->data, self->authInfo->length));
    struct blob *decryptedAuthInfo = NULL;
    xrdp_nla_gss_unwrap(gss_ctx, self->authInfo, &decryptedAuthInfo);
    g_writeln("DEC AUTH INFO :");
    LHEXDUMP(0, (decryptedAuthInfo->data, decryptedAuthInfo->length));

    // fill username and password for logon later.

    major_status = gss_release_cred(&minor_status, &cred);

    if (GSS_ERROR(major_status))
    {
        cssp_gss_report_error(GSS_C_GSS_CODE, "gss_release_cred failed",
                              major_status, minor_status);
        return 1;
    }

    major_status = gss_delete_sec_context(&minor_status, &gss_ctx, GSS_C_NO_BUFFER);

    if (GSS_ERROR(major_status))
    {
        cssp_gss_report_error(GSS_C_GSS_CODE, "gss_delete_sec_context failed",
                              major_status, minor_status);
        return 1;
    }

    LLOGLN(10, ("     out xrdp_nla_authenticate"));

    return 0;
}
