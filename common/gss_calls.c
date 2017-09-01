/**
 * xrdp: A Remote Desktop Protocol server.
 *
 * Copyright (C) Idan Freiberg 2012-2016
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
 * gssapi calls
 */
#if defined(HAVE_CONFIG_H)
#include <config_ac.h>
#endif

#include <gssapi/gssapi.h>
#include "arch.h"
#include "parse.h"
#include "os_calls.h"
#include "gss_calls.h"

#define LOG_LEVEL 11
#define LLOG(_level, _args) \
    do { if (_level < LOG_LEVEL) { g_write _args ; } } while (0)
#define LLOGLN(_level, _args) \
    do { if (_level < LOG_LEVEL) { g_writeln _args ; } } while (0)
#define LHEXDUMP(_level, _args) \
    do { if (_level < LOG_LEVEL) { g_hexdump _args ; } } while (0)


#define CASE(X) case X: return #X

struct blob
{
    int length;
    unsigned char *data;
};

const char *gss_maj_to_str(tui32 err)
{
    switch (err)
    {
            CASE(GSS_S_COMPLETE);
            /* caling errors */
            CASE(GSS_S_CALL_INACCESSIBLE_READ);
            CASE(GSS_S_CALL_INACCESSIBLE_WRITE);
            CASE(GSS_S_CALL_BAD_STRUCTURE);
            /* routine errors */
            CASE(GSS_S_BAD_MECH);
            CASE(GSS_S_BAD_NAME);
            CASE(GSS_S_BAD_NAMETYPE);
            CASE(GSS_S_BAD_BINDINGS);
            CASE(GSS_S_BAD_STATUS);
            CASE(GSS_S_BAD_SIG);
            CASE(GSS_S_NO_CRED);
            CASE(GSS_S_NO_CONTEXT);
            CASE(GSS_S_DEFECTIVE_TOKEN);
            CASE(GSS_S_CREDENTIALS_EXPIRED);
            CASE(GSS_S_CONTEXT_EXPIRED);
            CASE(GSS_S_BAD_QOP);
            CASE(GSS_S_UNAUTHORIZED);
            CASE(GSS_S_UNAVAILABLE);
            CASE(GSS_S_DUPLICATE_ELEMENT);
            CASE(GSS_S_NAME_NOT_MN);
            CASE(GSS_S_BAD_MECH_ATTR);
            /* supplementary info */
            CASE(GSS_S_CONTINUE_NEEDED);
            CASE(GSS_S_DUPLICATE_TOKEN);
            CASE(GSS_S_OLD_TOKEN);
            CASE(GSS_S_UNSEQ_TOKEN);
            CASE(GSS_S_GAP_TOKEN);

        default:
            return "Unknown Error";
    }
}

enum ntlm_err_code
{
    ERR_BASE = 0x4E540000, /* base error space at 'NT00' */
    ERR_DECODE,
    ERR_ENCODE,
    ERR_CRYPTO,
    ERR_NOARG,
    ERR_BADARG,
    ERR_NONAME,
    ERR_NOSRVNAME,
    ERR_NOUSRNAME,
    ERR_BADLMLVL,
    ERR_IMPOSSIBLE,
    ERR_BADCTX,
    ERR_WRONGCTX,
    ERR_WRONGMSG,
    ERR_REQNEGFLAG,
    ERR_FAILNEGFLAGS,
    ERR_BADNEGFLAGS,
    ERR_NOSRVCRED,
    ERR_NOUSRCRED,
    ERR_BADCRED,
    ERR_NOTOKEN,
    ERR_NOTSUPPORTED,
    ERR_NOTAVAIL,
    ERR_NAMETOOLONG,
    ERR_NOBINDINGS,
    ERR_TIMESKEW,
    ERR_EXPIRED,
    ERR_KEYLEN,
    ERR_NONTLMV1,
    ERR_NOUSRFOUND,
    ERR_LAST
};

static void print_min_status(tui32 err)
{
    gss_buffer_desc buf;
    tui32 msgctx = 0;
    tui32 retmaj;
    tui32 retmin;

    do
    {
        retmaj = gss_display_status(&retmin, err, GSS_C_MECH_CODE,
                                    NULL, &msgctx, &buf);

        if (retmaj)
        {
            LLOG(0, ("!!gssntlm_display_status failed for err=%d", err));
            msgctx = 0;
        }
        else
        {
            LLOG(0, ("%.*s%.*s",
                     (int)buf.length, (char *)buf.value,
                     msgctx, " "));
            (void)gss_release_buffer(&retmin, &buf);
        }
    }
    while (msgctx);
}

int test_Errors(void)
{
    int i;

    for (i = ERR_BASE; i < ERR_LAST; i++)
    {
        LLOGLN(0, ("%x: ", i));
        print_min_status(i);
        LLOGLN(0, (""));
    }

    return 0;
}

static void print_gss_error(const char *text, tui32 maj, tui32 min)
{

    LLOG(0, ("%s Major Error: [%s] Minor Error: [",
             text, gss_maj_to_str(maj)));
    print_min_status(min);
    LLOGLN(0, ("]"));
}


static void
cssp_gss_report_error(OM_uint32 code, char *str, OM_uint32 major_status, OM_uint32 minor_status)
{
    OM_uint32 msgctx = 0, ms;
    gss_buffer_desc status_string;

    //  LLOGLN(10, ("GSS error [%d:%d:%d]: %s\n", (major_status & 0xff000000) >> 24,    // Calling error
    //        (major_status & 0xff0000) >> 16,  // Routine error
    //        major_status & 0xffff,    // Supplementary info bits
    //        str));
    //
    //  do
    //  {
    //      ms = gss_display_status(&minor_status, major_status,
    //                  code, GSS_C_NULL_OID, &msgctx, &status_string);
    //      if (ms != GSS_S_COMPLETE)
    //          continue;
    //
    //      LLOGLN(10, (" - %s\n", (char *) status_string.value));
    //
    //  }
    //  while (ms == GSS_S_COMPLETE && msgctx);

    print_gss_error(str, major_status, minor_status);
}


int cssp_gss_mech_available(gss_OID mech)
{
    int mech_found;
    OM_uint32 major_status, minor_status;
    gss_OID_set mech_set;

    mech_found = 0;

    if (mech == GSS_C_NO_OID)
    {
        return 1;
    }

    major_status = gss_indicate_mechs(&minor_status, &mech_set);

    if (!mech_set)
    {
        return 0;
    }

    if (GSS_ERROR(major_status))
    {
        cssp_gss_report_error(GSS_C_GSS_CODE, "Failed to get available mechs on system",
                              major_status, minor_status);
        return 0;
    }

    gss_test_oid_set_member(&minor_status, mech, mech_set, &mech_found);

    if (GSS_ERROR(major_status))
    {
        cssp_gss_report_error(GSS_C_GSS_CODE, "Failed to match mechanism in set",
                              major_status, minor_status);
        return 0;
    }

    if (!mech_found)
    {
        return 0;
    }

    return 1;
}

static int
cssp_gss_get_service_name(char *server, gss_name_t *name)
{
    gss_buffer_desc output;
    OM_uint32 major_status, minor_status;

    const char service_name[] = "TERMSRV";

    gss_OID type = (gss_OID) GSS_C_NT_HOSTBASED_SERVICE;
    int size = (strlen(service_name) + 1 + strlen(server) + 1);

    output.value = malloc(size);
    snprintf(output.value, size, "%s@%s", service_name, server);
    output.length = strlen(output.value) + 1;

    major_status = gss_import_name(&minor_status, &output, type, name);

    if (GSS_ERROR(major_status))
    {
        cssp_gss_report_error(GSS_C_GSS_CODE, "Failed to create service principal name",
                              major_status, minor_status);
        return 0;
    }

    gss_release_buffer(&minor_status, &output);

    return 1;

}

static int
xrdp_nla_gss_unwrap(gss_ctx_id_t *ctx, struct blob *in, struct blob **out)
{
    OM_uint32 major_status;
    OM_uint32 minor_status;
    gss_qop_t qop_state;
    gss_buffer_desc inbuf, outbuf;
    int conf_state;

    inbuf.value = in->data;
    inbuf.length = in->length;

    major_status = gss_unwrap(&minor_status, ctx, &inbuf, &outbuf, &conf_state, &qop_state);

    if (major_status != GSS_S_COMPLETE)
    {
        cssp_gss_report_error(GSS_C_GSS_CODE, "Failed to decrypt message",
                              major_status, minor_status);
        return 0;
    }

    *out = xrdp_nla_make_blob(outbuf.length);
    g_memcpy((*out)->data, outbuf.value, outbuf.length);

    gss_release_buffer(&minor_status, &outbuf);

    return 1;
}

static int
xrdp_nla_gss_wrap(gss_ctx_id_t *ctx, struct blob *in, struct blob **out)
{
    int conf_state = 1;
    OM_uint32 major_status;
    OM_uint32 minor_status;
    gss_buffer_desc inbuf, outbuf;

    inbuf.value = in->data;
    inbuf.length = in->length;
    major_status = gss_wrap(&minor_status, ctx, 1,
                            GSS_C_QOP_DEFAULT, &inbuf, &conf_state, &outbuf);

    if (major_status != GSS_S_COMPLETE)
    {
        cssp_gss_report_error(GSS_C_GSS_CODE, "Failed to encrypt and sign message",
                              major_status, minor_status);
        return 0;
    }

    //  if (!conf_state)
    //  {
    //      g_writeln("GSS Confidentiality failed, no encryption of message performed.");
    //      return 0;
    //  }

    // write enc data to out stream
    *out = xrdp_nla_make_blob(outbuf.length);
    g_memcpy((*out)->data, outbuf.value, outbuf.length);

    gss_release_buffer(&minor_status, &outbuf);

    return 1;
}


