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
 * NLA authentication layer
 */


#include "libxrdp.h"
#include "log.h"
//#include "/opt/krb5/usr/local/include/gssapi/gssapi.h"
//#include "/opt/libntlmssp/include/gssapi/gssapi_ntlmssp.h"
#include <gssapi/gssapi.h>

#define ber_sizeof_sequence_octet_string(length) ber_sizeof_contextual_tag(ber_sizeof_octet_string(length)) + ber_sizeof_octet_string(length)
#define ber_write_sequence_octet_string(stream, context, value, length) ber_write_contextual_tag(stream, context, ber_sizeof_octet_string(length), 1) + ber_write_octet_string(stream, value, length)

/* NTLMSSP OID: 1.3.6.1.4.1.311.2.2.10 */
#define GSS_NTLMSSP_OID_STRING "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"
#define GSS_NTLMSSP_OID_LENGTH 10


#define LOG_LEVEL 11
#define LLOG(_level, _args) \
    do { if (_level < LOG_LEVEL) { g_write _args ; } } while (0)
#define LLOGLN(_level, _args) \
    do { if (_level < LOG_LEVEL) { g_writeln _args ; } } while (0)
#define LHEXDUMP(_level, _args) \
    do { if (_level < LOG_LEVEL) { g_hexdump _args ; } } while (0)


static gss_OID_desc g_ntlmsspOID = {
		GSS_NTLMSSP_OID_LENGTH,
		GSS_NTLMSSP_OID_STRING
};



/*****************************************************************************/
struct xrdp_nla *APP_CC
xrdp_nla_create(struct xrdp_sec *owner, struct trans *trans)
{
    struct xrdp_nla *self;

    LLOGLN(10, ("   in xrdp_nla_create"));
    self = (struct xrdp_nla *) g_malloc(sizeof(struct xrdp_nla), 1);
    self->sec_layer = owner;
    self->trans = trans;
    LLOGLN(10, ("   out xrdp_nla_create"));
    return self;
}

/*****************************************************************************/
void APP_CC
xrdp_nla_delete(struct xrdp_nla *self)
{
    if (self == 0)
    {
        return;
    }

    g_free(self);
}

/*****************************************************************************/
struct blob *
xrdp_nla_make_blob(int length)
{
	if (!length)
	{
		return 1; /* error */
	}

	struct blob *b = g_malloc(sizeof(struct blob), 1);

	if (!b)
	{
		return 1; /* error */
	}

	b->data = g_malloc(length, 1);
	b->length = length;

	return b;
}

/*****************************************************************************/
int
xrdp_nla_free_blob(struct blob *b)
{
	if (!b)
	{
		return 1; /* error */
	}
	if (b->data)
	{
		g_free(b->data);
		b->data = NULL;
	}
	b->length = 0;
	g_free(b);
	return 0;
}


/*****************************************************************************/
int APP_CC
xrdp_nla_recv_tsrequest(struct xrdp_nla *self)
{
    LLOGLN(10, ("   in xrdp_nla_recv_tsrequest"));
	int len = 0;
	int version = 0;
	struct stream *s;

    s = libxrdp_force_read(self->trans);

    if (s == 0)
    {
    	return 1;
    }

    ber_read_sequence_tag(s, &len);

    /* [0] version (INTEGER) */
    ber_read_contextual_tag(s, 0, &len, 1);
	ber_read_integer(s, &version);

	/* [1] negoTokens (NegoData) */
	if (ber_read_contextual_tag(s, 1, &len, 1) != 0)
	{
		ber_read_sequence_tag(s, &len); /* SEQUENCE OF NegoDataItem */
		ber_read_sequence_tag(s, &len); /* NegoDataItem */
		ber_read_contextual_tag(s, 0, &len, 1); /* [0] negoToken */
		ber_read_octet_string_tag(s, &len); /* OCTET STRING */
		self->negoTokens = xrdp_nla_make_blob(len);
		in_uint8a(s, self->negoTokens->data, len);
	}

	/* [2] authInfo (OCTET STRING) */
	if (ber_read_contextual_tag(s, 2, &len, 1) != 0)
	{
		ber_read_octet_string_tag(s, &len); /* OCTET STRING */
		self->authInfo = xrdp_nla_make_blob(len);
		in_uint8a(s, self->authInfo->data, len);
	}

	/* [3] pubKeyAuth (OCTET STRING) */
	if (ber_read_contextual_tag(s, 3, &len, 1) != 0)
	{
		ber_read_octet_string_tag(s, &len); /* OCTET STRING */
		self->pubKeyAuth = xrdp_nla_make_blob(len);
		in_uint8a(s, self->pubKeyAuth->data, len);
	}

	/* [4] errorCode (INTEGER) */
	if (ber_read_contextual_tag(s, 4, &len, 1) != 0)
	{
		ber_read_octet_string_tag(s, &len); /* INTEGER */
//		self->errorCode = xrdp_nla_make_blob(len);
		//todo: handle errorCode
		in_uint8s(s, len);
	}

//	xstream_free(s);

    LLOGLN(10, ("   out xrdp_nla_recv_tsrequest"));
	return 0;
}



int credssp_sizeof_nego_token(int length)
{
	length = ber_sizeof_octet_string(length);
	length += ber_sizeof_contextual_tag(length);
	return length;
}

int credssp_sizeof_nego_tokens(int length)
{
	length = credssp_sizeof_nego_token(length);
	length += ber_sizeof_sequence_tag(length);
	length += ber_sizeof_sequence_tag(length);
	length += ber_sizeof_contextual_tag(length);
	return length;
}

int credssp_sizeof_pub_key_auth(int length)
{
	length = ber_sizeof_octet_string(length);
	length += ber_sizeof_contextual_tag(length);
	return length;
}

int credssp_sizeof_auth_info(int length)
{
	length = ber_sizeof_octet_string(length);
	length += ber_sizeof_contextual_tag(length);
	return length;
}

int credssp_sizeof_ts_request(int length)
{
	length += ber_sizeof_integer(2);
	length += ber_sizeof_contextual_tag(3);
	return length;
}



/*****************************************************************************/
void xrdp_nla_send_tsrequest(struct xrdp_nla *self)
{
	struct stream* s;
	int length;
	int ts_request_length;
	int nego_tokens_length;
	int pub_key_auth_length;
	int auth_info_length;

	nego_tokens_length = (self->negoTokens != NULL) ? credssp_sizeof_nego_tokens(self->negoTokens->length) : 0;
	pub_key_auth_length = (self->pubKeyAuth != NULL) ? credssp_sizeof_pub_key_auth(self->pubKeyAuth->length) : 0;
	auth_info_length = (self->authInfo != NULL) ? credssp_sizeof_auth_info(self->authInfo->length) : 0;

	length = nego_tokens_length + pub_key_auth_length + auth_info_length;

	ts_request_length = credssp_sizeof_ts_request(length);

	xstream_new(s, ber_sizeof_sequence(ts_request_length));

	/* TSRequest */
	ber_write_sequence_tag(s, ts_request_length); /* SEQUENCE */

	/* [0] version */
	ber_write_contextual_tag(s, 0, 3, 1);
	ber_write_integer(s, 2); /* INTEGER */

	/* [1] negoTokens (NegoData) */
	if (nego_tokens_length > 0)
	{
		length = nego_tokens_length;

		length -= ber_write_contextual_tag(s, 1, ber_sizeof_sequence(ber_sizeof_sequence(ber_sizeof_sequence_octet_string(self->negoTokens->length))), 1); /* NegoData */
		length -= ber_write_sequence_tag(s, ber_sizeof_sequence(ber_sizeof_sequence_octet_string(self->negoTokens->length))); /* SEQUENCE OF NegoDataItem */
		length -= ber_write_sequence_tag(s, ber_sizeof_sequence_octet_string(self->negoTokens->length)); /* NegoDataItem */
		length -= ber_write_sequence_octet_string(s, 0, self->negoTokens->data, self->negoTokens->length); /* OCTET STRING */
	}

	/* [2] authInfo (OCTET STRING) */
	if (auth_info_length > 0)
	{
		length = auth_info_length;
		length -= ber_write_sequence_octet_string(s, 2, self->authInfo->data, self->authInfo->length);
	}

	/* [3] pubKeyAuth (OCTET STRING) */
	if (pub_key_auth_length > 0)
	{
		length = pub_key_auth_length;
		length -= ber_write_sequence_octet_string(s, 3, self->pubKeyAuth->data, self->pubKeyAuth->length);
	}

	s_mark_end(s);

	// send tsrequest
	trans_force_write_s(self->trans, s);

	xstream_free(s);
}


#define CASE(X) case X: return #X

const char *gss_maj_to_str(uint32_t err)
{
    switch (err) {
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

enum ntlm_err_code {
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

static void print_min_status(uint32_t err)
{
    gss_buffer_desc buf;
    uint32_t msgctx = 0;
    uint32_t retmaj;
    uint32_t retmin;

    do {
        retmaj = gss_display_status(&retmin, err, GSS_C_MECH_CODE,
                                        NULL, &msgctx, &buf);
        if (retmaj) {
            LLOG(0, ("!!gssntlm_display_status failed for err=%d", err));
            msgctx = 0;
        } else {
        	LLOG(0, ("%.*s%.*s",
                            (int)buf.length, (char *)buf.value,
                            msgctx, " "));
            (void)gss_release_buffer(&retmin, &buf);
        }
    } while (msgctx);
}

int test_Errors(void)
{
    int i;
    for (i = ERR_BASE; i < ERR_LAST; i++) {
    	LLOGLN(0, ("%x: ", i));
        print_min_status(i);
        LLOGLN(0, (""));
    }
    return 0;
}

static void print_gss_error(const char *text, uint32_t maj, uint32_t min)
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

//	LLOGLN(10, ("GSS error [%d:%d:%d]: %s\n", (major_status & 0xff000000) >> 24,	// Calling error
//	      (major_status & 0xff0000) >> 16,	// Routine error
//	      major_status & 0xffff,	// Supplementary info bits
//	      str));
//
//	do
//	{
//		ms = gss_display_status(&minor_status, major_status,
//					code, GSS_C_NULL_OID, &msgctx, &status_string);
//		if (ms != GSS_S_COMPLETE)
//			continue;
//
//		LLOGLN(10, (" - %s\n", (char *) status_string.value));
//
//	}
//	while (ms == GSS_S_COMPLETE && msgctx);

	print_gss_error(str, major_status, minor_status);
}


int cssp_gss_mech_available(gss_OID mech)
{
	int mech_found;
	OM_uint32 major_status, minor_status;
	gss_OID_set mech_set;

	mech_found = 0;

	if (mech == GSS_C_NO_OID)
		return 1;

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
cssp_gss_get_service_name(char *server, gss_name_t * name)
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

//	if (!conf_state)
//	{
//		g_writeln("GSS Confidentiality failed, no encryption of message performed.");
//		return 0;
//	}

	// write enc data to out stream
	*out = xrdp_nla_make_blob(outbuf.length);
	g_memcpy((*out)->data, outbuf.value, outbuf.length);

	gss_release_buffer(&minor_status, &outbuf);

	return 1;
}

void ap_integer_increment_le(struct blob* b)
{
	int index;
	int size = b->length;
	unsigned char *number = b->data;

	for (index = 0; index < size; index++)
	{
		if (number[index] < 0xFF)
		{
			number[index]++;
			break;
		}
		else
		{
			number[index] = 0;
			continue;
		}
	}
}

/*****************************************************************************/
#define discard_const(ptr) ((void *)((uintptr_t)(ptr)))
#define TEST_USER_FILE "/tmp/ntlmusers"
int APP_CC
xrdp_nla_authenticate(struct xrdp_nla *self)
{
    LLOGLN(10, ("     in xrdp_nla_authenticate"));
	OM_uint32 actual_time, time_req, time_rec;
	OM_uint32 major_status, minor_status;
	OM_uint32 actual_services;
	gss_name_t target_name, gss_srvname;
	gss_OID desired_mech = &g_ntlmsspOID, actual_mech;
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

//	const char *srvname = "test@testserver";
//
//	nbuf.value = discard_const(srvname);
//	nbuf.length = g_strlen(srvname);
//	major_status = gss_import_name(&minor_status, &nbuf,
//								GSS_C_NT_HOSTBASED_SERVICE,
//								 &gss_srvname);
//	if (GSS_ERROR(major_status))
//	{
//		cssp_gss_report_error(GSS_C_GSS_CODE, "gssntlm_import_name failed",
//				      major_status, minor_status);
//		g_writeln("minor %x", minor_status);
//		return 1;
//	}
//
//	desired_oid_set.count = 1;
//	desired_oid_set.elements = desired_mech;

	g_writeln("gss_acquire_cred ...");
	major_status = gss_acquire_cred(&minor_status,
			GSS_C_NO_NAME,
			GSS_C_INDEFINITE,
			GSS_C_NO_OID_SET,
			GSS_C_ACCEPT,
			&cred,
			NULL,
			NULL
			);
	if (GSS_ERROR(major_status))
	{
		cssp_gss_report_error(GSS_C_GSS_CODE, "gss_acquire_cred failed",
				      major_status, minor_status);
		g_writeln("minor %x", minor_status);
		return 1;
	}


	gss_ctx = GSS_C_NO_CONTEXT;
//		cred = GSS_C_NO_CREDENTIAL;

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
		major_status = gss_accept_sec_context(
				&minor_status,
				&gss_ctx,
				cred,
				&input_tok,
				GSS_C_NO_CHANNEL_BINDINGS,
				NULL,
				NULL,
				&output_tok,
				&actual_services,
				NULL,
				NULL
				);

		if (GSS_ERROR(major_status))
		{
			cssp_gss_report_error(GSS_C_GSS_CODE, "gss_accept_sec_context failed",
						  major_status, minor_status);
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

	} while (!context_established);

	g_writeln("out of gssapi loop");
	// validate required services
	if (!(actual_services & GSS_C_CONF_FLAG))
	{
		LLOGLN(0, ("xrdp_nla_authenticate: Confidentiality service required but is not available."));
//		goto bail_out;
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
