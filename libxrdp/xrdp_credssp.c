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
 * CredSSP, Network Level Authentication
 *
 * [MS-CSSP] https://msdn.microsoft.com/en-us/library/cc226764.aspx
 */


#include "libxrdp.h"
#include "log.h"

#define LOG_LEVEL 11
#define LLOG(_level, _args) \
    do { if (_level < LOG_LEVEL) { g_write _args ; } } while (0)
#define LLOGLN(_level, _args) \
    do { if (_level < LOG_LEVEL) { g_writeln _args ; } } while (0)
#define LHEXDUMP(_level, _args) \
    do { if (_level < LOG_LEVEL) { g_hexdump _args ; } } while (0)


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
        //      self->errorCode = xrdp_nla_make_blob(len);
        //todo: handle errorCode
        in_uint8s(s, len);
    }

    //  xstream_free(s);

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
    struct stream *s;
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


void ap_integer_increment_le(struct blob *b)
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

