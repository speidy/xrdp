/**
 * FreeRDP: A Remote Desktop Protocol Client
 * ASN.1 Basic Encoding Rules (BER)
 *
 * Copyright 2011 Marc-Andre Moreau <marcandre.moreau@gmail.com>
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
 */

#include "ber.h"
#include "os_calls.h"

int ber_read_length(struct stream *s, int *length)
{
    tui8 byte = 0;

    if (xstream_get_left(s) < 1)
    {
        return 0;
    }
    in_uint8(s, byte);

    if (byte & 0x80)
    {
        byte &= ~(0x80);

        if (xstream_get_left(s) < byte)
        {
            return 0;
        }

        if (byte == 1)
        {
            in_uint8(s, *length);
        }
        else if (byte == 2)
        {
            in_uint16_be(s, *length);
        }
        else
        {
            return 0;
        }
    }
    else
    {
        *length = byte;
    }

    return 1;
}

/**
 * Write BER length.
 * @param s stream
 * @param length length
 */

int ber_write_length(struct stream *s, int length)
{
    if (length > 0xFF)
    {
        out_uint8(s, 0x80 ^ 2);
        out_uint16_be(s, length);
        return 3;
    }
    if (length > 0x7F)
    {
        out_uint8(s, 0x80 ^ 1);
        out_uint8(s, length);
        return 2;
    }
    out_uint8(s, length);
    return 1;
}

int _ber_sizeof_length(int length)
{
    if (length > 0xFF)
        return 3;
    if (length > 0x7F)
        return 2;
    return 1;
}

/**
 * Read BER Universal tag.
 * @param s stream
 * @param tag BER universally-defined tag
 * @return
 */

int ber_read_universal_tag(struct stream *s, tui8 tag, int pc)
{
    tui8 byte = 0;

    if (xstream_get_left(s) < 1)
    {
        return 0;
    }
    in_uint8(s, byte);


    if (byte != (BER_CLASS_UNIV | BER_PC(pc) | (BER_TAG_MASK & tag)))
    {
        return 0;
    }

    return 1;
}

/**
 * Write BER Universal tag.
 * @param s stream
 * @param tag BER universally-defined tag
 * @param pc primitive (0) or constructed (1)
 */

int ber_write_universal_tag(struct stream *s, tui8 tag, int pc)
{
    out_uint8(s, (BER_CLASS_UNIV | BER_PC(pc)) | (BER_TAG_MASK & tag));
    return 1;
}

/**
 * Read BER Application tag.
 * @param s stream
 * @param tag BER application-defined tag
 * @param length length
 */

int ber_read_application_tag(struct stream *s, tui8 tag, int *length)
{
    tui8 byte = 0;

    if (tag > 30)
    {
        if (xstream_get_left(s) < 1)
        {
            return 0;
        }
        in_uint8(s, byte);

        if (byte != ((BER_CLASS_APPL | BER_CONSTRUCT) | BER_TAG_MASK))
            return 0;

        if (xstream_get_left(s) < 1)
        {
            return 0;
        }
        in_uint8(s, byte);

        if (byte != tag)
            return 0;

        return ber_read_length(s, length);
    }
    else
    {
        if (xstream_get_left(s) < 1)
        {
            return 0;
        }
        in_uint8(s, byte);

        if (byte != ((BER_CLASS_APPL | BER_CONSTRUCT) | (BER_TAG_MASK & tag)))
            return 0;

        return ber_read_length(s, length);
    }

    return 1;
}

/**
 * Write BER Application tag.
 * @param s stream
 * @param tag BER application-defined tag
 * @param length length
 */

void ber_write_application_tag(struct stream *s, tui8 tag, int length)
{
    if (tag > 30)
    {
        out_uint8(s, (BER_CLASS_APPL | BER_CONSTRUCT) | BER_TAG_MASK);
        out_uint8(s, tag);
        ber_write_length(s, length);
    }
    else
    {
        out_uint8(s, (BER_CLASS_APPL | BER_CONSTRUCT) | (BER_TAG_MASK & tag));
        ber_write_length(s, length);
    }
}

int ber_read_contextual_tag(struct stream *s, tui8 tag, int *length, int pc)
{
    tui8 byte = 0;

    if (xstream_get_left(s) < 1)
    {
        return 0;
    }
    in_uint8(s, byte);

    if (byte != ((BER_CLASS_CTXT | BER_PC(pc)) | (BER_TAG_MASK & tag)))
    {
        xstream_rewind(s, 1);
        return 0;
    }

    return ber_read_length(s, length);
}

int ber_write_contextual_tag(struct stream *s, tui8 tag, int length, int pc)
{
    out_uint8(s, (BER_CLASS_CTXT | BER_PC(pc)) | (BER_TAG_MASK & tag));
    return 1 + ber_write_length(s, length);
}

int ber_sizeof_contextual_tag(int length)
{
    return 1 + _ber_sizeof_length(length);
}

int ber_read_sequence_tag(struct stream *s, int *length)
{
    tui8 byte = 0;

    if (xstream_get_left(s) < 1)
    {
        return 0;
    }
    in_uint8(s, byte);

    if (byte != ((BER_CLASS_UNIV | BER_CONSTRUCT) | (BER_TAG_SEQUENCE_OF)))
    {
        return 0;
    }

    return ber_read_length(s, length);
}

/**
 * Write BER SEQUENCE tag.
 * @param s stream
 * @param length length
 */

int ber_write_sequence_tag(struct stream *s, int length)
{
    out_uint8(s, (BER_CLASS_UNIV | BER_CONSTRUCT) | (BER_TAG_MASK & BER_TAG_SEQUENCE));
    return 1 + ber_write_length(s, length);
}

int ber_sizeof_sequence(int length)
{
    return 1 + _ber_sizeof_length(length) + length;
}

int ber_sizeof_sequence_tag(int length)
{
    return 1 + _ber_sizeof_length(length);
}

int ber_read_enumerated(struct stream *s, tui8 *enumerated, tui8 count)
{
    int length;

    if (!ber_read_universal_tag(s, BER_TAG_ENUMERATED, 0) ||
            !ber_read_length(s, &length))
    {
        return 0;
    }


    if (length != 1 || xstream_get_left(s) < 1)
    {
        return 0;
    }

    in_uint8(s, *enumerated);

    /* check that enumerated value falls within expected range */
    if (*enumerated + 1 > count)
        return 0;

    return 1;
}

void ber_write_enumerated(struct stream *s, tui8 enumerated, tui8 count)
{
    ber_write_universal_tag(s, BER_TAG_ENUMERATED, 0);
    ber_write_length(s, 1);
    out_uint8(s, enumerated);
}

int ber_read_bit_string(struct stream *s, int *length, tui8 *padding)
{
    if (!ber_read_universal_tag(s, BER_TAG_BIT_STRING, 0) ||
            !ber_read_length(s, length))
    {
        return 0;
    }

    if (xstream_get_left(s) < 1)
    {
        return 0;
    }

    in_uint8(s, *padding);

    return 1;
}

int ber_read_octet_string(struct stream *s, int *length)
{
    ber_read_universal_tag(s, BER_TAG_OCTET_STRING, 0);
    ber_read_length(s, length);

    return 1;
}

/**
 * Write a BER OCTET_STRING
 * @param s stream
 * @param oct_str octet string
 * @param length string length
 */

int ber_write_octet_string(struct stream *s, const tui8 *oct_str, int length)
{
    int size = 0;
    size += ber_write_universal_tag(s, BER_TAG_OCTET_STRING, 0);
    size += ber_write_length(s, length);
    out_uint8a(s, oct_str, length);
    size += length;
    return size;

}

int ber_read_octet_string_tag(struct stream *s, int *length)
{
    return
        ber_read_universal_tag(s, BER_TAG_OCTET_STRING, 0) &&
        ber_read_length(s, length);
}


int ber_write_octet_string_tag(struct stream *s, int length)
{
    ber_write_universal_tag(s, BER_TAG_OCTET_STRING, 0);
    ber_write_length(s, length);
    return 1 + _ber_sizeof_length(length);
}

int ber_sizeof_octet_string(int length)
{
    return 1 + _ber_sizeof_length(length) + length;
}

/**
 * Read a BER BOOLEAN
 * @param s
 * @param value
 */

int ber_read_boolean(struct stream *s, int *value)
{
    int length;
    tui8 v = 0;

    if (!ber_read_universal_tag(s, BER_TAG_BOOLEAN, 0) ||
            !ber_read_length(s, &length))
        return 0;

    if (length != 1 || xstream_get_left(s) < 1)
        return 0;

    in_uint8(s, v);
    *value = (v ? 1 : 0);

    return 1;
}

/**
 * Write a BER BOOLEAN
 * @param s
 * @param value
 */

void ber_write_boolean(struct stream *s, int value)
{
    ber_write_universal_tag(s, BER_TAG_BOOLEAN, 0);
    ber_write_length(s, 1);
    out_uint8(s, value ? 0xFF : 0);
}

int ber_read_integer(struct stream *s, tui32 *value)
{
    int length;

    if (!ber_read_universal_tag(s, BER_TAG_INTEGER, 0) ||
            !ber_read_length(s, &length) ||
            xstream_get_left(s) < length)
    {
        return 0;
    }

    if (value == NULL)
    {
        if (xstream_get_left(s) < length)
        {
            return 0;
        }
        in_uint8s(s, length);
        return 1;
    }

    if (length == 1)
    {
        in_uint8(s, *value);
    }
    else if (length == 2)
    {
        in_uint16_be(s, *value);
    }
    else if (length == 3)
    {
        tui8 byte = 0;
        in_uint8(s, byte);
        in_uint16_be(s, *value);
        *value += (byte << 16);
    }
    else if (length == 4)
    {
        in_uint32_be(s, *value);
    }
    else if (length == 8)
    {
        g_writeln("%s: should implement reading an 8 bytes integer\n", __FUNCTION__);
        return 0;
    }
    else
    {
        g_writeln("%s: should implement reading an integer with length=%d\n", __FUNCTION__, length);
        return 0;
    }

    return 1;
}

/**
 * Write a BER INTEGER
 * @param s
 * @param value
 */

int ber_write_integer(struct stream *s, tui32 value)
{

    if (value < 0x80)
    {
        ber_write_universal_tag(s, BER_TAG_INTEGER, 0);
        ber_write_length(s, 1);
        out_uint8(s, value);
        return 3;
    }
    else if (value < 0x8000)
    {
        ber_write_universal_tag(s, BER_TAG_INTEGER, 0);
        ber_write_length(s, 2);
        out_uint16_be(s, value);
        return 4;
    }
    else if (value < 0x800000)
    {
        ber_write_universal_tag(s, BER_TAG_INTEGER, 0);
        ber_write_length(s, 3);
        out_uint8(s, (value >> 16));
        out_uint16_be(s, (value & 0xFFFF));
        return 5;
    }
    else if (value < 0x80000000)
    {
        ber_write_universal_tag(s, BER_TAG_INTEGER, 0);
        ber_write_length(s, 4);
        out_uint32_be(s, value);
        return 6;
    }

    return 0;
}

int ber_sizeof_integer(tui32 value)
{
    if (value < 0x80)
    {
        return 3;
    }
    else if (value < 0x8000)
    {
        return 4;
    }
    else if (value < 0x800000)
    {
        return 5;
    }
    else if (value < 0x80000000)
    {
        return 6;
    }

    return 0;
}

int ber_read_integer_length(struct stream *s, int *length)
{
    return
        ber_read_universal_tag(s, BER_TAG_INTEGER, 0) &&
        ber_read_length(s, length);
}
