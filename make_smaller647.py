import struct
import hashlib
import binascii
import os
import zipfile

import zopfli.zlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


OUT = "Planet-Smaller647.apk"

ALG = 0x0201
V2_ID = 0x7109871A
SIG_TRIES = 200000

NO_INDEX = 0xffffffff


# ============================================================
# BASIC HELPERS
# ============================================================

def u32(x):
    return struct.pack("<I", x)


def u64(x):
    return struct.pack("<Q", x)


def lp(x):
    return u32(len(x)) + x


def raw_deflate(data):
    z = zopfli.zlib.compress(
        data,
        numiterations=1000
    )
    return z[2:-4]


# ============================================================
# BINARY XML HELPERS
# ============================================================

def len8(n):
    if n < 0x80:
        return bytes([n])

    return bytes([
        0x80 | ((n >> 8) & 0x7f),
        n & 0xff
    ])


def make_string_pool(strings):

    string_data = bytearray()
    offsets = []

    for s in strings:

        offsets.append(
            len(string_data)
        )

        b = s.encode("utf-8")

        string_data += len8(len(s))
        string_data += len8(len(b))
        string_data += b
        string_data += b"\0"

    header_size = 28

    strings_start = (
        header_size
        + 4 * len(strings)
    )

    while (
        strings_start
        + len(string_data)
    ) & 3:

        string_data += b"\0"

    chunk_size = (
        strings_start
        + len(string_data)
    )

    out = bytearray()

    out += struct.pack(
        "<HHI",
        0x0001,
        28,
        chunk_size
    )

    out += struct.pack(
        "<IIIII",
        len(strings),
        0,
        0x100,
        strings_start,
        0
    )

    for off in offsets:
        out += struct.pack(
            "<I",
            off
        )

    out += string_data

    return bytes(out)


def start_element(name_idx, attrs):

    count = len(attrs)

    chunk_size = (
        36
        + 20 * count
    )

    out = bytearray()

    out += struct.pack(
        "<HHI",
        0x0102,
        16,
        chunk_size
    )

    out += struct.pack(
        "<II",
        0,
        NO_INDEX
    )

    out += struct.pack(
        "<IIHHHHHH",
        NO_INDEX,
        name_idx,
        20,
        20,
        count,
        0,
        0,
        0
    )

    for (
        namespace_idx,
        attr_name_idx,
        raw_value_idx,
        value_type,
        value_data
    ) in attrs:

        out += struct.pack(
            "<III",
            namespace_idx,
            attr_name_idx,
            raw_value_idx
        )

        out += struct.pack(
            "<HBBI",
            8,
            0,
            value_type,
            value_data
        )

    return bytes(out)


def end_element(name_idx):

    return (
        struct.pack(
            "<HHI",
            0x0103,
            16,
            24
        )
        +
        struct.pack(
            "<II",
            0,
            NO_INDEX
        )
        +
        struct.pack(
            "<II",
            NO_INDEX,
            name_idx
        )
    )


# ============================================================
# MINIMAL MANIFEST
#
# <manifest package="a.a"/>
# ============================================================

strings = [
    "manifest",
    "package",
    "a.a",
]

MANIFEST = 0
PACKAGE = 1
PACKAGE_VALUE = 2


pool = make_string_pool(
    strings
)


manifest_start = start_element(
    MANIFEST,
    [
        (
            NO_INDEX,
            PACKAGE,
            PACKAGE_VALUE,
            0x03,
            PACKAGE_VALUE
        )
    ]
)


manifest_end = end_element(
    MANIFEST
)


xml_body = (
    pool
    + manifest_start
    + manifest_end
)


manifest = (
    struct.pack(
        "<HHI",
        0x0003,
        8,
        8 + len(xml_body)
    )
    + xml_body
)


print(
    "MANIFEST RAW:",
    len(manifest),
    "bytes"
)

print(
    "MANIFEST DEFLATE:",
    len(raw_deflate(manifest)),
    "bytes"
)


# ============================================================
# DER HELPERS
# ============================================================

def der_len(n):

    if n < 128:
        return bytes([n])

    b = n.to_bytes(
        (n.bit_length() + 7) // 8,
        "big"
    )

    return (
        bytes([
            0x80 | len(b)
        ])
        + b
    )


def der(tag, content):

    return (
        bytes([tag])
        + der_len(len(content))
        + content
    )


def seq(content):
    return der(
        0x30,
        content
    )


def integer(n):

    b = n.to_bytes(
        max(
            1,
            (n.bit_length() + 7) // 8
        ),
        "big"
    )

    if b[0] & 0x80:
        b = b"\0" + b

    return der(
        0x02,
        b
    )


def bit_string(data):

    return der(
        0x03,
        b"\0" + data
    )


def utc_time(s):

    return der(
        0x17,
        s.encode("ascii")
    )


# ============================================================
# CERTIFICATE CONSTANTS
# ============================================================

OID_EC_PUBLIC_KEY = bytes.fromhex(
    "06072A8648CE3D0201"
)

OID_P256 = bytes.fromhex(
    "06082A8648CE3D030107"
)

# Short syntactically valid OID: 1.2.3
OID_TINY = bytes.fromhex(
    "06022A03"
)


ALG_PUBLIC_KEY = seq(
    OID_EC_PUBLIC_KEY
    + OID_P256
)

ALG_CERT = seq(
    OID_TINY
)


# ============================================================
# GENERATE P-256 KEY
# ============================================================

key = ec.generate_private_key(
    ec.SECP256R1()
)

nums = (
    key.public_key()
    .public_numbers()
)

x = nums.x.to_bytes(
    32,
    "big"
)

y = nums.y.to_bytes(
    32,
    "big"
)


# compressed point inside certificate
compressed_point = (
    (
        b"\x03"
        if nums.y & 1
        else b"\x02"
    )
    + x
)


# uncompressed point inside APK v2 signer
normal_point = (
    b"\x04"
    + x
    + y
)


spki_cert = seq(
    ALG_PUBLIC_KEY
    + bit_string(
        compressed_point
    )
)

spki_normal = seq(
    ALG_PUBLIC_KEY
    + bit_string(
        normal_point
    )
)


# ============================================================
# TINY CERTIFICATE
# ============================================================

empty_name = seq(
    b""
)


# Keep normal UTCTime format
validity = seq(
    utc_time(
        "260101000000Z"
    )
    +
    utc_time(
        "270101000000Z"
    )
)


tbs = seq(
    integer(1)
    + ALG_CERT
    + empty_name
    + validity
    + empty_name
    + spki_cert
)


# empty certificate self-signature
cert_der = seq(
    tbs
    + ALG_CERT
    + bit_string(
        b""
    )
)


print(
    "CERTIFICATE:",
    len(cert_der),
    "bytes"
)


# ============================================================
# ONE ZIP ENTRY
# ============================================================

name = b"AndroidManifest.xml"

compressed = raw_deflate(
    manifest
)

crc = (
    binascii.crc32(
        manifest
    )
    & 0xffffffff
)


# ============================================================
# LOCAL FILE HEADER
# ============================================================

prefix = bytearray()

prefix += struct.pack(
    "<IHHHHHIIIHH",

    0x04034b50,

    20,
    0,
    8,

    0,
    0,

    crc,

    len(compressed),
    len(manifest),

    len(name),

    0
)

prefix += name
prefix += compressed


# ============================================================
# CENTRAL DIRECTORY
# ============================================================

central = bytearray()

central += struct.pack(
    "<IHHHHHHIIIHHHHHII",

    0x02014b50,

    20,
    20,

    0,
    8,

    0,
    0,

    crc,

    len(compressed),
    len(manifest),

    len(name),

    0,
    0,
    0,
    0,
    0,

    0
)

central += name


signing_block_offset = len(
    prefix
)


# ============================================================
# EOCD USED FOR V2 DIGEST
# ============================================================

digest_eocd = struct.pack(
    "<IHHHHIIH",

    0x06054b50,

    0,
    0,

    1,
    1,

    len(central),

    signing_block_offset,

    0
)


# ============================================================
# APK V2 CONTENT DIGEST
# ============================================================

def chunk_digest(data):

    return hashlib.sha256(
        b"\xA5"
        + u32(len(data))
        + data
    ).digest()


chunks = [
    chunk_digest(
        bytes(prefix)
    ),

    chunk_digest(
        bytes(central)
    ),

    chunk_digest(
        digest_eocd
    )
]


content_digest = hashlib.sha256(
    b"\x5A"
    + u32(len(chunks))
    + b"".join(chunks)
).digest()


# ============================================================
# V2 SIGNED DATA
# ============================================================

digest_record = (
    u32(ALG)
    + lp(
        content_digest
    )
)

digests = lp(
    lp(
        digest_record
    )
)

certificates = lp(
    lp(
        cert_der
    )
)

attributes = lp(
    b""
)

signed_data = (
    digests
    + certificates
    + attributes
)


# ============================================================
# FIND SHORTEST VALID ECDSA SIGNATURE
# ============================================================

best_sig = None


for attempt in range(
    SIG_TRIES
):

    sig = key.sign(
        signed_data,
        ec.ECDSA(
            hashes.SHA256()
        )
    )

    if (
        best_sig is None
        or len(sig) < len(best_sig)
    ):

        best_sig = sig

        print(
            "APK SIGNATURE:",
            len(sig),
            "attempt:",
            attempt
        )

        if len(sig) <= 69:
            break


# ============================================================
# V2 SIGNER
# ============================================================

signature_record = (
    u32(ALG)
    + lp(
        best_sig
    )
)

signatures = lp(
    lp(
        signature_record
    )
)

public_key = lp(
    spki_normal
)

signer = (
    lp(
        signed_data
    )
    + signatures
    + public_key
)

signers = lp(
    lp(
        signer
    )
)

v2_value = signers


# ============================================================
# APK SIGNING BLOCK
# ============================================================

pair = (
    u64(
        4 + len(v2_value)
    )
    + u32(
        V2_ID
    )
    + v2_value
)

block_size = (
    len(pair)
    + 8
    + 16
)

signing_block = (
    u64(
        block_size
    )
    + pair
    + u64(
        block_size
    )
    + b"APK Sig Block 42"
)


print(
    "SIGNING BLOCK:",
    len(signing_block),
    "bytes"
)


# ============================================================
# FINAL EOCD
# ============================================================

real_cd_offset = (
    signing_block_offset
    + len(signing_block)
)

final_eocd = struct.pack(
    "<IHHHHIIH",

    0x06054b50,

    0,
    0,

    1,
    1,

    len(central),

    real_cd_offset,

    0
)


# ============================================================
# WRITE APK
# ============================================================

with open(
    OUT,
    "wb"
) as f:

    f.write(prefix)
    f.write(signing_block)
    f.write(central)
    f.write(final_eocd)


print()
print(
    "================================"
)

print(
    "FINAL APK:",
    os.path.getsize(OUT),
    "bytes"
)

print(
    "================================"
)


with zipfile.ZipFile(
    OUT
) as z:

    print(
        "ENTRIES:",
        z.namelist()
    )

    print(
        "BAD ENTRY:",
        z.testzip()
    )