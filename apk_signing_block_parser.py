#!/usr/bin/python3

import binascii
import struct
import sys

from enum import Enum, auto

try:
    from asn1crypto import x509, keys
except ImportError:
    x509 = keys = None


class ID(Enum):
    ADDITIONAL_ATTRIBUTE_ID = auto()
    ADDITIONAL_ATTRIBUTE_VALUE = auto()
    APK_SIGNATURE_SCHEME_V2_BLOCK = auto()
    APK_SIGNATURE_SCHEME_V3_BLOCK = auto()
    DIGEST = auto()
    MAX_SDK = auto()
    MIN_SDK = auto()
    PAIR_ID = auto()
    PAIR_LENGTH = auto()
    PAIR_TYPE = auto()
    PUBLIC_KEY = auto()
    SIGNATURE = auto()
    SIGNATURE_ALGORITHM_ID = auto()
    SIGNER = auto()
    UNKNOWN_BLOCK = auto()
    UNKNOWN_BLOCK_DATA = auto()
    VERITY_PADDING_BLOCK = auto()
    X509_CERTIFICATE = auto()


APK_SIGNATURE_SCHEME_V2_BLOCK_ID = 0x7109871a
APK_SIGNATURE_SCHEME_V3_BLOCK_ID = 0xf05368c0
PROOF_OF_ROTATION_STRUCT_ID = 0x3ba06f8c
VERITY_PADDING_BLOCK_ID = 0x42726577

SIGNATURE_ALGORITHM_IDS = {
    0x0101: "RSASSA-PSS with SHA2-256 digest, SHA2-256 MGF1, 32 bytes of salt, trailer: 0xbc",
    0x0102: "RSASSA-PSS with SHA2-512 digest, SHA2-512 MGF1, 64 bytes of salt, trailer: 0xbc",
    0x0103: "RSASSA-PKCS1-v1_5 with SHA2-256 digest",   # This is for build systems which require deterministic signatures.
    0x0104: "RSASSA-PKCS1-v1_5 with SHA2-512 digest",   # This is for build systems which require deterministic signatures.
    0x0201: "ECDSA with SHA2-256 digest",
    0x0202: "ECDSA with SHA2-512 digest",
    0x0301: "DSA with SHA2-256 digest",
}


def parse_apk_signing_block(data):
    magic = data[-16:]
    sb_size1 = int.from_bytes(data[:8], "little")
    sb_size2 = int.from_bytes(data[-24:-16], "little")
    assert magic == b"APK Sig Block 42"
    assert sb_size1 == sb_size2 == len(data) - 8
    data = data[8:-24]
    while data:
        pair_len, pair_id = struct.unpack("<QL", data[:12])
        pair_val, data = data[12:8 + pair_len], data[8 + pair_len:]
        yield ID.PAIR_LENGTH, pair_len
        yield ID.PAIR_ID, pair_id
        if pair_id == APK_SIGNATURE_SCHEME_V2_BLOCK_ID:
            yield ID.PAIR_TYPE, ID.APK_SIGNATURE_SCHEME_V2_BLOCK
            yield from parse_apk_signature_scheme_v2_block(pair_val)
        elif pair_id == APK_SIGNATURE_SCHEME_V3_BLOCK_ID:
            yield ID.PAIR_TYPE, ID.APK_SIGNATURE_SCHEME_V3_BLOCK
            yield from parse_apk_signature_scheme_v3_block(pair_val)
        elif pair_id == VERITY_PADDING_BLOCK_ID:
            yield ID.PAIR_TYPE, ID.VERITY_PADDING_BLOCK
            assert all(b == 0 for b in pair_val)
        else:
            yield ID.PAIR_TYPE, ID.UNKNOWN_BLOCK
            yield ID.UNKNOWN_BLOCK_DATA, pair_val


def _len_prefixed_field(data):
    assert len(data) >= 4
    field_len = int.from_bytes(data[:4], "little")
    assert len(data) >= 4 + field_len
    return data[4:4 + field_len], data[4 + field_len:]


def parse_apk_signature_scheme_v2_block(data):
    yield from parse_apk_signature_scheme_block(data, False)


def parse_apk_signature_scheme_v3_block(data):
    yield from parse_apk_signature_scheme_block(data, True)


def parse_apk_signature_scheme_block(data, v3):
    seq_len, data = int.from_bytes(data[:4], "little"), data[4:]
    assert seq_len == len(data)
    i = 0
    while data:
        signer, data = _len_prefixed_field(data)
        yield ID.SIGNER, i
        yield from parse_signer(signer, v3)
        i += 1


def parse_signer(data, v3):
    sigdata, data = _len_prefixed_field(data)
    yield from parse_signed_data(sigdata, v3)
    if v3:
      minSDK, maxSDK = struct.unpack("<LL", data[:8])
      data = data[8:]
      yield ID.MIN_SDK, minSDK
      yield ID.MAX_SDK, maxSDK
    sigs, data = _len_prefixed_field(data)
    yield from parse_signatures(sigs)
    pubkey, data = _len_prefixed_field(data)
    yield ID.PUBLIC_KEY, pubkey
    assert all(b == 0 for b in data)


def parse_signed_data(data, v3):
    digests, data = _len_prefixed_field(data)
    yield from parse_digests(digests)
    certs, data = _len_prefixed_field(data)
    yield from parse_certificates(certs)
    if v3:
      minSDK, maxSDK = struct.unpack("<LL", data[:8])
      data = data[8:]
      yield ID.MIN_SDK, minSDK
      yield ID.MAX_SDK, maxSDK
    attrs, data = _len_prefixed_field(data)
    yield from parse_additional_attributes(attrs)
    assert all(b == 0 for b in data)


def parse_digests(data):
    while data:
        digest, data = _len_prefixed_field(data)
        sig_algo_id = int.from_bytes(digest[:4], "little")
        yield ID.SIGNATURE_ALGORITHM_ID, sig_algo_id
        yield ID.DIGEST, digest[4:]


def parse_certificates(data):
    while data:
        cert, data = _len_prefixed_field(data)
        yield ID.X509_CERTIFICATE, cert


def parse_additional_attributes(data):
    while data:
        attr, data = _len_prefixed_field(data)
        attr_id = int.from_bytes(attr[:4], "little")
        yield ID.ADDITIONAL_ATTRIBUTE_ID, attr_id
        yield ID.ADDITIONAL_ATTRIBUTE_VALUE, attr[4:]


def parse_signatures(data):
    while data:
        sig, data = _len_prefixed_field(data)
        sig_algo_id = int.from_bytes(sig[:4], "little")
        yield ID.SIGNATURE_ALGORITHM_ID, sig_algo_id
        yield ID.SIGNATURE, sig[4:]


# FIXME
def main(apk_signing_block_file):
    with open(apk_signing_block_file, "rb") as fh:
        data = fh.read()
    padding = ""
    for k, v in parse_apk_signing_block(data):
        if k is ID.PAIR_LENGTH:
            padding = ""
        s = v
        if isinstance(v, int) and k is not ID.SIGNER:
            if "LENGTH" not in k.name and "SDK" not in k.name:
                s = hex(v)
        elif isinstance(v, bytes):
            s = binascii.hexlify(v).decode()
        elif isinstance(v, ID):
            s = v.name
        if k is ID.SIGNATURE_ALGORITHM_ID and v in SIGNATURE_ALGORITHM_IDS:
            s = "{} ({})".format(s, SIGNATURE_ALGORITHM_IDS[v])
        elif k is ID.ADDITIONAL_ATTRIBUTE_ID and v == PROOF_OF_ROTATION_STRUCT_ID:
            s = "{} (Proof-of-rotation struct)".format(s)       # FIXME
        print(padding + k.name, s)
        if x509 is not None:
            if k is ID.X509_CERTIFICATE:
                cert = x509.Certificate.load(v)
                fpr = cert.sha256_fingerprint.replace(" ", "").lower()
                print("      X509_SUBJECT", cert.subject.human_friendly)
                print("      X509_SHA256_FINGERPRINT", fpr)
                key = cert.public_key
            elif k is ID.PUBLIC_KEY:
                key = keys.PublicKeyInfo.load(v)
            if k is ID.X509_CERTIFICATE or k is ID.PUBLIC_KEY:
                fpr = binascii.hexlify(key.sha256).decode()     # FIXME
                print("      PUBLIC_KEY_ALGORITHM", key.algorithm.upper())
                print("      PUBLIC_KEY_BIT_SIZE", key.bit_size)
                print("      PUBLIC_KEY_SHA256_FINGERPRINT", fpr)
        if k is ID.PAIR_TYPE:
            padding = "  "
        elif k is ID.SIGNER:
            padding = "    "


if __name__ == "__main__":
    main(sys.argv[1])
