#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2021 Felix C. Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: AGPL-3.0-or-later

import binascii
import hashlib
import struct

from collections import namedtuple

import click

from apksigcopier import extract_v2_sig

try:
    import asn1crypto.keys
    import asn1crypto.x509
except ImportError:
    have_asn1crypto = False
else:
    have_asn1crypto = True


__version__ = "0.0.1"

# FIXME: incomplete
APK_SIGNATURE_SCHEME_V2_BLOCK_ID = 0x7109871a
APK_SIGNATURE_SCHEME_V3_BLOCK_ID = 0xf05368c0
VERITY_PADDING_BLOCK_ID = 0x42726577
DEPENDENCY_INFO_BLOCK_ID = 0x504b4453
GOOGLE_PLAY_FROSTING_BLOCK_ID = 0x2146444e

# FIXME: unused
STRIPPING_PROTECTION_ATTR_ID = 0xbeeff00d
PROOF_OF_ROTATION_STRUCT_ID = 0x3ba06f8c

# FIXME: incomplete
SIGNATURE_ALGORITHM_IDS = {
    0x0101: "RSASSA-PSS with SHA2-256 digest, SHA2-256 MGF1, 32 bytes of salt, trailer: 0xbc",
    0x0102: "RSASSA-PSS with SHA2-512 digest, SHA2-512 MGF1, 64 bytes of salt, trailer: 0xbc",
    0x0103: "RSASSA-PKCS1-v1_5 with SHA2-256 digest",   # This is for build systems which require deterministic signatures.
    0x0104: "RSASSA-PKCS1-v1_5 with SHA2-512 digest",   # This is for build systems which require deterministic signatures.
    0x0201: "ECDSA with SHA2-256 digest",
    0x0202: "ECDSA with SHA2-512 digest",
    0x0301: "DSA with SHA2-256 digest",
}


APKSigningBlock = namedtuple("APKSigningBlock", ("pairs",))
Pair = namedtuple("Pair", ("length", "id", "value"))

APKSignatureSchemeBlock = namedtuple("APKSignatureSchemeBlock", ("version", "signers"))
VerityPaddingBlock = namedtuple("VerityPaddingBlock", ())
DependencyInfoBlock = namedtuple("DependencyInfoBlock", ("data",))
GooglePlayFrostingBlock = namedtuple("GooglePlayFrostingBlock", ("data",))
UnknownBlock = namedtuple("UnknownBlock", ("data",))

V2Signer = namedtuple("V2Signer", ("signed_data", "signatures", "public_key"))
V3Signer = namedtuple("V3Signer", ("signed_data", "min_sdk", "max_sdk", "signatures",
                                   "public_key"))

V2SignedData = namedtuple("V2SignedData", ("digests", "certificates", "additional_attributes"))
V3SignedData = namedtuple("V3SignedData", ("digests", "certificates", "min_sdk", "max_sdk",
                                           "additional_attributes"))

Digest = namedtuple("Digest", ("signature_algorithm_id", "digest"))
Certificate = namedtuple("Certificate", ("data",))
AdditionalAttribute = namedtuple("AdditionalAttribute", ("id", "value"))
Signature = namedtuple("Signature", ("signature_algorithm_id", "signature"))
PublicKey = namedtuple("PublicKey", ("data",))


APKSignatureSchemeBlock.is_v2 = lambda self: self.version == 2
APKSignatureSchemeBlock.is_v3 = lambda self: self.version == 3

AdditionalAttribute.is_stripping_protection = lambda self: \
    self.id == STRIPPING_PROTECTION_ATTR_ID
AdditionalAttribute.is_proof_of_rotation_struct = lambda self: \
    self.id == PROOF_OF_ROTATION_STRUCT_ID


def parse_apk_signing_block(data):
    return APKSigningBlock(tuple(_parse_apk_signing_block(data)))


def _parse_apk_signing_block(data):
    magic = data[-16:]
    sb_size1 = int.from_bytes(data[:8], "little")
    sb_size2 = int.from_bytes(data[-24:-16], "little")
    assert magic == b"APK Sig Block 42"
    assert sb_size1 == sb_size2 == len(data) - 8
    data = data[8:-24]
    while data:
        pair_len, pair_id = struct.unpack("<QL", data[:12])
        pair_val, data = data[12:8 + pair_len], data[8 + pair_len:]
        if pair_id == APK_SIGNATURE_SCHEME_V2_BLOCK_ID:
            value = parse_apk_signature_scheme_v2_block(pair_val)
        elif pair_id == APK_SIGNATURE_SCHEME_V3_BLOCK_ID:
            value = parse_apk_signature_scheme_v3_block(pair_val)
        elif pair_id == VERITY_PADDING_BLOCK_ID:
            assert all(b == 0 for b in pair_val)
            value = VerityPaddingBlock()
        elif pair_id == DEPENDENCY_INFO_BLOCK_ID:
            value = DependencyInfoBlock(pair_val)
        elif pair_id == GOOGLE_PLAY_FROSTING_BLOCK_ID:
            value = GooglePlayFrostingBlock(pair_val)
        else:
            value = UnknownBlock(pair_val)
        yield Pair(pair_len, pair_id, value)


def parse_apk_signature_scheme_v2_block(data):
    signers = _parse_apk_signature_scheme_block(data, False)
    return APKSignatureSchemeBlock(2, tuple(signers))


def parse_apk_signature_scheme_v3_block(data):
    signers = _parse_apk_signature_scheme_block(data, True)
    return APKSignatureSchemeBlock(3, tuple(signers))


def _parse_apk_signature_scheme_block(data, v3):
    seq_len, data = int.from_bytes(data[:4], "little"), data[4:]
    assert seq_len == len(data)
    while data:
        signer, data = _len_prefixed_field(data)
        yield parse_signer(signer, v3)


def parse_signer(data, v3):
    result = []
    sigdata, data = _len_prefixed_field(data)
    result.append(parse_signed_data(sigdata, v3))
    if v3:
        minSDK, maxSDK = struct.unpack("<LL", data[:8])
        data = data[8:]
        result.append(minSDK)
        result.append(maxSDK)
    sigs, data = _len_prefixed_field(data)
    result.append(parse_signatures(sigs))
    pubkey, data = _len_prefixed_field(data)
    result.append(PublicKey(pubkey))
    assert all(b == 0 for b in data)
    return (V3Signer if v3 else V2Signer)(*result)


def parse_signed_data(data, v3):
    result = []
    digests, data = _len_prefixed_field(data)
    result.append(parse_digests(digests))
    certs, data = _len_prefixed_field(data)
    result.append(parse_certificates(certs))
    if v3:
        minSDK, maxSDK = struct.unpack("<LL", data[:8])
        data = data[8:]
        result.append(minSDK)
        result.append(maxSDK)
    attrs, data = _len_prefixed_field(data)
    result.append(parse_additional_attributes(attrs))
    assert all(b == 0 for b in data)
    return (V3SignedData if v3 else V2SignedData)(*result)


def parse_digests(data):
    return tuple(_parse_digests(data))


def _parse_digests(data):
    while data:
        digest, data = _len_prefixed_field(data)
        sig_algo_id = int.from_bytes(digest[:4], "little")
        yield Digest(sig_algo_id, digest[4:])


def parse_certificates(data):
    return tuple(_parse_certificates(data))


def _parse_certificates(data):
    while data:
        cert, data = _len_prefixed_field(data)
        yield Certificate(cert)


def parse_additional_attributes(data):
    return tuple(_parse_additional_attributes(data))


def _parse_additional_attributes(data):
    while data:
        attr, data = _len_prefixed_field(data)
        attr_id = int.from_bytes(attr[:4], "little")
        yield AdditionalAttribute(attr_id, attr[4:])


def parse_signatures(data):
    return tuple(_parse_signatures(data))


def _parse_signatures(data):
    while data:
        sig, data = _len_prefixed_field(data)
        sig_algo_id = int.from_bytes(sig[:4], "little")
        yield Signature(sig_algo_id, sig[4:])


def _len_prefixed_field(data):
    assert len(data) >= 4
    field_len = int.from_bytes(data[:4], "little")
    assert len(data) >= 4 + field_len
    return data[4:4 + field_len], data[4 + field_len:]


@click.command()
@click.option("-v", "--verbose", is_flag=True)
@click.argument("apk", type=click.Path(exists=True, dir_okay=False))
@click.version_option(__version__)
def cli(apk, verbose):
    sb_offset, sig_block = extract_v2_sig(apk)
    for pair in parse_apk_signing_block(sig_block).pairs:
        b = pair.value
        if verbose:
            print("PAIR LENGTH:", pair.length)
        print("PAIR ID:", hex(pair.id))
        if isinstance(b, APKSignatureSchemeBlock):
            print("  APK SIGNATURE SCHEME v{} BLOCK".format(b.version))
            for i, signer in enumerate(b.signers):
                print("  SIGNER", i)
                print("    SIGNED DATA")
                for j, digest in enumerate(signer.signed_data.digests):
                    print("      DIGEST", j)
                    _show_aid(digest, 8)
                    _show_hex(digest.digest, 8)
                for j, cert in enumerate(signer.signed_data.certificates):
                    print("      CERTIFICATE", j)
                    show_x509_certificate(cert.data, 8)
                if b.is_v3():
                    print("      MIN SDK:", signer.signed_data.min_sdk)
                    print("      MAX SDK:", signer.signed_data.max_sdk)
                for j, attr in enumerate(signer.signed_data.additional_attributes):
                    print("      ADDITIONAL ATTRIBUTE", j)
                    print("        ADDITIONAL ATTRIBUTE ID:", hex(attr.id))
                    if attr.is_stripping_protection():
                        print("        STRIPPING PROTECTION ATTR")
                    elif attr.is_proof_of_rotation_struct():
                        print("        PROOF OF ROTATION STRUCT")
                    _show_hex(attr.value, 8)
                if b.is_v3():
                    print("    MIN SDK:", signer.min_sdk)
                    print("    MAX SDK:", signer.max_sdk)
                for j, sig in enumerate(signer.signatures):
                    print("    SIGNATURE", j)
                    _show_aid(sig, 6)
                    _show_hex(sig.signature, 6)
                print("    PUBLIC KEY")
                show_public_key(signer.public_key.data, 6)
        elif isinstance(b, VerityPaddingBlock):
            print("  VERITY PADDING BLOCK")
        elif isinstance(b, DependencyInfoBlock):
            print("  DEPENDENCY INFO BLOCK")
        elif isinstance(b, GooglePlayFrostingBlock):
            print("  GOOGLE PLAY FROSTING BLOCK")
        else:
            print("  UNKNOWN BLOCK")
        if verbose and hasattr(b, "data"):
            _show_hex(b.data, 2)


def _show_hex(data, indent):
    print(" " * indent + "VALUE (HEX):", binascii.hexlify(data).decode())


def _show_aid(x, indent):
    aid = x.signature_algorithm_id
    aid_s = SIGNATURE_ALGORITHM_IDS.get(aid, "UNKNOWN")
    print(" " * indent + "SIGNATURE ALGORITHM ID: {} ({})".format(hex(aid), aid_s))


if have_asn1crypto:
    # FIXME: show more? s/Common Name:/CN=/ etc?
    def show_x509_certificate(value, indent):
        cert = asn1crypto.x509.Certificate.load(value)
        fpr = cert.sha256_fingerprint.replace(" ", "").lower()
        print(" " * indent + "X.509 SUBJECT:", cert.subject.human_friendly)
        print(" " * indent + "X.509 ISSUER:", cert.issuer.human_friendly)
        print(" " * indent + "X.509 SHA256 FINGERPRINT (HEX):", fpr)
        _show_public_key(cert.public_key, indent)

    def show_public_key(value, indent):
        _show_public_key(asn1crypto.keys.PublicKeyInfo.load(value), indent)

    def _show_public_key(key, indent):
        fpr = hashlib.sha256(key.dump()).hexdigest()
        print(" " * indent + "PUBLIC KEY ALGORITHM:", key.algorithm.upper())
        print(" " * indent + "PUBLIC KEY BIT SIZE:", key.bit_size)
        print(" " * indent + "PUBLIC KEY SHA256 FINGERPRINT (HEX):", fpr)
else:
    show_x509_certificate = show_public_key = _show_hex


if __name__ == "__main__":
    cli()
