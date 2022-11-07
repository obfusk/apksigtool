#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2022 FC Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: AGPL-3.0-or-later

# --                                                            ; {{{1
#
# File        : apksigtool
# Maintainer  : FC Stegerman <flx@obfusk.net>
# Date        : 2022-11-06
#
# Copyright   : Copyright (C) 2022  FC Stegerman
# Version     : v0.1.0
# License     : AGPLv3+
#
# --                                                            ; }}}1

"""
parse/verify/clean android apk signing blocks & apks

apksigtool is a tool for parsing android APK Signing Blocks (either embedded in
an APK or extracted as a separate file, e.g. using apksigcopier) and verifying
APK signatures.  It can also clean them (i.e. remove everything that's not an
APK Signature Scheme v2/v3 Block or verity padding block), which can be useful
for reproducible builds.

WARNING: verification is considered EXPERIMENTAL and SHOULD NOT BE RELIED ON,
please use apksigner instead.


CLI
===

$ apksigtool parse [--block] [--json] [--verbose] APK_OR_BLOCK
$ apksigtool verify [--check-v1] [--quiet] [--verbose] APK
$ apksigtool clean [--block] [--check] [--keep HEXID] APK_OR_BLOCK

$ apksigtool parse-v1 [--json] [--verbose] APK_OR_DIR
$ apksigtool verify-v1 [--quiet] [--rollback-is-error] APK


API
===

>> from apksigtool import ...
>> apk_signing_block = parse_apk_signing_block(data, apkfile=None, ...)
>> apk_signing_block = APKSigningBlock.parse(data, ...)     # same as the above

>> show_parse_tree(apk_signing_block, apkfile=None, ...)
>> show_json(obj, ...)

>> apk_signing_block.verify(apkfile, ...)                   # raises on failure
>> verified, failed = apk_signing_block.verify_results(apkfile, ...)
>> verify_apk(apkfile, ...)                                 # verify APK (uses the above)

>> verify_apk_signature_scheme(signers, apkfile, ...)       # does the verification
>> APKSignatureSchemeBlock(...).verify(apkfile, ...)        # uses the above

>> data_cleaned = clean_apk_signing_block(data, keep=())    # clean block
>> cleaned = clean_apk(apkfile, check=False, keep=(), ...)  # clean APK
"""

from __future__ import annotations

import base64
import binascii
import dataclasses
import datetime
import glob
import os
import re
import struct
import sys
import textwrap
import zipfile

from binascii import hexlify
from dataclasses import dataclass, field
from functools import reduce
from hashlib import sha1, sha224, sha256, sha384, sha512
from typing import (Any, Dict, FrozenSet, Iterator, List, Literal, Mapping,
                    Optional, TextIO, Tuple, Union)

import apksigcopier

from apksigcopier import APKSigCopierError, ZipInfoDataPairs
from asn1crypto.keys import PublicKeyInfo as X509CertPubKeyInfo
from asn1crypto.x509 import Certificate as X509Cert
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15, PSS, MGF1
from cryptography.hazmat.primitives.hashes import SHA1, SHA224, SHA256, SHA384, SHA512
from cryptography.hazmat.primitives.serialization import load_der_public_key, Encoding
from cryptography.hazmat.primitives.serialization.pkcs7 import load_der_pkcs7_certificates
from pyasn1.codec.der.decoder import decode as pyasn1_decode
from pyasn1_modules import rfc5480

__version__ = "0.1.0"
NAME = "apksigtool"

# FIXME: list of block type IDs is incomplete
# https://source.android.com/docs/security/features/apksigning/v2#apk-signing-block-format
APK_SIGNATURE_SCHEME_V2_BLOCK_ID = 0x7109871a
APK_SIGNATURE_SCHEME_V3_BLOCK_ID = 0xf05368c0

# zero padding
VERITY_PADDING_BLOCK_ID = 0x42726577

# FIXME: opaque
# https://developer.android.com/studio/releases/gradle-plugin#dependency-metadata
#   "[...] data is compressed, encrypted by a Google Play signing key [...]"
# https://android.googlesource.com/platform/tools/apkzlib
#   src/main/java/com/android/tools/build/apkzlib/sign/SigningExtension.java
DEPENDENCY_INFO_BLOCK_ID = 0x504b4453

# FIXME: opaque
# https://bi-zone.medium.com/easter-egg-in-apk-files-what-is-frosting-f356aa9f4d1
GOOGLE_PLAY_FROSTING_BLOCK_ID = 0x2146444e

# FIXME: opaque
SOURCE_STAMP_V1_BLOCK_ID = 0x2b09189e
SOURCE_STAMP_V2_BLOCK_ID = 0x6dff800d

# FIXME: unused
STRIPPING_PROTECTION_ATTR_ID = 0xbeeff00d
PROOF_OF_ROTATION_STRUCT_ID = 0x3ba06f8c

# FIXME: incomplete
# https://android.googlesource.com/platform/tools/apksig
#   src/main/java/com/android/apksig/internal/apk/SignatureAlgorithm.java
SIGNATURE_ALGORITHM_IDS = {
    0x0101: "RSASSA-PSS with SHA2-256 digest, SHA2-256 MGF1, 32 bytes of salt, trailer: 0xbc, content digested using SHA2-256 in 1 MB chunks",
    0x0102: "RSASSA-PSS with SHA2-512 digest, SHA2-512 MGF1, 64 bytes of salt, trailer: 0xbc, content digested using SHA2-512 in 1 MB chunks",
    0x0103: "RSASSA-PKCS1-v1_5 with SHA2-256 digest, content digested using SHA2-256 in 1 MB chunks",   # for build systems which require deterministic signatures
    0x0104: "RSASSA-PKCS1-v1_5 with SHA2-512 digest, content digested using SHA2-512 in 1 MB chunks",   # for build systems which require deterministic signatures
    0x0201: "ECDSA with SHA2-256 digest, content digested using SHA2-256 in 1 MB chunks",
    0x0202: "ECDSA with SHA2-512 digest, content digested using SHA2-512 in 1 MB chunks",
    0x0301: "DSA with SHA2-256 digest, content digested using SHA2-256 in 1 MB chunks",
#   0x0301: "DSA with SHA2-256 digest, content digested using SHA2-256 in 1 MB chunks. Signing is done deterministically according to RFC 6979",    # noqa: E122
    0x0421: "RSASSA-PKCS1-v1_5 with SHA2-256 digest, content digested using SHA2-256 in 4 KB chunks, in the same way fsverity operates; this digest and the content length (before digestion, 8 bytes in little endian) construct the final digest",
    0x0423: "ECDSA with SHA2-256 digest, content digested using SHA2-256 in 4 KB chunks, in the same way fsverity operates; this digest and the content length (before digestion, 8 bytes in little endian) construct the final digest",
    0x0425: "DSA with SHA2-256 digest, content digested using SHA2-256 in 4 KB chunks, in the same way fsverity operates; this digest and the content length (before digestion, 8 bytes in little endian) construct the final digest",
}

CHUNKED, VERITY = 1, 2

# FIXME: incomplete
HASHERS = {
    # id     algo   hasher  halgo   pad                                              chunk_type
    0x0101: ("rsa", sha256, SHA256, lambda: PSS(mgf=MGF1(SHA256()), salt_length=32), CHUNKED),
    0x0102: ("rsa", sha512, SHA512, lambda: PSS(mgf=MGF1(SHA512()), salt_length=64), CHUNKED),
    0x0103: ("rsa", sha256, SHA256, PKCS1v15, CHUNKED),
    0x0104: ("rsa", sha512, SHA512, PKCS1v15, CHUNKED),
    0x0201: ("ec", sha256, lambda: ECDSA(SHA256()), None, CHUNKED),
    0x0202: ("ec", sha512, lambda: ECDSA(SHA512()), None, CHUNKED),
    0x0301: ("dsa", sha256, SHA256, None, CHUNKED),
    0x0421: ("rsa", sha256, SHA256, PKCS1v15, VERITY),
    0x0423: ("ec", sha256, lambda: ECDSA(SHA256()), None, VERITY),      # NB: untested
    0x0425: ("dsa", sha256, SHA256, None, VERITY),                      # NB: untested
}

assert set(SIGNATURE_ALGORITHM_IDS.keys()) == set(HASHERS.keys())

CHUNK_SIZE = 1048576
VERITY_BLOCK_SIZE = 4096

# FIXME
VERITY_SALT = b"\x00" * 8

# FIXME: incomplete?
JAR_HASHERS_OID = {
    # OID               algo      hasher  halgo
    rfc5480.id_sha224: ("SHA224", sha224, SHA224),
    rfc5480.id_sha256: ("SHA256", sha256, SHA256),
    rfc5480.id_sha384: ("SHA384", sha384, SHA384),
    rfc5480.id_sha512: ("SHA512", sha512, SHA512),
    rfc5480.id_sha1: ("SHA1", sha1, SHA1),
}
#                  algo  OID    hasher...
JAR_HASHERS_STR = {v[0]: (k,) + v[1:] for k, v in JAR_HASHERS_OID.items()}

JAR_DIGEST_HEADER = r"(SHA(?:1|-(?:224|256|384|512)))-Digest"
JAR_MANIFEST = "META-INF/MANIFEST.MF"
JAR_SBF_EXTS = ("RSA", "DSA", "EC")
JAR_META_EXTS = ("SF",) + JAR_SBF_EXTS + (JAR_MANIFEST.split(".")[-1],)

# FIXME
UNSAFE_HASH_ALGO = dict(
    SHA1=True, SHA224=False, SHA256=False, SHA384=False, SHA512=False
)

# FIXME
UNSAFE_KEY_SIZE = dict(
    RSA=lambda size: size < 1024,
    DSA=lambda size: size < 1024,
    EC=None,
)

assert set(JAR_HASHERS_STR.keys()) == set(UNSAFE_HASH_ALGO.keys())
assert set(JAR_SBF_EXTS) == set(UNSAFE_KEY_SIZE.keys())
assert set(JAR_SBF_EXTS) == set(x[0].upper() for x in HASHERS.values())

WRAP_COLUMNS = 80   # overridden in main() if $APKSIGTOOL_WRAP_COLUMNS is set


class APKSigToolError(Exception):
    """Base class for errors."""


class VerificationError(APKSigToolError):
    """Verification failure."""


class AssertionFailed(APKSigToolError):
    """Assertion failure."""


@dataclass(frozen=True)
class APKSigToolBase:
    """Base class for dataclasses."""

    def for_json(self) -> Mapping[str, Any]:
        """Convert to JSON: dict of all attributes not starting with _, plus _type."""
        d = {k: v for k, v in self.__dict__.items() if not k.startswith("_")}
        return dict(_type=self.__class__.__name__, **d)


@dataclass(frozen=True)
class CertificateInfo(APKSigToolBase):
    """X.509 certificate info."""
    subject: str
    issuer: str
    serial_number: int
    hash_algorithm: str
    signature_algorithm: str
    not_valid_before: datetime.datetime
    not_valid_after: datetime.datetime
    fingerprint: str


@dataclass(frozen=True)
class PublicKeyInfo(APKSigToolBase):
    """Public key info."""
    algorithm: str
    bit_size: int
    fingerprint: str
    hash_algorithm: Optional[str]


@dataclass(frozen=True)
class Block(APKSigToolBase):
    """Base class for APKSigningBlock etc."""


@dataclass(frozen=True)
class Pair(APKSigToolBase):
    """ID-value pair."""
    length: int
    id: int
    value: Block


@dataclass(frozen=True)
class Digest(APKSigToolBase):
    """APK Signature Scheme v2/v3 Block -> signer -> signed data -> digest."""
    signature_algorithm_id: int
    digest: bytes
    algoritm_id_info: str = field(init=False)

    def __post_init__(self):
        object.__setattr__(self, "algoritm_id_info", aid_info(self.signature_algorithm_id))

    @classmethod
    def parse(_cls, data: bytes) -> Tuple[Digest, ...]:
        """
        Parse APK Signature Scheme v2/v3 Block -> signer -> signed data -> digests.

        NB: returns a tuple of Digest.

        Uses parse_digests().
        """
        return parse_digests(data)


@dataclass(frozen=True)
class Certificate(APKSigToolBase):
    """APK Signature Scheme v2/v3 Block -> signer -> signed data -> certificate."""
    raw_data: bytes
    _certificate: X509Cert = field(init=False, repr=False, compare=False)
    _public_key: X509CertPubKeyInfo = field(init=False, repr=False, compare=False)
    certificate_info: CertificateInfo = field(init=False)
    public_key_info: PublicKeyInfo = field(init=False)

    def __post_init__(self):
        object.__setattr__(self, "_certificate", X509Cert.load(self.raw_data))
        object.__setattr__(self, "_public_key", self.certificate.public_key)
        object.__setattr__(self, "certificate_info", x509_certificate_info(self.certificate))
        object.__setattr__(self, "public_key_info", public_key_info(self.public_key))

    @property
    def certificate(self) -> X509Cert:
        return self._certificate

    @property
    def public_key(self) -> X509CertPubKeyInfo:
        return self._public_key

    @classmethod
    def parse(_cls, data: bytes) -> Tuple[Certificate, ...]:
        """
        Parse APK Signature Scheme v2/v3 Block -> signer -> signed data ->
        certificates.

        NB: returns a tuple of Certificate.

        Uses parse_certificates().
        """
        return parse_certificates(data)


@dataclass(frozen=True)
class AdditionalAttribute(APKSigToolBase):
    """APK Signature Scheme v2/v3 Block -> signer -> signed data -> additional attribute."""
    id: int
    value: bytes

    @property
    def is_stripping_protection(self) -> bool:
        return self.id == STRIPPING_PROTECTION_ATTR_ID

    @property
    def is_proof_of_rotation_struct(self) -> bool:
        return self.id == PROOF_OF_ROTATION_STRUCT_ID

    def for_json(self) -> Mapping[str, Any]:
        x = super().for_json()
        y = dict(is_stripping_protection=self.is_stripping_protection,
                 is_proof_of_rotation_struct=self.is_proof_of_rotation_struct)
        return {**x, **y}

    @classmethod
    def parse(_cls, data: bytes) -> Tuple[AdditionalAttribute, ...]:
        """
        Parse APK Signature Scheme v2/v3 Block -> signer -> signed data ->
        additional attributes.

        NB: returns a tuple of AdditionalAttribute.

        Uses parse_additional_attributes().
        """
        return parse_additional_attributes(data)


@dataclass(frozen=True)
class Signature(APKSigToolBase):
    """APK Signature Scheme v2/v3 Block -> signer -> signature."""
    signature_algorithm_id: int
    signature: bytes
    algoritm_id_info: str = field(init=False)

    def __post_init__(self):
        object.__setattr__(self, "algoritm_id_info", aid_info(self.signature_algorithm_id))

    @classmethod
    def parse(_cls, data: bytes) -> Tuple[Signature, ...]:
        """
        Parse APK Signature Scheme v2/v3 Block -> signer -> signatures.

        NB: returns a tuple of Signature

        Uses parse_signatures().
        """
        return parse_signatures(data)


@dataclass(frozen=True)
class PublicKey(APKSigToolBase):
    """APK Signature Scheme v2/v3 Block -> signer -> public key."""
    raw_data: bytes
    _public_key: X509CertPubKeyInfo = field(init=False, repr=False, compare=False)
    public_key_info: PublicKeyInfo = field(init=False)

    def __post_init__(self):
        object.__setattr__(self, "_public_key", X509CertPubKeyInfo.load(self.raw_data))
        object.__setattr__(self, "public_key_info", public_key_info(self.public_key))

    @property
    def public_key(self) -> X509CertPubKeyInfo:
        return self._public_key


@dataclass(frozen=True)
class V2SignedData(APKSigToolBase):
    """APK Signature Scheme v2/v3 Block -> signer -> signed data (v2)."""
    raw_data: bytes
    digests: Tuple[Digest, ...]
    certificates: Tuple[Certificate, ...]
    additional_attributes: Tuple[AdditionalAttribute, ...]

    @classmethod
    def parse(_cls, data: bytes) -> V2SignedData:
        """
        Parse APK Signature Scheme v2 Block -> v2 signer -> signed data.

        Uses parse_signed_data(v3=False).
        """
        signed_data = parse_signed_data(data, v3=False)
        assert isinstance(signed_data, V2SignedData)
        return signed_data


@dataclass(frozen=True)
class V3SignedData(APKSigToolBase):
    """APK Signature Scheme v2/v3 Block -> signer -> signed data (v3)."""
    raw_data: bytes
    digests: Tuple[Digest, ...]
    certificates: Tuple[Certificate, ...]
    min_sdk: int
    max_sdk: int
    additional_attributes: Tuple[AdditionalAttribute, ...]

    @classmethod
    def parse(_cls, data: bytes) -> V3SignedData:
        """
        Parse APK Signature Scheme v3 Block -> v3 signer -> signed data.

        Uses parse_signed_data(v3=True).
        """
        signed_data = parse_signed_data(data, v3=True)
        assert isinstance(signed_data, V3SignedData)
        return signed_data


@dataclass(frozen=True)
class V2Signer(APKSigToolBase):
    """APK Signature Scheme v2/v3 Block -> signer (v2)."""
    signed_data: V2SignedData
    signatures: Tuple[Signature, ...]
    public_key: PublicKey

    @classmethod
    def parse(_cls, data: bytes) -> V2Signer:
        """
        Parse APK Signature Scheme v2 Block -> v2 signer.

        Uses parse_signer(v3=False).
        """
        signer = parse_signer(data, v3=False)
        assert isinstance(signer, V2Signer)
        return signer


@dataclass(frozen=True)
class V3Signer(APKSigToolBase):
    """APK Signature Scheme v2/v3 Block -> signer (v3)."""
    signed_data: V3SignedData
    min_sdk: int
    max_sdk: int
    signatures: Tuple[Signature, ...]
    public_key: PublicKey

    @classmethod
    def parse(_cls, data: bytes) -> V3Signer:
        """
        Parse APK Signature Scheme v3 Block -> v3 signer.

        Uses parse_signer(v3=True).
        """
        signer = parse_signer(data, v3=True)
        assert isinstance(signer, V3Signer)
        return signer


@dataclass(frozen=True)
class APKSigningBlock(APKSigToolBase):
    """APK Signing Block."""
    pairs: Tuple[Pair, ...]

    @classmethod
    def parse(_cls, data: bytes, apkfile: Optional[str] = None, *,
              allow_unsafe: Tuple[str, ...] = (), sdk: Optional[int] = None) \
            -> APKSigningBlock:
        """
        Parse APK Signing Block.

        Uses parse_apk_signing_block().
        """
        return parse_apk_signing_block(data, apkfile=apkfile, allow_unsafe=allow_unsafe, sdk=sdk)

    # FIXME
    # WARNING: verification is considered EXPERIMENTAL
    def verify(self, apkfile: str, *, allow_unsafe: Tuple[str, ...] = (),
               sdk: Optional[int] = None) -> None:
        """
        Verify APK file using the APK Signature Scheme v2/v3 Blocks found in
        this APKSigningBlock.

        WARNING: verification is considered EXPERIMENTAL and SHOULD NOT BE
        RELIED ON, please use apksigner instead.

        Raises VerificationError on failure.

        Uses APKSignatureSchemeBlock.verify().
        """
        for pair in self.pairs:
            if isinstance(pair.value, APKSignatureSchemeBlock):
                pair.value.verify(apkfile, allow_unsafe=allow_unsafe, sdk=sdk)

    # FIXME
    # WARNING: verification is considered EXPERIMENTAL
    def verify_results(self, apkfile: str, *, allow_unsafe: Tuple[str, ...] = (),
                       sdk: Optional[int] = None) \
            -> Tuple[Tuple[Tuple[int, Tuple[Tuple[str, str], ...]], ...],
                     Tuple[Tuple[int, Exception], ...]]:
        """
        Verify APK file using the APK Signature Scheme v2/v3 Blocks found in
        this APKSigningBlock.

        WARNING: verification is considered EXPERIMENTAL and SHOULD NOT BE
        RELIED ON, please use apksigner instead.

        Returns (verified, failed), where verified is a tuple of (version,
        signers) of verification successes, and failed is a tuple of (version,
        exception) tuples of verification failures.

        Uses APKSignatureSchemeBlock.verify().
        """
        verified, failed = [], []
        for pair in self.pairs:
            if isinstance(pair.value, APKSignatureSchemeBlock):
                try:
                    signers = pair.value.verify(apkfile, allow_unsafe=allow_unsafe, sdk=sdk)
                except VerificationError as e:
                    failed.append((pair.value.version, e))
                else:
                    verified.append((pair.value.version, signers))
        return tuple(verified), tuple(failed)


@dataclass(frozen=True)
class APKSignatureSchemeBlock(Block):
    """APK Signature Scheme v2/v3 Block."""
    version: Literal[2, 3]
    signers: Tuple[Union[V2Signer, V3Signer], ...]
    verified: Union[None, Literal[False], Tuple[Tuple[str, str], ...]] = None
    verification_error: Optional[str] = None

    def __post_init__(self):
        assert self.verified in (None, False) or len(self.verified) >= 1
        assert (self.verification_error is not None) == (self.verified == False)    # noqa: E712
        if self.is_v2:
            assert all(isinstance(s, V2Signer) for s in self.signers)
        else:
            assert all(isinstance(s, V3Signer) for s in self.signers)

    @property
    def is_v2(self) -> bool:
        return self.version == 2

    @property
    def is_v3(self) -> bool:
        return self.version == 3

    @classmethod
    def parse(_cls, version: Literal[2, 3], data: bytes, apkfile: Optional[str] = None, *,
              allow_unsafe: Tuple[str, ...] = (), sdk: Optional[int] = None) \
            -> APKSignatureSchemeBlock:
        """
        Parse APK Signature Scheme v2/v3 Block.

        Uses parse_apk_signature_scheme_block().
        """
        return parse_apk_signature_scheme_block(version, data, allow_unsafe=allow_unsafe,
                                                apkfile=apkfile, sdk=sdk)

    # FIXME
    # WARNING: verification is considered EXPERIMENTAL
    def verify(self, apkfile: str, *, allow_unsafe: Tuple[str, ...] = (),
               sdk: Optional[int] = None) -> Tuple[Tuple[str, str], ...]:
        """
        Verify APK Signature Scheme using verify_apk_signature_scheme().

        WARNING: verification is considered EXPERIMENTAL and SHOULD NOT BE
        RELIED ON, please use apksigner instead.

        Raises VerificationError on failure.

        Uses verify_apk_signature_scheme().
        """
        return verify_apk_signature_scheme(self.signers, apkfile=apkfile,
                                           allow_unsafe=allow_unsafe, sdk=sdk)


@dataclass(frozen=True)
class VerityPaddingBlock(Block):
    """Verity padding block (zero padding)."""


@dataclass(frozen=True)
class DependencyInfoBlock(Block):
    """Google dependency info block (opaque, encrypted)."""
    raw_data: bytes


@dataclass(frozen=True)
class GooglePlayFrostingBlock(Block):
    """Google Play frosting block (opaque)."""
    raw_data: bytes


@dataclass(frozen=True)
class SourceStampBlock(Block):
    """Google source stamp block (opaque)."""
    raw_data: bytes
    version: Literal[1, 2]


@dataclass(frozen=True)
class UnknownBlock(Block):
    """Unknown block."""
    raw_data: bytes


@dataclass(frozen=True)
class JAREntry(APKSigToolBase):
    """JAR (manifest) entry."""
    raw_data: bytes
    filename: str
    digests: Tuple[Tuple[str, str], ...]

    def __post_init__(self):
        assert all(algo in JAR_HASHERS_STR for algo, _ in self.digests)


@dataclass(frozen=True)
class JARManifestBase(APKSigToolBase):
    """Base class for JARManifest and JARSignatureFile."""
    raw_data: bytes
    entries: Tuple[JAREntry, ...]
    version: str
    created_by: Optional[str]
    headers_len: int


@dataclass(frozen=True)
class JARManifest(JARManifestBase):
    """JAR manifest (MANIFEST.MF)."""
    built_by: Optional[str]

    @classmethod
    def parse(_cls, data: bytes) -> JARManifest:
        """
        Parse JAR manifest (MANIFEST.MF).

        Uses parse_apk_v1_manifest().
        """
        return parse_apk_v1_manifest(data)


@dataclass(frozen=True)
class JARSignatureFile(JARManifestBase):
    """JAR signature file (.SF)."""
    filename: str
    digests_manifest: Tuple[Tuple[str, str], ...]
    digests_manifest_main_attributes: Optional[Tuple[Tuple[str, str], ...]]
    x_android_apk_signed: Optional[Tuple[int, ...]]

    def __post_init__(self):
        assert all(algo in JAR_HASHERS_STR for algo, _ in self.digests_manifest)
        assert all(algo in JAR_HASHERS_STR for algo, _ in self.digests_manifest_main_attributes or ())

    @classmethod
    def parse(_cls, filename: str, data: bytes) -> JARSignatureFile:
        """
        Parse JAR signature file (.SF).

        Uses parse_apk_v1_signature_file().
        """
        return parse_apk_v1_signature_file(filename, data)


@dataclass(frozen=True)
class JARSignatureBlockFile(APKSigToolBase):
    """JAR signature block file (.RSA, .DSA, or .EC)."""
    raw_data: bytes
    filename: str
    _certificate: X509Cert = field(init=False, repr=False, compare=False)
    _public_key: X509CertPubKeyInfo = field(init=False, repr=False, compare=False)
    certificate_info: CertificateInfo = field(init=False)
    public_key_info: PublicKeyInfo = field(init=False)
    signature: bytes = field(init=False)
    hash_algorithm: Optional[str] = field(init=False)

    def __post_init__(self):
        sig, algo, cert = _load_apk_v1_signature_block_file_sig_algo_cert(self.raw_data)
        object.__setattr__(self, "_certificate", cert)
        object.__setattr__(self, "_public_key", self.certificate.public_key)
        object.__setattr__(self, "certificate_info", x509_certificate_info(self.certificate))
        object.__setattr__(self, "public_key_info", public_key_info(self.public_key))
        object.__setattr__(self, "signature", sig)
        object.__setattr__(self, "hash_algorithm", algo)

    @property
    def certificate(self) -> X509Cert:
        return self._certificate

    @property
    def public_key(self) -> X509CertPubKeyInfo:
        return self._public_key


@dataclass(frozen=True)
class JARSignature(APKSigToolBase):
    """v1 (JAR) signature."""
    manifest: JARManifest
    signature_files: Tuple[JARSignatureFile, ...]
    signature_block_files: Tuple[JARSignatureBlockFile, ...]
    verified: Union[None, Literal[False], Tuple[Tuple[str, str], ...]] = None
    verification_error: Optional[str] = None
    unverified_mf: Optional[Tuple[str, ...]] = None
    unverified_sf: Optional[Tuple[Tuple[str, Tuple[str, ...]], ...]] = None

    def __post_init__(self):
        assert [_fn_base(x) for x in self.signature_files] \
            == [_fn_base(x) for x in self.signature_block_files]
        assert self.verified in (None, False) or len(self.verified) >= 1
        assert (self.verification_error is not None) == (self.verified == False)    # noqa: E712
        assert (self.unverified_mf is not None) == (self.verified not in (None, False))
        assert (self.unverified_sf is not None) == (self.verified not in (None, False))

    @property
    def required_signature_versions(self) -> FrozenSet[int]:
        """Require signature versions (from X-Android-APK-Signed)."""
        return frozenset(v for sf in self.signature_files for v in sf.x_android_apk_signed or ())

    @classmethod
    def parse(_cls, extracted_meta: ZipInfoDataPairs, apkfile: Optional[str] = None, *,
              allow_unsafe: Tuple[str, ...] = (), strict: bool = True) -> JARSignature:
        """
        Parse v1 signature metadata files from apksigcopier.extract_meta().

        Uses parse_apk_v1_signature().
        """
        return parse_apk_v1_signature(extracted_meta, apkfile=apkfile,
                                      allow_unsafe=allow_unsafe, strict=strict)

    # FIXME
    # WARNING: verification is considered EXPERIMENTAL
    def verify(self, apkfile: str, *, allow_unsafe: Tuple[str, ...] = (), strict: bool = True) \
            -> Tuple[Tuple[Tuple[str, str], ...], Tuple[str, ...],
                     Tuple[Tuple[str, Tuple[str, ...]], ...]]:
        """
        Verify APK file using this v1 (JAR) signature.

        WARNING: verification is considered EXPERIMENTAL and SHOULD NOT BE
        RELIED ON, please use apksigner instead.

        Raises VerificationError on failure.

        Uses verify_apk_v1_signature().
        """
        return verify_apk_v1_signature(self, apkfile=apkfile, strict=strict,
                                       allow_unsafe=allow_unsafe)


def _assert(b: bool, what: Optional[str] = None) -> None:
    """
    assert that is not removed with optimization.

    >>> from apksigtool import _assert
    >>> _assert(1 == 1, "all good")
    >>> _assert(1 == 2, "oops") # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    AssertionFailed: Assertion failed: oops

    """
    if not b:
        raise AssertionFailed("Assertion failed" + (f": {what}" if what else ""))


def _fn_base(x):
    return x.filename.rsplit(".", 1)[0]


def parse_apk_signing_block(data: bytes, apkfile: Optional[str] = None, *,
                            allow_unsafe: Tuple[str, ...] = (),
                            sdk: Optional[int] = None) -> APKSigningBlock:
    """
    Parse APK Signing Block (a sequence of pairs).

    The apkfile parameter is passed down to parse_apk_signature_scheme_block()
    (along with the sdk parameter), which will attempt to verify the APK using
    verify_apk_signature_scheme() when it is not None.

    Returns APKSigningBlock with .pairs a tuple of Pair (with .length, .id,
    .value; each .value is e.g. an APKSignatureSchemeBlock or other block type,
    UnknownBlock if not identified).
    """
    return APKSigningBlock(tuple(_parse_apk_signing_block(
        data, allow_unsafe=allow_unsafe, apkfile=apkfile, sdk=sdk)))


# FIXME: check if sb_size % 4096 == 0? when?
# https://source.android.com/docs/security/features/apksigning/v2#apk-signing-block-format
def _parse_apk_signing_block(data: bytes, apkfile: Optional[str] = None, *,
                             allow_unsafe: Tuple[str, ...] = (),
                             sdk: Optional[int] = None) -> Iterator[Pair]:
    """Yield Pair(s) (with e.g. an APKSignatureSchemeBlock as .value)."""
    magic = data[-16:]
    sb_size1 = int.from_bytes(data[:8], "little")
    sb_size2 = int.from_bytes(data[-24:-16], "little")
    _assert(magic == b"APK Sig Block 42", "APK Sig Block magic")
    _assert(sb_size1 == sb_size2 == len(data) - 8, "APK Sig Block size")
    data = data[8:-24]
    while data:
        value: Block
        pair_len, pair_id = struct.unpack("<QL", data[:12])
        pair_val, data = data[12:8 + pair_len], data[8 + pair_len:]
        if pair_id == APK_SIGNATURE_SCHEME_V2_BLOCK_ID:
            value = parse_apk_signature_scheme_block(
                2, pair_val, allow_unsafe=allow_unsafe, apkfile=apkfile, sdk=sdk)
        elif pair_id == APK_SIGNATURE_SCHEME_V3_BLOCK_ID:
            value = parse_apk_signature_scheme_block(
                3, pair_val, allow_unsafe=allow_unsafe, apkfile=apkfile, sdk=sdk)
        elif pair_id == VERITY_PADDING_BLOCK_ID:
            _assert(all(b == 0 for b in pair_val), "verity zero padding")
            value = VerityPaddingBlock()
        elif pair_id == DEPENDENCY_INFO_BLOCK_ID:
            value = DependencyInfoBlock(pair_val)
        elif pair_id == GOOGLE_PLAY_FROSTING_BLOCK_ID:
            value = GooglePlayFrostingBlock(pair_val)
        elif pair_id == SOURCE_STAMP_V1_BLOCK_ID:
            value = SourceStampBlock(pair_val, 1)
        elif pair_id == SOURCE_STAMP_V2_BLOCK_ID:
            value = SourceStampBlock(pair_val, 2)
        else:
            value = UnknownBlock(pair_val)
        yield Pair(pair_len, pair_id, value)


# FIXME
# FIXME: adjust/add verity padding if sb_size % 4096 != 0? when?
def clean_apk_signing_block(data: bytes, *, keep: Tuple[int, ...] = ()) -> bytes:
    """
    Clean APK Signing Block: remove everything that's not an APK Signature
    Scheme v2/v3 Block or verity padding block (or has a pair_id in keep).

    Returns cleaned block (bytes).
    """
    magic = data[-16:]
    sb_size1 = int.from_bytes(data[:8], "little")
    sb_size2 = int.from_bytes(data[-24:-16], "little")
    _assert(magic == b"APK Sig Block 42", "APK Sig Block magic")
    _assert(sb_size1 == sb_size2 == len(data) - 8, "APK Sig Block size")
    data = data[8:-24]
    cleaned = b""
    while data:
        pair_len, pair_id = struct.unpack("<QL", data[:12])
        pair, data = data[:8 + pair_len], data[8 + pair_len:]
        if pair_id == APK_SIGNATURE_SCHEME_V2_BLOCK_ID:
            pass
        elif pair_id == APK_SIGNATURE_SCHEME_V3_BLOCK_ID:
            pass
        elif pair_id == VERITY_PADDING_BLOCK_ID:
            _assert(all(b == 0 for b in pair[12:]), "verity zero padding")
        elif pair_id in keep:
            pass
        else:
            continue
        cleaned += pair
    c_size = int.to_bytes(len(cleaned) + 24, 8, "little")
    return c_size + cleaned + c_size + magic


def parse_apk_signature_scheme_block(
        version: Literal[2, 3], data: bytes, apkfile: Optional[str] = None, *,
        allow_unsafe: Tuple[str, ...] = (), sdk: Optional[int] = None) \
        -> APKSignatureSchemeBlock:
    """
    Parse APK Signature Scheme v2/v3 Block (and attempt to verify -- setting
    .verified to #signers or False instead of None -- if apkfile is not
    None).

    Returns APKSignatureSchemeBlock (with .version, .signers, .verified,
    .verification_error).
    """
    signers = tuple(_parse_apk_signature_scheme_block(data, v3=version == 3))
    if apkfile is not None:
        verified: Union[Literal[False], Tuple[Tuple[str, str], ...]]
        verification_error = None
        try:
            verified = verify_apk_signature_scheme(signers, allow_unsafe=allow_unsafe,
                                                   apkfile=apkfile, sdk=sdk)
        except VerificationError as e:
            verified, verification_error = False, str(e)
        return APKSignatureSchemeBlock(version, signers, verified, verification_error)
    return APKSignatureSchemeBlock(version, signers)


def _parse_apk_signature_scheme_block(data: bytes, v3: bool) \
        -> Iterator[Union[V2Signer, V3Signer]]:
    """Yield V2Signer/V3Signer(s) for each parse_signer()."""
    seq_len, data = int.from_bytes(data[:4], "little"), data[4:]
    _assert(seq_len == len(data), "APK Signature Scheme Block size")
    while data:
        signer, data = _len_prefixed_field(data)
        yield parse_signer(signer, v3=v3)


def parse_signer(data: bytes, v3: bool) -> Union[V2Signer, V3Signer]:
    """
    Parse APK Signature Scheme v2/v3 Block -> signer.

    Returns V2Signer/V3Signer (with .signed_data, .signatures, .public_key;
    V3Signer also .min_sdk, .max_sdk).
    """
    result: List = []
    sigdata, data = _len_prefixed_field(data)
    result.append(parse_signed_data(sigdata, v3=v3))
    if v3:
        minSDK, maxSDK = struct.unpack("<LL", data[:8])
        data = data[8:]
        result.append(minSDK)
        result.append(maxSDK)
    sigs, data = _len_prefixed_field(data)
    result.append(parse_signatures(sigs))
    pubkey, data = _len_prefixed_field(data)
    result.append(PublicKey(pubkey))
    _assert(all(b == 0 for b in data), "signer zero padding")
    return (V3Signer if v3 else V2Signer)(*result)


def parse_signed_data(data: bytes, v3: bool) -> Union[V2SignedData, V3SignedData]:
    """
    Parse APK Signature Scheme v2/v3 Block -> signer -> signed data.

    Returns V2SignedData/V3SignedData (with .raw_data, .digests, .certificates,
    .additional_attributes; V3SignedData also .min_sdk, .max_sdk).
    """
    result: List = [data]
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
    _assert(all(b == 0 for b in data), "signed data zero padding")
    return (V3SignedData if v3 else V2SignedData)(*result)


def parse_digests(data: bytes) -> Tuple[Digest, ...]:
    """
    Parse APK Signature Scheme v2/v3 Block -> signer -> signed data -> digests.

    Returns tuple of Digest (with .signature_algorithm_id, .digest).
    """
    return tuple(_parse_digests(data))


def _parse_digests(data: bytes) -> Iterator[Digest]:
    """Yield Digest(s)."""
    while data:
        digest, data = _len_prefixed_field(data)
        sig_algo_id = int.from_bytes(digest[:4], "little")
        _assert(int.from_bytes(digest[4:8], "little") == len(digest) - 8, "digest size")
        yield Digest(sig_algo_id, digest[8:])


def parse_certificates(data: bytes) -> Tuple[Certificate, ...]:
    """
    Parse APK Signature Scheme v2/v3 Block -> signer -> signed data ->
    certificates.

    Returns tuple of Certificate (with .raw_data).
    """
    return tuple(_parse_certificates(data))


def _parse_certificates(data: bytes) -> Iterator[Certificate]:
    """Yield Certificate(s)."""
    while data:
        cert, data = _len_prefixed_field(data)
        yield Certificate(cert)


def parse_additional_attributes(data: bytes) -> Tuple[AdditionalAttribute, ...]:
    """
    Parse APK Signature Scheme v2/v3 Block -> signer -> signed data ->
    additional attributes.

    Returns tuple of AdditionalAttribute (with .id, .value).
    """
    return tuple(_parse_additional_attributes(data))


def _parse_additional_attributes(data: bytes) -> Iterator[AdditionalAttribute]:
    """Yield AdditionalAttribute(s)."""
    while data:
        attr, data = _len_prefixed_field(data)
        attr_id = int.from_bytes(attr[:4], "little")
        yield AdditionalAttribute(attr_id, attr[4:])


def parse_signatures(data: bytes) -> Tuple[Signature, ...]:
    """
    Parse APK Signature Scheme v2/v3 Block -> signer -> signatures.

    Returns tuple of Signature (with .signature_algorithm_id, .signature).
    """
    return tuple(_parse_signatures(data))


def _parse_signatures(data: bytes) -> Iterator[Signature]:
    """Yield Signature(s)."""
    while data:
        sig, data = _len_prefixed_field(data)
        sig_algo_id = int.from_bytes(sig[:4], "little")
        _assert(int.from_bytes(sig[4:8], "little") == len(sig) - 8, "signature size")
        yield Signature(sig_algo_id, sig[8:])


def _len_prefixed_field(data: bytes) -> Tuple[bytes, bytes]:
    """
    Parse length-prefixed field (length is little-endian, uint32) at beginning
    of data.

    Returns (field data, remaining data).
    """
    _assert(len(data) >= 4, "prefixed field must be at least 4 bytes")
    field_len = int.from_bytes(data[:4], "little")
    _assert(len(data) >= 4 + field_len, "prefixed field size")
    return data[4:4 + field_len], data[4 + field_len:]


# FIXME: check & audit!
# WARNING: verification is considered EXPERIMENTAL
# https://source.android.com/docs/security/features/apksigning/v2#v2-verification
# https://source.android.com/docs/security/features/apksigning/v3#v3-verification
def verify_apk_signature_scheme(signers: Tuple[Union[V2Signer, V3Signer], ...],
                                apkfile: str, *, allow_unsafe: Tuple[str, ...] = (),
                                sdk: Optional[int] = None) -> Tuple[Tuple[str, str], ...]:
    """
    Verify APK Signature Scheme v2/v3.

    WARNING: verification is considered EXPERIMENTAL and SHOULD NOT BE RELIED
    ON, please use apksigner instead.

    NB: currently verifies all signatures, not just the one with the strongest
    supported signature algorithm ID.

    Raises VerificationError on failure.

    Returns the successfully verified signers (no less than 1, but less than the
    total number of signers when some are skipped because of min/max SDK) on
    success: a tuple of (cert_sha256_fingerprint, pubkey_sha256_fingerprint)
    pairs.
    """
    sb_offset, _ = extract_v2_sig(apkfile)
    verified = []
    if not signers:
        raise VerificationError("No signers")
    if not any(all(isinstance(s, c) for s in signers) for c in (V2Signer, V3Signer)):
        raise VerificationError("Mixed v2 and v3 signers")
    for signer in signers:
        if isinstance(signer, V3Signer):
            if signer.min_sdk != signer.signed_data.min_sdk:
                raise VerificationError("Min SDK of signer and signed data are not identical")
            if signer.max_sdk != signer.signed_data.max_sdk:
                raise VerificationError("Max SDK of signer and signed data are not identical")
            if sdk is not None and not (signer.min_sdk <= sdk <= signer.max_sdk):
                continue
        if not signer.signatures:
            raise VerificationError("No signatures")
        if not signer.signed_data.certificates:
            raise VerificationError("No certificates")
        if not signer.signed_data.digests:
            raise VerificationError("No digests")
        pk = signer.public_key
        c0 = signer.signed_data.certificates[0]
        da = sorted(d.signature_algorithm_id for d in signer.signed_data.digests)
        sa = sorted(s.signature_algorithm_id for s in signer.signatures)
        pk_algo = pk.public_key.algorithm
        if (key_algo := pk_algo.upper()) not in allow_unsafe:
            if (f := UNSAFE_KEY_SIZE[key_algo]) is not None and f(pk.public_key.bit_size):
                raise VerificationError(f"Unsafe {key_algo} key size: {pk.public_key.bit_size}")
        for sig in signer.signatures:
            if sig.signature_algorithm_id not in HASHERS:
                raise VerificationError(f"Unknown signature algorithm ID: {hex(sig.signature_algorithm_id)}")
            algo, _, halgo, pad, _ = HASHERS[sig.signature_algorithm_id]
            if pk_algo != algo:
                raise VerificationError(f"Public key algorithm mismatch: expected {algo}, got {pk_algo}")
            verify_signature(pk.raw_data, sig.signature, signer.signed_data.raw_data, halgo, pad)
        if c0.public_key.dump() != pk.raw_data:
            raise VerificationError("Public key does not match first certificate")
        if da != sa:
            raise VerificationError("Signature algorithm IDs of digests and signatures are not identical")
        for dig in signer.signed_data.digests:
            if dig.signature_algorithm_id not in HASHERS:
                raise VerificationError(f"Unknown signature algorithm ID: {hex(dig.signature_algorithm_id)}")
            _, hasher, _, _, chunk_type = HASHERS[dig.signature_algorithm_id]
            digest = _apk_digest(apkfile, sb_offset, hasher, chunk_type)
            if digest != dig.digest:
                raise VerificationError(f"Digest mismatch: expected {hexlify(dig.digest).decode()}, got {hexlify(digest).decode()}")
        verified.append((c0.certificate_info.fingerprint, pk.public_key_info.fingerprint))
    if not verified:
        raise VerificationError("No compatible signers")
    return tuple(verified)


def _apk_digest(apkfile: str, sb_offset: int, hasher, chunk_type: int) -> bytes:
    """Calculate APK digest (either chunked or verity)."""
    if chunk_type == CHUNKED:
        return apk_digest_chunked(apkfile, sb_offset, hasher)
    elif chunk_type == VERITY:
        return apk_digest_verity(apkfile, sb_offset, hasher)
    else:
        raise ValueError(f"Unknown chunk type: {chunk_type}")


def apk_digest_chunked(apkfile: str, sb_offset: int, hasher) -> bytes:
    """Calculate chunked digest for APK."""
    def f(size):
        while size > 0:
            data = fh.read(min(size, CHUNK_SIZE))
            if not data:
                break
            size -= len(data)
            digests.append(_chunk_digest(data, hasher))
    digests: List[bytes] = []
    cd_offset, eocd_offset, _ = apksigcopier.zip_data(apkfile)
    with open(apkfile, "rb") as fh:
        f(sb_offset)
        fh.seek(cd_offset)
        f(eocd_offset - cd_offset)
        fh.seek(eocd_offset)
        data = fh.read()
        data = data[:16] + int.to_bytes(sb_offset, 4, "little") + data[20:]
        digests.extend(_chunk_digest(c, hasher) for c in _chunks(data, CHUNK_SIZE))
    return _top_level_chunked_digest(digests, hasher)


def apk_digest_verity(apkfile: str, sb_offset: int, hasher) -> bytes:
    """Calculate verity digest for APK."""
    _assert(sb_offset % VERITY_BLOCK_SIZE == 0,
            "APK Sig Block offset must be a multiple of verity block size")
    digests = []
    cd_offset, eocd_offset, cd_and_eocd = apksigcopier.zip_data(apkfile)
    with open(apkfile, "rb") as fh:
        size = sb_offset
        while size > 0:
            data = fh.read(min(size, VERITY_BLOCK_SIZE))
            if not data:
                break
            size -= len(data)
            digests.append(_verity_block_digest(data, hasher))
        fh.seek(0, os.SEEK_END)
        total_size = fh.tell() - (cd_offset - sb_offset)
    off = eocd_offset - cd_offset
    sbo = int.to_bytes(sb_offset, 4, "little")
    data = _verity_pad(cd_and_eocd[:off + 16] + sbo + cd_and_eocd[off + 20:])
    digests.extend(_verity_block_digest(c, hasher) for c in _chunks(data, VERITY_BLOCK_SIZE))
    return _top_level_verity_digest(digests, total_size, hasher)


def _chunk_digest(chunk: bytes, hasher) -> bytes:
    data = b"\xa5" + int.to_bytes(len(chunk), 4, "little") + chunk
    return hasher(data).digest()


def _top_level_chunked_digest(digests: List[bytes], hasher) -> bytes:
    data = b"\x5a" + int.to_bytes(len(digests), 4, "little") + b"".join(digests)
    return hasher(data).digest()


def _verity_block_digest(block: bytes, hasher) -> bytes:
    _assert(len(block) == VERITY_BLOCK_SIZE, "verity block size")
    return hasher(VERITY_SALT + block).digest()


def _top_level_verity_digest(digests: List[bytes], total_size: int, hasher) -> bytes:
    data = _verity_pad(b"".join(digests))
    while len(data) > VERITY_BLOCK_SIZE:
        data = _verity_pad(b"".join(_verity_block_digest(c, hasher)
                                    for c in _chunks(data, VERITY_BLOCK_SIZE)))
    return hasher(VERITY_SALT + data).digest() + int.to_bytes(total_size, 8, "little")


def _verity_pad(data: bytes) -> bytes:
    if len(data) % VERITY_BLOCK_SIZE != 0:
        data += b"\x00" * (VERITY_BLOCK_SIZE - (len(data) % VERITY_BLOCK_SIZE))
    return data


def _chunks(data: bytes, blocksize: int) -> Iterator[bytes]:
    """Yield chunks of blocksize from data."""
    while data:
        chunk, data = data[:blocksize], data[blocksize:]
        yield chunk


# https://docs.oracle.com/javase/8/docs/technotes/guides/jar/jar.html
def parse_apk_v1_signature(extracted_meta: ZipInfoDataPairs, apkfile: Optional[str] = None,
                           *, allow_unsafe: Tuple[str, ...] = (), strict: bool = True) \
        -> JARSignature:
    """Parse v1 signature metadata files from apksigcopier.extract_meta()."""
    manifest = None
    sig_files = {}
    sig_block_files = {}
    for info, data in extracted_meta:
        if not apksigcopier.is_meta(info.filename):
            raise APKSigToolError(f"Not a v1 signature file: {info.filename!r}")
        if info.filename == JAR_MANIFEST:
            _assert(manifest is None, "duplicate manifest")
            manifest = parse_apk_v1_manifest(data)
        elif info.filename.endswith(".SF"):
            _assert(info.filename not in sig_files, "duplicate signature file")
            sig_files[info.filename] = parse_apk_v1_signature_file(info.filename, data)
        elif any(info.filename.endswith(f".{ext}") for ext in JAR_SBF_EXTS):
            _assert(info.filename not in sig_block_files, "duplicate signature block file")
            sbf = JARSignatureBlockFile(raw_data=data, filename=info.filename)
            _assert(sbf.public_key_info.algorithm == info.filename.split(".")[-1],
                    "public key algorithm must match file extension")
            sig_block_files[info.filename] = sbf
        else:
            raise APKSigToolError(f"Unexpected metadata file: {info.filename!r}")
    if manifest is None:
        raise APKSigToolError("Missing manifest")
    _assert(bool(sig_files), "must have at least one signature file")
    _assert(bool(sig_block_files), "must have at least one signature block file")
    sf_fb = tuple(map(_fn_base, sig_files.values()))
    sbf_fb = tuple(map(_fn_base, sig_block_files.values()))
    _assert(sorted(sf_fb) == sorted(sbf_fb), "signature files and signature block files must match")
    sbfs = sorted(sig_block_files.values(), key=lambda x: sf_fb.index(_fn_base(x)))
    sig = JARSignature(manifest=manifest, signature_files=tuple(sig_files.values()),
                       signature_block_files=tuple(sbfs))
    if apkfile is not None:
        verified: Union[Literal[False], Tuple[Tuple[str, str], ...]]
        verification_error = unverified_mf = unverified_sf = None
        try:
            verified, unverified_mf, unverified_sf = sig.verify(
                apkfile, allow_unsafe=allow_unsafe, strict=strict)
        except VerificationError as e:
            verified, verification_error = False, str(e)
        return dataclasses.replace(
            sig, verified=verified, verification_error=verification_error,
            unverified_mf=unverified_mf, unverified_sf=unverified_sf)
    return sig


# FIXME: what about other keys besides name & digests?
def parse_apk_v1_manifest(data: bytes) -> JARManifest:
    """Parse JAR manifest (MANIFEST.MF)."""
    headers, headers_len, ents = _parse_apk_v1_manifest(data)
    _assert("Manifest-Version" in headers, "manifest must have version")
    version = headers["Manifest-Version"]
    _assert(version == "1.0", "manifest version must be 1.0")
    created_by = headers.get("Created-By")
    built_by = headers.get("Built-By")
    entries = []
    for ent, raw in ents:
        _assert("Name" in ent, "entry must have name")
        entries.append(JAREntry(raw_data=raw, filename=ent["Name"],
                                digests=tuple(_digests_from_dict(ent))))
    return JARManifest(raw_data=data, entries=tuple(entries), version=version,
                       created_by=created_by, built_by=built_by, headers_len=headers_len)


# FIXME: what about other keys besides name & digests?
def parse_apk_v1_signature_file(filename: str, data: bytes) -> JARSignatureFile:
    """Parse JAR signature file (.SF)."""
    headers, headers_len, ents = _parse_apk_v1_manifest(data)
    _assert("Signature-Version" in headers, "signature file must have version")
    version = headers["Signature-Version"]
    _assert(version == "1.0", "signature file version must be 1.0")
    created_by = headers.get("Created-By")
    digests_manifest = tuple(_digests_from_dict(headers, "-Manifest"))
    digests_mma = tuple(_digests_from_dict(headers, "-Manifest-Main-Attributes")) or None
    xaas = headers.get("X-Android-APK-Signed")
    try:
        x_android_apk_signed = tuple(map(int, xaas.split(","))) if xaas else None
    except ValueError:
        _assert(False, "X-Android-APK-Signed must contain comma-separated integers")
    entries = []
    for ent, raw in ents:
        _assert("Name" in ent, "entry must have name")
        entries.append(JAREntry(raw_data=raw, filename=ent["Name"],
                                digests=tuple(_digests_from_dict(ent))))
    return JARSignatureFile(
        raw_data=data, entries=tuple(entries), version=version, created_by=created_by,
        digests_manifest=digests_manifest, digests_manifest_main_attributes=digests_mma,
        x_android_apk_signed=x_android_apk_signed, filename=filename, headers_len=headers_len)


def _digests_from_dict(ent: Dict[str, str], suffix: str = "") -> Iterator[Tuple[str, str]]:
    for k, v in ent.items():
        if m := re.fullmatch(JAR_DIGEST_HEADER + suffix, k):
            try:
                base64.b64decode(v, validate=True)
            except binascii.Error:
                _assert(False, "digest must be valid base64")
            yield m[1].replace("-", ""), v


# FIXME
def _parse_apk_v1_manifest(data: bytes) \
        -> Tuple[Dict[str, str], int, Tuple[Tuple[Dict[str, str], bytes], ...]]:
    lines = data.splitlines(keepends=True)
    i, n = 0, len(lines)
    headers: Dict[str, str] = {}
    raw_headers: List[bytes] = []
    entries = []
    entry, raw = headers, raw_headers
    while i < n:
        if not lines[i].rstrip(b"\r\n"):
            raw.append(lines[i])
            i += 1
            if i >= n:
                break
            _assert(bool(lines[i].rstrip(b"\r\n")), "consecutive empty lines")
            entry, raw = {}, []
            entries.append((entry, raw))
        raw.append(lines[i])
        _assert(b": " in lines[i], "header separator")
        key, val = lines[i].rstrip(b"\r\n").split(b": ", 1)
        key_d = key.decode()
        while i + 1 < n and lines[i + 1].startswith(b" "):
            raw.append(lines[i + 1])
            val += lines[i + 1][1:].rstrip(b"\r\n")
            i += 1
        _assert(key_d not in entry, "duplicate key")
        entry[key_d] = val.decode()
        i += 1
    if entries and not entries[-1][0]:
        entries.pop()
    return headers, len(b"".join(raw_headers)), tuple((e, b"".join(r)) for e, r in entries)


# FIXME
# FIXME: improve error messages
# FIXME: what about files in the .MF not in the .SF?
# WARNING: verification is considered EXPERIMENTAL
# https://docs.oracle.com/javase/tutorial/deployment/jar/intro.html
# https://docs.oracle.com/javase/8/docs/technotes/guides/jar/jar.html#Signature_Validation
def verify_apk_v1_signature(signature: JARSignature, apkfile: str, *,
                            allow_unsafe: Tuple[str, ...] = (), strict: bool = True) \
        -> Tuple[Tuple[Tuple[str, str], ...], Tuple[str, ...],
                 Tuple[Tuple[str, Tuple[str, ...]], ...]]:
    """
    Verify v1 (JAR) signature.

    WARNING: verification is considered EXPERIMENTAL and SHOULD NOT BE RELIED
    ON, please use apksigner instead.

    Verifies more strictly than the spec when strict is True,

    Raises an error for unsafe hash algorithms (like SHA1) and key sizes (or
    skips those digests when appropriate and strict is False) when allow_unsafe
    is False.

    Raises VerificationError on failure.

    Returns (verified_signers, unverified_mf, unverified_sf), where
    verified_signers is a tuple of (cert_sha256_fingerprint,
    pubkey_sha256_fingerprint) pairs, unverified_mf is a tuple of filenames in
    the ZIP but not in the manifest, and unverified_sf is a tuple of
    (sf_filename, filenames) for files in the manifest but not in the signature
    file.
    """
    verified = []
    manifest = {}
    unverified_sf = {}
    for entry in signature.manifest.entries:
        if entry.filename in manifest:
            raise VerificationError(f"Duplicate manifest entry: {entry.filename!r}")
        manifest[entry.filename] = entry
    for sf, sbf in zip(signature.signature_files, signature.signature_block_files):
        def halgo_f():
            return ECDSA(halgo()) if sbf.filename.endswith("EC") else halgo()
        if sbf.hash_algorithm is None:
            raise VerificationError("Unknown hash algorithm")
        halgo = JAR_HASHERS_STR[sbf.hash_algorithm][2]
        if sbf.hash_algorithm not in allow_unsafe and UNSAFE_HASH_ALGO[sbf.hash_algorithm]:
            raise VerificationError(f"Unsafe hash algorithm: {sbf.hash_algorithm}")
        if (key_algo := sbf.public_key_info.algorithm) not in allow_unsafe:
            if (f := UNSAFE_KEY_SIZE[key_algo]) is not None and f(sbf.public_key.bit_size):
                raise VerificationError(f"Unsafe {key_algo} key size: {sbf.public_key.bit_size}")
        pad = PKCS1v15 if sbf.filename.endswith("RSA") else None
        verify_signature(sbf.public_key.dump(), sbf.signature, sf.raw_data, halgo_f, pad)
        md_verified = False
        for algo, digest in sf.digests_manifest:
            hasher = JAR_HASHERS_STR[algo][1]
            if algo not in allow_unsafe and UNSAFE_HASH_ALGO[algo]:
                if strict:
                    raise VerificationError(f"Unsafe hash algorithm: {algo}")
                continue
            manifest_digest = hasher(signature.manifest.raw_data).digest()
            manifest_digest_b64 = base64.b64encode(manifest_digest).decode()
            if digest == manifest_digest_b64:
                md_verified = True  # spec says that's sufficient
                if not strict:
                    break
            elif strict:
                raise VerificationError(f"Manifest {algo} digest mismatch")
        if not md_verified:
            if sf.digests_manifest_main_attributes:
                mma_verified = False
                for algo, digest in sf.digests_manifest_main_attributes:
                    hasher = JAR_HASHERS_STR[algo][1]
                    if unsafe := algo not in allow_unsafe and UNSAFE_HASH_ALGO[algo]:
                        if strict:
                            raise VerificationError(f"Unsafe hash algorithm: {algo}")
                    hdrs = signature.manifest.raw_data[:signature.manifest.headers_len]
                    mma_digest = base64.b64encode(hasher(hdrs).digest()).decode()
                    if digest != mma_digest:
                        raise VerificationError(f"Manifest main attributes {algo} digest mismatch")
                    if not unsafe:
                        mma_verified = True
                if not mma_verified:
                    raise VerificationError("No suitable digests for manifest main attributes")
            for entry in sf.entries:
                if entry.filename not in manifest:
                    err = f"Signature file entry not in manifest: {entry.filename!r}"
                    raise VerificationError(err)
                entry_verified = False
                for algo, digest in entry.digests:
                    hasher = JAR_HASHERS_STR[algo][1]
                    if unsafe := algo not in allow_unsafe and UNSAFE_HASH_ALGO[algo]:
                        if strict:
                            raise VerificationError(f"Unsafe hash algorithm: {algo}")
                    entry_digest = hasher(manifest[entry.filename].raw_data).digest()
                    entry_digest_b64 = base64.b64encode(entry_digest).decode()
                    if digest != entry_digest_b64:
                        err = f"Manifest entry {algo} digest mismatch for {entry.filename!r}"
                        raise VerificationError(err)
                    if not unsafe:
                        entry_verified = True
                if not entry_verified:
                    err = f"No suitable digests for {entry.filename!r} in {sf.filename!r}"
                    raise VerificationError(err)
            if not_in_sf := tuple(sorted(set(manifest) - set(e.filename for e in sf.entries))):
                unverified_sf[sf.filename] = not_in_sf
                if strict:
                    raise VerificationError(f"Mainfest entries missing from {sf.filename!r}")
        verified.append((sbf.certificate_info.fingerprint, sbf.public_key_info.fingerprint))
    with zipfile.ZipFile(apkfile, "r") as zf:
        filenames = set(zi.filename for zi in zf.infolist())
        if len(filenames) != len(zf.infolist()):
            raise VerificationError("Duplicate ZIP entries")
        for filename, entry in manifest.items():
            if filename not in filenames:
                raise VerificationError(f"Manifest entry not in ZIP: {filename!r}")
            data_verified = False
            for algo, digest in entry.digests:
                hasher = JAR_HASHERS_STR[algo][1]
                if unsafe := algo not in allow_unsafe and UNSAFE_HASH_ALGO[algo]:
                    if strict:
                        raise VerificationError(f"Unsafe hash algorithm: {algo}")
                h = hasher()
                with zf.open(filename) as fh:
                    while data := fh.read(4096):
                        h.update(data)
                file_digest = base64.b64encode(h.digest()).decode()
                if digest != file_digest:
                    raise VerificationError(f"ZIP entry {algo} digest mismatch for {filename!r}")
                if not unsafe:
                    data_verified = True
            if not data_verified:
                raise VerificationError(f"No suitable digests for {filename!r} in manifest")
    unverified_mf = tuple(sorted(filenames - set(manifest)))
    if strict:
        for filename in unverified_mf:
            if not apksigcopier.is_meta(filename):
                raise VerificationError(f"ZIP entry not in manifest: {filename!r}")
    if not verified:
        raise VerificationError("No signers")
    return tuple(verified), unverified_mf, tuple(sorted(unverified_sf.items()))


# FIXME
# FIXME: catch exceptions?
def _load_apk_v1_signature_block_file_sig_algo_cert(data: bytes) \
        -> Tuple[bytes, Optional[str], X509Cert]:
    asn = pyasn1_decode(data)
    sig = asn[0][-1][-1][-1][-1].asOctets()     # FIXME
    hsh = asn[0][-1][-1][-1][-3][0]             # FIXME
    algo = JAR_HASHERS_OID.get(hsh, [None])[0]
    certs = load_der_pkcs7_certificates(data)
    _assert(len(certs) == 1, "signature block file must contain exactly 1 certificate")
    return sig, algo, X509Cert.load(certs[0].public_bytes(Encoding.DER))


# FIXME: type checking?!
# WARNING: verification is considered EXPERIMENTAL
def verify_signature(key: bytes, sig: bytes, msg: bytes, halgo, pad) -> None:
    """
    Verify signature (sig) from key on message (msg) using appropriate hashing
    algorithm and padding.

    WARNING: verification is considered EXPERIMENTAL and SHOULD NOT BE RELIED
    ON, please use apksigner instead.

    Raises VerificationError (as a result of InvalidSignature) on failure.
    """
    k = load_der_public_key(key)
    try:
        if pad is None:
            k.verify(sig, msg, halgo())                 # type: ignore
        else:
            k.verify(sig, msg, pad(), halgo())          # type: ignore
    except InvalidSignature:
        raise VerificationError("Invalid signature")    # pylint: disable=W0707


def x509_certificate_info(cert: X509Cert) -> CertificateInfo:
    """X.509 certificate info."""
    return CertificateInfo(
        subject=cert.subject.human_friendly,
        issuer=cert.issuer.human_friendly,
        serial_number=cert.serial_number,
        hash_algorithm=cert.hash_algo.upper(),
        signature_algorithm=cert.signature_algo.upper(),
        not_valid_before=cert.not_valid_before,
        not_valid_after=cert.not_valid_after,
        fingerprint=cert.sha256_fingerprint.replace(" ", "").lower())


def public_key_info(key: X509CertPubKeyInfo) -> PublicKeyInfo:
    """Public key info."""
    try:
        algo = key.hash_algo.upper()
    except ValueError:
        algo = None
    return PublicKeyInfo(
        algorithm=key.algorithm.upper(),
        bit_size=key.bit_size,
        fingerprint=sha256(key.dump()).hexdigest(),
        hash_algorithm=algo)


def aid_info(aid: int) -> str:
    """Signature algorithm ID info."""
    return SIGNATURE_ALGORITHM_IDS.get(aid, "UNKNOWN").split(";")[0]


def show_parse_tree(apk_signing_block: APKSigningBlock, *,
                    apkfile: Optional[str] = None, file: TextIO = sys.stdout,
                    sdk: Optional[int] = None, verbose: bool = False,
                    wrap: bool = False) -> None:
    """Print parse tree (w/ indent etc.) to file (stdout)."""
    p = _printer(file, wrap)
    for pair in apk_signing_block.pairs:
        if verbose:
            p("PAIR LENGTH:", pair.length)
        p("PAIR ID:", hex(pair.id))
        if isinstance(pair.value, APKSignatureSchemeBlock):
            show_apk_signature_scheme_block(pair.value, apkfile=apkfile, file=file,
                                            sdk=sdk, verbose=verbose, wrap=wrap)
        elif isinstance(pair.value, VerityPaddingBlock):
            p("  VERITY PADDING BLOCK")
        elif isinstance(pair.value, DependencyInfoBlock):
            p("  DEPENDENCY INFO BLOCK")
        elif isinstance(pair.value, GooglePlayFrostingBlock):
            p("  GOOGLE PLAY FROSTING BLOCK")
        elif isinstance(pair.value, SourceStampBlock):
            p(f"  SOURCE STAMP v{pair.value.version} BLOCK")
        else:
            p("  UNKNOWN BLOCK")
        if verbose and hasattr(pair.value, "raw_data"):
            _show_hex(pair.value.raw_data, 2, file=file, wrap=wrap)     # type: ignore


def show_apk_signature_scheme_block(block: APKSignatureSchemeBlock, *,
                                    apkfile: Optional[str] = None, file: TextIO = sys.stdout,
                                    sdk: Optional[int] = None, verbose: bool = False,
                                    wrap: bool = False) -> None:
    """Print APKSignatureSchemeBlock parse tree to file (stdout)."""
    p = _printer(file, wrap)
    p(f"  APK SIGNATURE SCHEME v{block.version} BLOCK")
    for i, signer in enumerate(block.signers):
        p("  SIGNER", i)
        p("    SIGNED DATA")
        for j, digest in enumerate(signer.signed_data.digests):
            p("      DIGEST", j)
            _show_aid(digest, 8, file=file, verbose=verbose, wrap=wrap)
            _show_hex(digest.digest, 8, file=file, wrap=wrap)
        for j, cert in enumerate(signer.signed_data.certificates):
            p("      CERTIFICATE", j)
            cert_info, pk_info = cert.certificate_info, cert.public_key_info
            show_x509_certificate_info(cert_info, pk_info, 8, file=file, verbose=verbose, wrap=wrap)
        if block.is_v3:
            assert isinstance(signer, V3Signer)
            p("      MIN SDK:", signer.signed_data.min_sdk)
            p("      MAX SDK:", signer.signed_data.max_sdk)
        for j, attr in enumerate(signer.signed_data.additional_attributes):
            p("      ADDITIONAL ATTRIBUTE", j)
            p("        ADDITIONAL ATTRIBUTE ID:", hex(attr.id))
            if attr.is_stripping_protection:
                p("        STRIPPING PROTECTION ATTR")
            elif attr.is_proof_of_rotation_struct:
                p("        PROOF OF ROTATION STRUCT")
            _show_hex(attr.value, 8, file=file, wrap=wrap)
        if block.is_v3:
            assert isinstance(signer, V3Signer)
            p("    MIN SDK:", signer.min_sdk)
            p("    MAX SDK:", signer.max_sdk)
        for j, sig in enumerate(signer.signatures):
            p("    SIGNATURE", j)
            _show_aid(sig, 6, file=file, verbose=verbose, wrap=wrap)
            _show_hex(sig.signature, 6, file=file, wrap=wrap)
        p("    PUBLIC KEY")
        show_public_key_info(signer.public_key.public_key_info, 6, file=file, wrap=wrap)
    if apkfile is not None:
        try:
            n = len(block.verify(apkfile, sdk=sdk))
        except VerificationError as e:
            p(f"  NOT VERIFIED ({e})")
        else:
            p(f"  VERIFIED ({n} signer(s))")
    else:
        p("  NOT VERIFIED (No APK file)")


# FIXME: show more? s/Common Name:/CN=/ etc?
def show_x509_certificate_info(info: CertificateInfo, pk_info: PublicKeyInfo,
                               indent: int, *, file: TextIO = sys.stdout,
                               verbose: bool = False, wrap: bool = False) -> None:
    """Print X.509 certificate information to file (stdout)."""
    p = _printer(file, wrap)
    p(" " * indent + "X.509 SUBJECT:", info.subject)
    if verbose:
        p(" " * indent + "X.509 ISSUER:", info.issuer)
        p(" " * indent + "X.509 SERIAL NUMBER:", hex(info.serial_number))
        p(" " * indent + "X.509 HASH ALGORITHM:", info.hash_algorithm)
        p(" " * indent + "X.509 SIGNATURE ALGORITHM:", info.signature_algorithm)
        p(" " * indent + "X.509 NOT VALID BEFORE:", info.not_valid_before)
        p(" " * indent + "X.509 NOT VALID AFTER:", info.not_valid_after)
    p(" " * indent + "X.509 SHA256 FINGERPRINT (HEX):", info.fingerprint)
    show_public_key_info(pk_info, indent, file=file, wrap=wrap)


def show_public_key_info(info: PublicKeyInfo, indent: int, *, file: TextIO = sys.stdout,
                         wrap: bool = False) -> None:
    """Print public key information to file (stdout)."""
    p = _printer(file, wrap)
    p(" " * indent + "PUBLIC KEY ALGORITHM:", info.algorithm)
    p(" " * indent + "PUBLIC KEY BIT SIZE:", info.bit_size)
    p(" " * indent + "PUBLIC KEY SHA256 FINGERPRINT (HEX):", info.fingerprint)
    if info.hash_algorithm is not None:
        p(" " * indent + "PUBLIC KEY HASH ALGORITHM:", info.hash_algorithm)


def _show_hex(data: bytes, indent: int, *, file: TextIO = sys.stdout,
              wrap: bool = False) -> None:
    """Print hex value (w/ indent etc.) to file (stdout)."""
    out = " " * indent + "VALUE (HEX): " + hexlify(data).decode()
    print(_wrap(out, indent, wrap), file=file)


def _show_aid(x: Union[Digest, Signature], indent: int, *,
              file: TextIO = sys.stdout, verbose: bool = False,
              wrap: bool = False) -> None:
    """Print signature algorithm ID (w/ indent etc.) to file (stdout)."""
    aid, aid_s = x.signature_algorithm_id, x.algoritm_id_info
    if not verbose:
        aid_s = aid_s.split(",")[0]
    out = " " * indent + f"SIGNATURE ALGORITHM ID: {hex(aid)} ({aid_s})"
    print(_wrap(out, indent, wrap), file=file)


def _printer(file: TextIO, wrap: bool):
    def p(*a):
        print(_wrap(" ".join(map(str, a)), wrap=wrap), file=file)
    return p


def _wrap(s: str, indent: Optional[int] = None, wrap: bool = True) -> str:
    if not wrap:
        return s
    i = len(re.split("^( *)", s, 1)[1]) if indent is None else indent
    return "\n".join(textwrap.wrap(s, width=WRAP_COLUMNS, subsequent_indent=" " * (i + 2)))


def show_v1_signature(signature: JARSignature, *, allow_unsafe: Tuple[str, ...] = (),
                      apkfile: Optional[str] = None, file: TextIO = sys.stdout,
                      strict: bool = True, verbose: bool = False, wrap: bool = False) -> None:
    """Print JARSignature parse tree (w/ indent etc.) to file (stdout)."""
    p = _printer(file, wrap)
    show_v1_manifest(signature.manifest, file=file, verbose=verbose, wrap=wrap)
    for sf in signature.signature_files:
        show_v1_signature_file(sf, file=file, verbose=verbose, wrap=wrap)
    for sbf in signature.signature_block_files:
        show_v1_signature_block_file(sbf, file=file, verbose=verbose, wrap=wrap)
    if apkfile is not None:
        try:
            signers, unverified_mf, unverified_sf = signature.verify(
                apkfile, allow_unsafe=allow_unsafe, strict=strict)
        except VerificationError as e:
            p(f"NOT VERIFIED ({e})")
        else:
            p(f"VERIFIED ({len(signers)} signature(s))")
            if verbose:
                if unverified_mf:
                    p("UNVERIFIED FILES (IN ZIP, NOT IN MANIFEST)")
                    for filename in unverified_mf:
                        p("  FILENAME:", repr(filename)[1:-1])
                if unverified_sf:
                    for sfn, filenames in unverified_sf:
                        p(f"UNVERIFIED FILES (IN MANIFEST, NOT IN {repr(sfn)[1:-1]})")
                        for filename in filenames:
                            p("  FILENAME:", repr(filename)[1:-1])
    else:
        p("NOT VERIFIED (No APK file)")


def show_v1_manifest(manifest: JARManifest, *, file: TextIO = sys.stdout,
                     verbose: bool = False, wrap: bool = False) -> None:
    """Print JARManifest parse tree (w/ indent etc.) to file (stdout)."""
    p = _printer(file, wrap)
    p("JAR MANIFEST")
    p("  VERSION:", manifest.version)
    if manifest.created_by:
        p("  CREATED BY:", manifest.created_by)
    if manifest.built_by:
        p("  BUILT BY:", manifest.built_by)
    if verbose:
        for i, entry in enumerate(manifest.entries):
            p("  ENTRY", i)
            p("    NAME:", repr(entry.filename)[1:-1])
            for algo, digest in entry.digests:
                p(f"    {algo} DIGEST: {digest}")


def show_v1_signature_file(sf: JARSignatureFile, *, file: TextIO = sys.stdout,
                           verbose: bool = False, wrap: bool = False) -> None:
    """Print JARSignatureFile parse tree (w/ indent etc.) to file (stdout)."""
    p = _printer(file, wrap)
    p("JAR SIGNATURE FILE")
    p("  FILENAME:", repr(sf.filename)[1:-1])
    p("  VERSION:", sf.version)
    if sf.created_by:
        p("  CREATED BY:", sf.created_by)
    for algo, digest in sf.digests_manifest:
        p(f"  {algo} MANIFEST DIGEST: {digest}")
    if sf.digests_manifest_main_attributes:
        for algo, digest in sf.digests_manifest_main_attributes:
            p(f"  {algo} MANIFEST MAIN ATTRIBUTES DIGEST: {digest}")
    if sf.x_android_apk_signed:
        p("  ANDROID APK SIGNED:", ", ".join(str(n) for n in sf.x_android_apk_signed))
    if verbose:
        for i, entry in enumerate(sf.entries):
            p("  ENTRY", i)
            p("    NAME:", repr(entry.filename)[1:-1])
            for algo, digest in entry.digests:
                p(f"    {algo} DIGEST: {digest}")


def show_v1_signature_block_file(sbf: JARSignatureBlockFile, *, file: TextIO = sys.stdout,
                                 verbose: bool = False, wrap: bool = False) -> None:
    """Print JARSignatureBlockFile parse tree (w/ indent etc.) to file (stdout)."""
    p = _printer(file, wrap)
    p("JAR SIGNATURE BLOCK FILE")
    p("  FILENAME:", repr(sbf.filename)[1:-1])
    p("  CERTIFICATE")
    cert_info, pk_info = sbf.certificate_info, sbf.public_key_info
    show_x509_certificate_info(cert_info, pk_info, 4, file=file, verbose=verbose, wrap=wrap)
    p("  SIGNATURE")
    _show_hex(sbf.signature, 4, file=file, wrap=wrap)
    p("  HASH ALGORITHM:", sbf.hash_algorithm)


def show_json(obj: APKSigToolBase, *, file: TextIO = sys.stdout) -> None:
    """Print parse tree as JSON to file (stdout)."""
    import simplejson
    simplejson.dump(obj, file, indent=2, sort_keys=True, encoding=None,
                    default=json_dump_default, for_json=True)
    print(file=file)


def json_dump_default(obj):
    """
    Returns serializable versions of bytes (hex str) and datetime.datetime (str)
    for simplejson.dump().

    >>> import io, simplejson
    >>> from apksigtool import json_dump_default
    >>> out = io.StringIO()
    >>> simplejson.dump(dict(foo=b"bar"), out, encoding=None, default=json_dump_default)
    >>> print(out.getvalue())
    {"foo": "626172"}

    """
    if isinstance(obj, bytes):
        return hexlify(obj).decode()
    if isinstance(obj, datetime.datetime):
        return str(obj)
    raise TypeError(repr(obj) + " is not JSON serializable")


def asdict(obj: APKSigToolBase):
    """dataclasses.asdict() with a dict_factory that skips attributes that start with _."""
    def dict_factory(pairs):
        return dict((k, v) for k, v in pairs if not k.startswith("_"))
    return dataclasses.asdict(obj, dict_factory=dict_factory)


def extract_v2_sig(apkfile: str) -> Tuple[int, bytes]:
    extracted_v2_sig = apksigcopier.extract_v2_sig(apkfile)
    assert extracted_v2_sig is not None
    return extracted_v2_sig


def load_extracted_meta_from_dir(path: str) -> Iterator[Tuple[zipfile.ZipInfo, bytes]]:
    for ext in JAR_META_EXTS:
        for fn in glob.glob(os.path.join(path, "*." + ext)):
            info = zipfile.ZipInfo("META-INF/" + os.path.basename(fn))
            with open(fn, "rb") as fh:
                yield info, fh.read()


# FIXME
# FIXME: handle common signers properly.
# FIXME: handle key rotation etc.
# WARNING: verification is considered EXPERIMENTAL
def verify_apk_and_check_signers(
        apkfile, *, allow_unsafe: Tuple[str, ...] = (), check_v1: bool = False,
        quiet: bool = True, sdk_version: Optional[int] = None, verbose: bool = False) -> bool:
    """
    Verify APK signatures and check whether signers match between v1/v2/v3.

    WARNING: verification is considered EXPERIMENTAL and SHOULD NOT BE RELIED
    ON, please use apksigner instead.

    Returns True on success, False on failure.
    """
    all_signers = []
    required_sig_versions = set()
    if check_v1:
        res = _verify_v1(apkfile, allow_unsafe=allow_unsafe, expected=False, quiet=quiet)
        if res:
            _, sig, v1_signers = res
            all_signers.append(set(v1_signers))
            required_sig_versions = set(sig.required_signature_versions)
        v1_ok = bool(res or res is None)
    else:
        v1_ok = True
    verified, failed = verify_apk(apkfile, allow_unsafe=allow_unsafe, sdk=sdk_version)
    for version, signers in verified:
        required_sig_versions.discard(version)
        all_signers.append(set(signers))
        if not quiet:
            print(f"v{version} verified ({len(signers)} signer(s))")
    for version, e in failed:
        if not quiet:
            print(f"v{version} not verified ({e})")
    if failed or not verified or not v1_ok:
        return False
    if required_sig_versions:
        if not quiet:
            for n in sorted(required_sig_versions):
                print(f"v{n} signature(s) not found but required")
        return False
    common_signers = reduce(lambda x, y: x & y, all_signers)
    if not common_signers:
        if not quiet:
            print("no common signers")
        return False
    if verbose:
        for cert, pk in sorted(common_signers):
            print("common signer:")
            print(f"  {cert} (sha256 fingerprint of certificate)")
            print(f"  {pk} (sha256 fingerprint of public key)")
    return True


# FIXME: warn about unverified files?
def _verify_v1(apk, *, allow_unsafe: Tuple[str, ...] = (), expected: bool = True,
               quiet: bool = True, strict: bool = True) \
        -> Union[Tuple[Literal[True], JARSignature, Tuple[Tuple[str, str], ...]],
                 Literal[False], None]:
    res = verify_apk_v1(apk, allow_unsafe=allow_unsafe, expected=expected, strict=strict)
    if not res:
        if not quiet:
            print("v1 signature(s) not found")
        return None
    else:
        if res[0]:
            _, sig, signers, _, _ = res
            if not quiet:
                print(f"v1 verified ({len(signers)} signature(s))")
            return True, sig, signers
        else:
            _, err = res
            if not quiet:
                print(f"v1 not verified ({err})")
            return False


# FIXME
# WARNING: verification is considered EXPERIMENTAL
def verify_apk(apkfile: str, sig_block: Optional[bytes] = None, *,
               allow_unsafe: Tuple[str, ...] = (), sdk: Optional[int] = None) \
        -> Tuple[Tuple[Tuple[int, Tuple[Tuple[str, str], ...]], ...],
                 Tuple[Tuple[int, Exception], ...]]:
    """
    Verify APK file using the APK Signature Scheme v2/v3 Blocks found parsing
    the APK Signing Block.

    WARNING: verification is considered EXPERIMENTAL and SHOULD NOT BE RELIED
    ON, please use apksigner instead.

    If sig_block is None, it will be extracted from the APK using
    apksigcopier.extract_v2_sig().

    Returns (verified, failed), where verified is a tuple of (version, signers)
    of verification successes, and failed is a tuple of (version, exception)
    tuples of verification failures.
    """
    if sig_block is None:
        _, sig_block = extract_v2_sig(apkfile)
    return APKSigningBlock.parse(sig_block).verify_results(
        apkfile, allow_unsafe=allow_unsafe, sdk=sdk)


# FIXME
# FIXME: rollback protections.
# WARNING: verification is considered EXPERIMENTAL
def verify_apk_v1(apkfile: str, *, allow_unsafe: Tuple[str, ...] = (),
                  expected: bool = True, strict: bool = True) \
        -> Union[Tuple[Literal[True], JARSignature,
                       Tuple[Tuple[str, str], ...], Tuple[str, ...],
                       Tuple[Tuple[str, Tuple[str, ...]], ...]],
                 Tuple[Literal[False], str], None]:
    """
    Verify APK file using the v1 (JAR) signatures.

    WARNING: verification is considered EXPERIMENTAL and SHOULD NOT BE RELIED
    ON, please use apksigner instead.

    Returns None when no v1 signature was found and expected is False, otherwise
    (True, verified_signers, unverified_files) on success and (False, error) on
    failure.
    """
    e_meta = tuple(apksigcopier.extract_meta(apkfile))
    if not e_meta or [i.filename for i, _ in e_meta] == [JAR_MANIFEST]:
        if expected:
            return False, "Missing v1 signature"
        return None
    sig = JARSignature.parse(e_meta)
    try:
        signers, unverified_mf, unverified_sf = sig.verify(
            apkfile, allow_unsafe=allow_unsafe, strict=strict)
        return True, sig, signers, unverified_mf, unverified_sf
    except VerificationError as err:
        return False, str(err)


# NB: modifies in-place!
def clean_apk(apkfile: str, *, check: bool = False, keep: Tuple[int, ...] = (),
              sdk: Optional[int] = None) -> bool:
    """
    Clean APK file: remove everything that's not an APK Signature Scheme v2/v3
    Block or verity padding block (or has a pair_id in keep) from its APK
    Signing Block.

    NB: modifies the file in-place!.

    Does not modify the APK file when the cleaned block is equal to the
    original.

    Raises VerificationError when check is True and verify_apk() has failures or
    no successes.

    Returns True when the APK was modified, False otherwise.
    """
    sb_offset, sig_block = extract_v2_sig(apkfile)
    if check:
        verified, failed = verify_apk(apkfile, sig_block, sdk=sdk)
        if failed or not verified:
            raise VerificationError("Verification failed")
    sig_block_cleaned = clean_apk_signing_block(sig_block, keep=keep)
    if sig_block == sig_block_cleaned:
        return False
    data_out = apksigcopier.zip_data(apkfile)
    offset = len(sig_block_cleaned) - len(sig_block)
    with open(apkfile, "r+b") as fh:
        fh.seek(sb_offset)
        fh.write(sig_block_cleaned)
        fh.write(data_out.cd_and_eocd)
        fh.truncate()
        fh.seek(data_out.eocd_offset + offset + 16)
        fh.write(int.to_bytes(data_out.cd_offset + offset, 4, "little"))
    return True


def main():
    """CLI; requires click."""

    global WRAP_COLUMNS
    if (columns := os.environ.get("APKSIGTOOL_WRAP_COLUMNS", "")).isdigit():
        WRAP_COLUMNS = int(columns)

    import click

    UNSAFE = click.Choice(tuple(
        k for d in (UNSAFE_HASH_ALGO, UNSAFE_KEY_SIZE) for k, v in d.items() if v))

    @click.group(help="""
        apksigtool - parse/verify/clean android apk signing blocks & apks
    """)
    @click.version_option(__version__)
    def cli():
        pass

    @cli.command(help="""
        Parse APK Signing Block (from APK or extracted block) and output a parse
        tree (indented with spaces) or JSON.
    """)
    @click.option("--block", is_flag=True,
                  help="APK_OR_BLOCK is an extracted block, not an APK.")
    @click.option("--json", is_flag=True, help="JSON output.")
    @click.option("--sdk-version", type=click.INT, help="For v3 signers specifying min/max SDK.")
    @click.option("-v", "--verbose", is_flag=True, help="Be verbose (no-op w/ --json).")
    @click.option("--wrap", is_flag=True, help="Wrap output (no-op w/ --json).")
    @click.argument("apk_or_block", type=click.Path(exists=True, dir_okay=False))
    def parse(apk_or_block, block, json, sdk_version, verbose, wrap):
        if block:
            apkfile = None
            with open(apk_or_block, "rb") as fh:
                sig_block = fh.read()
        else:
            apkfile = apk_or_block
            _, sig_block = extract_v2_sig(apkfile)
        if json:
            show_json(APKSigningBlock.parse(sig_block, apkfile=apkfile, sdk=sdk_version))
        else:
            show_parse_tree(APKSigningBlock.parse(sig_block), apkfile=apkfile,
                            sdk=sdk_version, verbose=verbose, wrap=wrap)

    @cli.command(help="""
        Parse APK v1 (JAR) signatures (from APK or extracted files in a
        directory) and output a parse tree (indented with spaces) or JSON.
    """)
    @click.option("--allow-unsafe", multiple=True, default=(), type=UNSAFE,
                  help="Allow specified unsafe hash algorithm(s) (e.g. SHA1) or "
                       "key sizes for specified encryption(s) (e.g. RSA).")
    @click.option("--json", is_flag=True, help="JSON output.")
    @click.option("--no-strict", is_flag=True, help="Don't be stricter than the spec.")
    @click.option("-v", "--verbose", is_flag=True, help="Be verbose (no-op w/ --json).")
    @click.option("--wrap", is_flag=True, help="Wrap output (no-op w/ --json).")
    @click.argument("apk_or_dir", type=click.Path(exists=True, dir_okay=True))
    def parse_v1(apk_or_dir, allow_unsafe, json, no_strict, verbose, wrap):
        if os.path.isdir(apk_or_dir):
            apkfile = None
            e_meta = load_extracted_meta_from_dir(apk_or_dir)
        else:
            apkfile = apk_or_dir
            e_meta = apksigcopier.extract_meta(apk_or_dir)
        if json:
            show_json(JARSignature.parse(e_meta, apkfile=apkfile, allow_unsafe=allow_unsafe,
                                         strict=not no_strict))
        else:
            show_v1_signature(JARSignature.parse(e_meta), allow_unsafe=allow_unsafe,
                              apkfile=apkfile, strict=not no_strict, verbose=verbose, wrap=wrap)

    # FIXME
    @cli.command(help="""
        Verify APK using the APK Signature Scheme v2/v3 Blocks in its APK
        Signing Block.

        WARNING: verification is considered EXPERIMENTAL and SHOULD NOT BE
        RELIED ON, please use apksigner instead.
    """)
    @click.option("--allow-unsafe", multiple=True, default=(), type=UNSAFE,
                  help="Allow specified unsafe hash algorithm(s) (e.g. SHA1) or "
                       "key sizes for specified encryption(s) (e.g. RSA).")
    @click.option("--check-v1", is_flag=True, help="Validate v1 signature (if any) as well.")
    @click.option("--quiet", is_flag=True, help="Don't print 'vN verified' etc. to stdout.")
    @click.option("--sdk-version", type=click.INT, help="For v3 signers specifying min/max SDK.")
    @click.option("-v", "--verbose", is_flag=True, help="Show signer(s).")
    @click.argument("apk", type=click.Path(exists=True, dir_okay=False))
    def verify(apk, allow_unsafe, check_v1, quiet, sdk_version, verbose):
        print("WARNING: verification is considered EXPERIMENTAL,"
              " please use apksigner instead.", file=sys.stderr)
        if not verify_apk_and_check_signers(apk, allow_unsafe=allow_unsafe, check_v1=check_v1,
                                            quiet=quiet, sdk_version=sdk_version, verbose=verbose):
            sys.exit(4)

    # FIXME
    @cli.command(help="""
        Verify APK v1 (JAR) signatures.

        WARNING: verification is considered EXPERIMENTAL and SHOULD NOT BE
        RELIED ON, please use apksigner instead.
    """)
    @click.option("--allow-unsafe", multiple=True, default=(), type=UNSAFE,
                  help="Allow specified unsafe hash algorithm(s) (e.g. SHA1) or "
                       "key sizes for specified encryption(s) (e.g. RSA).")
    @click.option("--no-strict", is_flag=True, help="Don't be stricter than the spec.")
    @click.option("--quiet", is_flag=True, help="Don't print 'vN verified' etc. to stdout.")
    @click.option("--rollback-is-error", is_flag=True,
                  help="Exit with status 5 if v2/v3 signature(s) are required.")
    @click.argument("apk", type=click.Path(exists=True, dir_okay=False))
    def verify_v1(apk, allow_unsafe, no_strict, quiet, rollback_is_error):
        print("WARNING: verification is considered EXPERIMENTAL,"
              " please use apksigner instead.", file=sys.stderr)
        res = _verify_v1(apk, allow_unsafe=allow_unsafe, quiet=quiet, strict=not no_strict)
        if not res:
            sys.exit(4)
        if required_sv := res[1].required_signature_versions:
            what = "Error" if rollback_is_error else "Warning"
            vsns = ", ".join(f"v{n}" for n in sorted(required_sv))
            sys.stdout.flush()  # FIXME
            print(f"{what}: rollback protections require {vsns} signature(s) as well.",
                  file=sys.stderr)
            if rollback_is_error:
                sys.exit(5)

    @cli.command(help="""
        Clean APK (or extracted block): remove everything that's not an APK
        Signature Scheme v2/v3 Block or verity padding block (or has a pair_id
        in keep) from its APK Signing Block.

        NB: modifies in-place!
    """)
    @click.option("--block", is_flag=True,
                  help="APK_OR_BLOCK is an extracted block, not an APK.")
    @click.option("--check", is_flag=True,
                  help="Raise error when parsing or verification (no --block) fails.")
    @click.option("--keep", multiple=True, default=(), metavar="HEXID",
                  help="Do not remove pairs with the specified hex ID(s); use multiple "
                       "times or separate IDs with commas to specify multiple IDs.")
    @click.option("--sdk-version", type=click.INT,
                  help="For v3 signers specifying min/max SDK.")
    @click.argument("apk_or_block", type=click.Path(exists=True, dir_okay=False))
    @click.pass_context
    def clean(ctx, apk_or_block, block, check, keep, sdk_version):
        try:
            keep = tuple(int(x, 16) for p in keep for x in p.split(","))
        except ValueError as e:
            p, = [x for x in clean.params if x.name == "keep"]
            raise click.exceptions.BadParameter(e.args[0], ctx, p)
        if block:
            with open(apk_or_block, "rb") as fh:
                sig_block = fh.read()
            if check:
                APKSigningBlock.parse(sig_block)    # try parsing, ignore result
            sig_block_cleaned = clean_apk_signing_block(sig_block, keep=keep)
            if cleaned := (sig_block != sig_block_cleaned):
                with open(apk_or_block, "wb") as fh:
                    fh.write(sig_block_cleaned)
        else:
            cleaned = clean_apk(apk_or_block, check=check, keep=keep, sdk=sdk_version)
        if cleaned:
            print("cleaned")
        else:
            print("nothing to clean")

    # FIXME
    # @cli.command(help="""
    #     ...
    # """)
    # @click.argument("apk", type=click.Path(exists=True, dir_okay=False))
    # def sign(apk):
    #     ...

    try:
        cli(prog_name=NAME)
    except (APKSigToolError, APKSigCopierError, zipfile.BadZipFile) as e:
        sys.stdout.flush()  # FIXME
        print(f"Error: {e}.", file=sys.stderr)
        sys.exit(3)


if __name__ == "__main__":
    main()

# vim: set tw=80 sw=4 sts=4 et fdm=marker :
