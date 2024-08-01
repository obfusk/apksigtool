#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2024 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
parse/verify/clean/sign android apk (signing block)

apksigtool is a tool for parsing android APK Signing Blocks (either embedded in
an APK or extracted as a separate file, e.g. using apksigcopier) and verifying
APK signatures.  It can also clean them (i.e. remove everything that's not an
APK Signature Scheme v2/v3 Block or verity padding block), which can be useful
for reproducible builds, and sign APKs.

WARNING: verification and signing are considered EXPERIMENTAL and SHOULD NOT BE
RELIED ON, please use apksigner instead.


CLI
===

$ apksigtool parse [--block] [--json] [--verbose] [--wrap] APK_OR_BLOCK
$ apksigtool verify [--check-v1] [--quiet] [--verbose] APK
$ apksigtool extract-certs [--block] APK_OR_BLOCK_OR_DIR OUTPUT_DIR
$ apksigtool clean [--block] [--check] [--keep HEXID] APK_OR_BLOCK
$ apksigtool sign --cert CERT --key PRIVKEY UNSIGNED_APK OUTPUT_APK

$ apksigtool parse-v1 [--json] [--verbose] [--wrap] APK_OR_DIR
$ apksigtool verify-v1 [--quiet] [--rollback-is-error] APK


API
===

NB: every CLI command maps to an API function: e.g. parse to do_parse().

#>> import apksigtool
#>> apksigtool.do_parse(apk, verbose=True)
#>> apksigtool.do_parse_v1(apk, verbose=True)
#>> apksigtool.do_extract_certs(apk, output_dir)
#>> apksigtool.do_verify(apk, check_v1=True)                # [EXPERIMENTAL]
#>> apksigtool.do_verify_v1(apk, allow_unsafe=("SHA1",))    # [EXPERIMENTAL]
#>> apksigtool.do_clean(apk)                                # NB: modifies existing APK!
#>> apksigtool.do_sign(unsigned_apk, output_apk, cert=cert_file,
...                    key=key_file, password=password)     # [EXPERIMENTAL]


APK Signing Block
-----------------

>>> import apksigtool as ast, io
>>> apk = "test/apks/apks/golden-aligned-v1v2v3-out.apk"
>>> _, data = ast.extract_v2_sig(apk)
>>> blk = ast.APKSigningBlock.parse(data)       # parse APK Signing Block
>>> blk == ast.parse_apk_signing_block(data)    # same as above
True
>>> [hex(p.id) for p in blk.pairs]
['0x7109871a', '0xf05368c0', '0x42726577']
>>> data == blk.dump()
True

>>> out = io.StringIO()
>>> ast.show_parse_tree(blk, file=out)          # print parse tree
>>> for line in out.getvalue().splitlines():
...     if line.startswith("PAIR ID") or "BLOCK" in line:
...         print(line)
PAIR ID: 0x7109871a
  APK SIGNATURE SCHEME v2 BLOCK
PAIR ID: 0xf05368c0
  APK SIGNATURE SCHEME v3 BLOCK
PAIR ID: 0x42726577
  VERITY PADDING BLOCK
>>> out = io.StringIO()
>>> ast.show_json(blk, file=out)                # JSON
>>> for line in out.getvalue().splitlines()[:10]:
...     print(line)
{
  "_type": "APKSigningBlock",
  "pairs": [
    {
      "_type": "Pair",
      "id": 1896449818,
      "length": 1427,
      "value": {
        "_type": "APKSignatureSchemeBlock",
        "signers": [

>>> blk.verify(apk)                             # [EXPERIMENTAL] raises on failure
>>> result = blk.verify_result(apk)
>>> result.is_verified
True
>>> result.is_v2_verified, result.is_v3_verified, result.is_v31_verified
(True, True, False)
>>> ast.versions_sorted(result.verified_signature_versions)
(2, 3)
>>> len(result.verified), len(result.failed)
(2, 0)
>>> result == ast.verify_apk(apk)               # uses .verify_result()
True

>>> r = ast.verify_apk_and_check_signers(apk, check_v1=True)
>>> r.is_v1_verified, r.is_v2_verified, r.is_v3_verified, r.is_v31_verified
(True, True, True, False)
>>> ast.versions_sorted(r.verified_signature_versions)
(1, 2, 3)

>>> apk = "test/apks/apks/v2-only-cert-and-public-key-mismatch.apk"
>>> result = ast.verify_apk(apk)
>>> result.is_verified
False
>>> for version, error in result.failed:
...     print(f"v{version}: {error}")
v2: Public key does not match first certificate
>>> blk = ast.APKSigningBlock.parse(ast.extract_v2_sig(apk)[1])
>>> try:
...     blk.verify(apk)
... except ast.VerificationError as e:
...     print(e)
Public key does not match first certificate


Cleaning
--------

>>> import apksigtool as ast, io
>>> apk = "test/apks/apks/v3-only-with-stamp.apk"
>>> _, data = ast.extract_v2_sig(apk)
>>> data_cleaned = ast.clean_apk_signing_block(data)
>>> len(data), len(data_cleaned)
(4096, 3027)

#>> ast.clean_apk(some_apk)                     # NB: modifies existing APK!


v1 (JAR) signatures
-------------------

>>> import apksigtool as ast, io
>>> apk = "test/apks/apks/golden-aligned-v1v2v3-out.apk"
>>> meta = ast.extract_meta(apk)
>>> [x.filename for x, _ in meta]
['META-INF/RSA-2048.SF', 'META-INF/RSA-2048.RSA', 'META-INF/MANIFEST.MF']
>>> sig = ast.JARSignature.parse(meta)          # parse v1 signature
>>> sig == ast.parse_apk_v1_signature(meta)     # same as above
True

>>> out = io.StringIO()
>>> ast.show_v1_signature(sig, file=out)        # print parse tree
>>> for line in out.getvalue().splitlines()[:11]:
...     print(line)
JAR MANIFEST
  VERSION: 1.0
  CREATED BY: 1.8.0_45-internal (Oracle Corporation)
JAR SIGNATURE FILE
  FILENAME: META-INF/RSA-2048.SF
  VERSION: 1.0
  CREATED BY: 1.0 (Android)
  SHA256 MANIFEST DIGEST: hz7AxDJU9Namxoou/kc4Z2GVRS9anCGI+M52tbCsXT0=
  ANDROID APK SIGNED: 2, 3
JAR SIGNATURE BLOCK FILE
  FILENAME: META-INF/RSA-2048.RSA
>>> out = io.StringIO()
>>> ast.show_json(sig, file=out)                # JSON
>>> for line in out.getvalue().splitlines()[:7]:
...     print(line)
{
  "_type": "JARSignature",
  "manifest": {
    "_type": "JARManifest",
    "built_by": null,
    "created_by": "1.8.0_45-internal (Oracle Corporation)",
    "entries": [

>>> result = sig.verify(apk)                    # [EXPERIMENTAL] raises on failure
>>> result.unverified_mf
('META-INF/MANIFEST.MF', 'META-INF/RSA-2048.RSA', 'META-INF/RSA-2048.SF')
>>> len(result.verified_signers)
1

>>> apk = "test/apks/apks/v1-only-with-nul-in-entry-name.apk"
>>> ast.verify_apk_v1(apk)
JARVerificationFailure(error="Manifest entry not in ZIP: 'test.txt\\\\x00'")
>>> sig = ast.JARSignature.parse(ast.extract_meta(apk))
>>> try:
...     sig.verify(apk)
... except ast.VerificationError as e:
...     print(e)
Manifest entry not in ZIP: 'test.txt\\x00'


Signing
-------

#>> import apksigtool
#>> unsigned_apk = "path/to/unsigned.apk"
#>> output_apk = "path/to/output.apk"
#>> cert = "path/to/cert.der"
#>> key = "path/to/privkey.der"
#>> password = "top secret"
#>> apksigtool.do_sign(unsigned_apk, output_apk, cert=cert,
...                    key=key, password=password)  # [EXPERIMENTAL]

#>> from cryptography.hazmat.primitives import serialization
#>> with open(cert, "rb") as fh:
#>>     cert_bytes = fh.read()
#>> with open(key, "rb") as fh:
#>>     key_bytes = fh.read()
#>> privkey = serialization.load_der_private_key(key_bytes, password.encode())
#>> apksigtool.sign_apk(unsigned_apk, output_apk, cert=cert_bytes,
...                     key=privkey)                # low-level API

"""

from __future__ import annotations

import abc
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
from enum import Flag
from functools import reduce
from hashlib import md5, sha1, sha224, sha256, sha384, sha512
from typing import (cast, Any, Callable, ClassVar, Dict, FrozenSet, Iterable, Iterator, List,
                    Literal, Mapping, Optional, Set, TextIO, Tuple, Type, TypeVar, Union)

import apksigcopier

from apksigcopier import APKSigCopierError, ZipInfoDataPairs
from asn1crypto.keys import PublicKeyInfo as X509CertPubKeyInfo     # type: ignore[import-untyped]
from asn1crypto.x509 import Certificate as X509Cert                 # type: ignore[import-untyped]
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPrivateKey, DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.padding import MGF1, PKCS1v15, PSS
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.hashes import HashAlgorithm, MD5, SHA1, SHA224, SHA256, SHA384, SHA512
from cryptography.hazmat.primitives.serialization.pkcs7 import load_der_pkcs7_certificates
from pyasn1.codec.der.decoder import decode as pyasn1_decode
from pyasn1.codec.der.encoder import encode as pyasn1_encode
from pyasn1.error import PyAsn1Error
from pyasn1.type import univ as pyasn1_univ
from pyasn1_modules import rfc2315                                  # type: ignore[import-untyped]

__version__ = "0.1.0"
NAME = "apksigtool"

Halgo = Union[HashAlgorithm, ECDSA]
HalgoFun = Union[Callable[[], Halgo], Type[HashAlgorithm]]
PadFun = Union[Callable[[], PSS], Type[PKCS1v15]]

PrivKey = Union[RSAPrivateKey, DSAPrivateKey, EllipticCurvePrivateKey]
PrivKeyTypes = (RSAPrivateKey, DSAPrivateKey, EllipticCurvePrivateKey)
PubKey = Union[RSAPublicKey, DSAPublicKey, EllipticCurvePublicKey]
PubKeyTypes = (RSAPublicKey, DSAPublicKey, EllipticCurvePublicKey)

SchemeVersion = Literal[2, 3, "3.1"]

T = TypeVar("T")

# FIXME: list of block type IDs is incomplete
# https://source.android.com/docs/security/features/apksigning/v2#apk-signing-block-format
APK_SIGNATURE_SCHEME_V2_BLOCK_ID = 0x7109871a
APK_SIGNATURE_SCHEME_V3_BLOCK_ID = 0xf05368c0

# FIXME: undocumented & not used properly
APK_SIGNATURE_SCHEME_V31_BLOCK_ID = 0x1b93ad61

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

# FIXME: not used properly
STRIPPING_PROTECTION_ATTR_ID = 0xbeeff00d
ROTATION_MIN_SDK_VERSION_ATTR_ID = 0x559f8b02
ROTATION_ON_DEV_RELEASE_ATTR_ID = 0xc2a6b3ba

# signing lineage & proof of rotation
PROOF_OF_ROTATION_ATTR_ID = 0x3ba06f8c
PROOF_OF_ROTATION_VERSION = 1

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
HASHERS: Dict[int, Tuple[str, Any, HalgoFun, Optional[PadFun], int]] = {
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

assert set(SIGNATURE_ALGORITHM_IDS) == set(HASHERS)

# in order of preference
HASH_ALGOS = dict(RSA=("SHA512", "SHA256"), DSA=("SHA256",), EC=("SHA512", "SHA256"))

# FIXME: choose best?!
SIGNATURE_ALGORITHM = dict(
    RSA=dict(SHA256=0x0103, SHA512=0x0104),   # deterministic
    DSA=dict(SHA256=0x0301),                  # non-deterministic
    EC=dict(SHA256=0x0201, SHA512=0x0202),    # non-deterministic
)

assert all(v in HASHERS for d in SIGNATURE_ALGORITHM.values() for v in d.values())

CHUNK_SIZE = 1048576
VERITY_BLOCK_SIZE = 4096

# FIXME
VERITY_SALT = b"\x00" * 8

MIN_SDK, MAX_SDK = 24, 2 * 1024**3 - 1

# FIXME: pyasn1_modules.rfc5480 is not available in bullseye/jammy
RFC5480 = dict(
    id_sha224=pyasn1_univ.ObjectIdentifier("2.16.840.1.101.3.4.2.4"),
    id_sha256=pyasn1_univ.ObjectIdentifier("2.16.840.1.101.3.4.2.1"),
    id_sha384=pyasn1_univ.ObjectIdentifier("2.16.840.1.101.3.4.2.2"),
    id_sha512=pyasn1_univ.ObjectIdentifier("2.16.840.1.101.3.4.2.3"),
    id_md5=pyasn1_univ.ObjectIdentifier("1.2.840.113549.2.5"),
    id_sha1=pyasn1_univ.ObjectIdentifier("1.3.14.3.2.26"),

    rsaEncryption=pyasn1_univ.ObjectIdentifier("1.2.840.113549.1.1.1"),
    md5WithRSAEncryption=pyasn1_univ.ObjectIdentifier("1.2.840.113549.1.1.4"),
    sha1WithRSAEncryption=pyasn1_univ.ObjectIdentifier("1.2.840.113549.1.1.5"),

    id_dsa=pyasn1_univ.ObjectIdentifier("1.2.840.10040.4.1"),
    id_dsa_with_sha1=pyasn1_univ.ObjectIdentifier("1.2.840.10040.4.3"),
    id_dsa_with_sha224=pyasn1_univ.ObjectIdentifier("2.16.840.1.101.3.4.3.1"),
    id_dsa_with_sha256=pyasn1_univ.ObjectIdentifier("2.16.840.1.101.3.4.3.2"),

    id_ecPublicKey=pyasn1_univ.ObjectIdentifier("1.2.840.10045.2.1"),
    ecdsa_with_SHA1=pyasn1_univ.ObjectIdentifier("1.2.840.10045.4.1"),
    ecdsa_with_SHA224=pyasn1_univ.ObjectIdentifier("1.2.840.10045.4.3.1"),
    ecdsa_with_SHA256=pyasn1_univ.ObjectIdentifier("1.2.840.10045.4.3.2"),
    ecdsa_with_SHA384=pyasn1_univ.ObjectIdentifier("1.2.840.10045.4.3.3"),
    ecdsa_with_SHA512=pyasn1_univ.ObjectIdentifier("1.2.840.10045.4.3.4"),
)

# FIXME: incomplete?
JAR_HASHERS_OID = {
    # OID                  algo      hasher  halgo
    RFC5480["id_sha224"]: ("SHA224", sha224, SHA224),
    RFC5480["id_sha256"]: ("SHA256", sha256, SHA256),
    RFC5480["id_sha384"]: ("SHA384", sha384, SHA384),
    RFC5480["id_sha512"]: ("SHA512", sha512, SHA512),
    RFC5480["id_md5"]: ("MD5", md5, MD5),       # NB: unsafe!
    RFC5480["id_sha1"]: ("SHA1", sha1, SHA1),   # NB: unsafe!
}
#                  algo  OID    hasher...
JAR_HASHERS_STR = {v[0]: (k,) + v[1:] for k, v in JAR_HASHERS_OID.items()}

# FIXME: MD5?
JAR_DIGEST_HEADER = r"(SHA(?:1|-?(?:224|256|384|512)))-Digest"
JAR_MANIFEST = "META-INF/MANIFEST.MF"
JAR_SBF_EXTS = ("RSA", "DSA", "EC")
JAR_META_EXTS = ("SF",) + JAR_SBF_EXTS + (JAR_MANIFEST.rsplit(".", 1)[-1],)

# FIXME
UNSAFE_HASH_ALGO = dict(
    SHA224=False, SHA256=False, SHA384=False, SHA512=False,
    MD5=True, SHA1=True
)

# FIXME
UNSAFE_KEY_SIZE: Dict[str, Callable[[int], bool]] = dict(
    RSA=lambda size: size < 1024,
    DSA=lambda size: size < 1024,
    EC=lambda size: size < 224,
)

assert set(JAR_HASHERS_STR) == set(UNSAFE_HASH_ALGO)
assert set(JAR_SBF_EXTS) == set(UNSAFE_KEY_SIZE)
assert set(JAR_SBF_EXTS) == set(x[0].upper() for x in HASHERS.values())

PRIVKEY_TYPE = {RSAPrivateKey: "RSA", DSAPrivateKey: "DSA", EllipticCurvePrivateKey: "EC"}
PUBKEY_TYPE = {RSAPublicKey: "RSA", DSAPublicKey: "DSA", EllipticCurvePublicKey: "EC"}

DIGEST_ENCRYPTION_ALGORITHM = dict(
    RSA=dict(
        _any=RFC5480["rsaEncryption"],          # 1.2.840.113549.1.1.1
        MD5=RFC5480["md5WithRSAEncryption"],    # 1.2.840.113549.1.1.4
        SHA1=RFC5480["sha1WithRSAEncryption"],  # 1.2.840.113549.1.1.5
        SHA224=pyasn1_univ.ObjectIdentifier("1.2.840.113549.1.1.14"),
        SHA256=pyasn1_univ.ObjectIdentifier("1.2.840.113549.1.1.11"),
        SHA384=pyasn1_univ.ObjectIdentifier("1.2.840.113549.1.1.12"),
        SHA512=pyasn1_univ.ObjectIdentifier("1.2.840.113549.1.1.13"),
    ),
    DSA=dict(
        _any=RFC5480["id_dsa"],                 # 1.2.840.10040.4.1
        SHA1=RFC5480["id_dsa_with_sha1"],       # 1.2.840.10040.4.3
        SHA224=RFC5480["id_dsa_with_sha224"],   # 2.16.840.1.101.3.4.3.1
        SHA256=RFC5480["id_dsa_with_sha256"],   # 2.16.840.1.101.3.4.3.2
        SHA384=pyasn1_univ.ObjectIdentifier("2.16.840.1.101.3.4.3.3"),
        SHA512=pyasn1_univ.ObjectIdentifier("2.16.840.1.101.3.4.3.4"),
    ),
    EC=dict(
        _any=RFC5480["id_ecPublicKey"],         # 1.2.840.10045.2.1
        SHA1=RFC5480["ecdsa_with_SHA1"],        # 1.2.840.10045.4.1
        SHA224=RFC5480["ecdsa_with_SHA224"],    # 1.2.840.10045.4.3.1
        SHA256=RFC5480["ecdsa_with_SHA256"],    # 1.2.840.10045.4.3.2
        SHA384=RFC5480["ecdsa_with_SHA384"],    # 1.2.840.10045.4.3.3
        SHA512=RFC5480["ecdsa_with_SHA512"],    # 1.2.840.10045.4.3.4
    ),
)

WRAP_COLUMNS = 80   # overridden in main() if $APKSIGTOOL_WRAP_COLUMNS is set


class APKSigToolError(Exception):
    """Base class for errors."""


class ParseError(APKSigToolError):
    """Parse failure."""


class VerificationError(APKSigToolError):
    """Verification failure."""


class SigningError(APKSigToolError):
    """Signing failure."""


class RollbackError(APKSigToolError):
    """Other signature versions required by X-Android-APK-Signed."""


class PasswordError(APKSigToolError):
    """Password error (e.g. incorrect or missing)."""


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

    @property
    def pair_id(self) -> int:
        """Pair ID for this block type (either .__class__.PAIR_ID or custom)."""
        if hasattr(self.__class__, "PAIR_ID"):
            return cast(int, self.__class__.PAIR_ID)
        raise NotImplementedError("no .PAIR_ID or custom .pair_id")

    def dump(self) -> bytes:
        """Dump Block (either .raw_data or custom)."""
        if hasattr(self, "raw_data"):
            return cast(bytes, self.raw_data)
        raise NotImplementedError("no .raw_data or custom .dump()")


@dataclass(frozen=True)
class Pair(APKSigToolBase):
    """ID-value pair."""
    length: int
    id: int
    value: Block

    @classmethod
    def from_block(cls, block: Block, *, length: Optional[int] = None) -> Pair:
        """Create a Pair from a Block using .pair_id (and .dump() if length is None)."""
        if length is None:
            length = len(block.dump()) + 4
        return cls(length, block.pair_id, block)

    def dump(self) -> bytes:
        """
        Dump Pair.

        Uses dump_pair().
        """
        return dump_pair(self)


@dataclass(frozen=True)
class Digest(APKSigToolBase):
    """APK Signature Scheme v2/v3 Block -> signer -> signed data -> digest."""
    signature_algorithm_id: int
    digest: bytes
    algoritm_id_info: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "algoritm_id_info", aid_info(self.signature_algorithm_id))

    @classmethod
    def parse(_cls, data: bytes) -> Tuple[Digest, ...]:
        """
        Parse APK Signature Scheme v2/v3 Block -> signer -> signed data ->
        digests.

        NB: returns a tuple of Digest.

        Uses parse_digests().
        """
        return parse_digests(data)

    def dump(self) -> bytes:
        """
        Dump APK Signature Scheme v2/v3 Block -> signer -> signed data ->
        digests -> digest.

        Uses dump_digest().
        """
        return dump_digest(self)


@dataclass(frozen=True)
class Certificate(APKSigToolBase):
    """APK Signature Scheme v2/v3 Block -> signer -> signed data -> certificate."""
    raw_data: bytes
    _certificate: Any = field(init=False, repr=False, compare=False)    # Any=X509Cert
    _public_key: Any = field(init=False, repr=False, compare=False)     # Any=X509CertPubKeyInfo
    certificate_info: CertificateInfo = field(init=False)
    public_key_info: PublicKeyInfo = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_certificate", X509Cert.load(self.raw_data))
        object.__setattr__(self, "_public_key", self.certificate.public_key)
        object.__setattr__(self, "certificate_info", x509_certificate_info(self.certificate))
        object.__setattr__(self, "public_key_info", public_key_info(self.public_key))

    @property   # type: ignore[no-any-unimported]
    def certificate(self) -> X509Cert:
        return self._certificate

    @property   # type: ignore[no-any-unimported]
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

    def dump(self) -> bytes:
        """
        Dump APK Signature Scheme v2/v3 Block -> signer -> signed data ->
        certificates -> certificate.

        Uses dump_certificate().
        """
        return dump_certificate(self)


@dataclass(frozen=True)
class SigningLineageNode:
    """Signing lineage node."""
    signed_data: bytes
    certificate: Certificate
    parent_signature_algorithm_id: int
    flags: Flags
    signature: Signature

    class Flags(Flag):
        PAST_CERT_INSTALLED_DATA = 1
        PAST_CERT_SHARED_USER_ID = 2
        PAST_CERT_PERMISSION = 4
        PAST_CERT_ROLLBACK = 8
        PAST_CERT_AUTH = 16

        def __str__(self) -> str:
            return "|".join(cast(str, f.name) for f in self)


@dataclass(frozen=True)
class SigningLineage:
    """Signing lineage."""
    version: int
    nodes: Tuple[SigningLineageNode, ...]

    def verify(self) -> None:
        """Verify signing lineage."""
        verify_signing_lineage(self)


@dataclass(frozen=True)
class AdditionalAttribute(APKSigToolBase):
    """APK Signature Scheme v2/v3 Block -> signer -> signed data -> additional attribute."""
    id: int
    value: bytes
    struct: Optional[SigningLineage]

    @property
    def is_stripping_protection(self) -> bool:
        """Whether .id is STRIPPING_PROTECTION_ATTR_ID."""
        return self.id == STRIPPING_PROTECTION_ATTR_ID

    @property
    def is_proof_of_rotation(self) -> bool:
        """Whether .id is PROOF_OF_ROTATION_ATTR_ID."""
        return self.id == PROOF_OF_ROTATION_ATTR_ID

    @property
    def is_rotation_min_sdk_version(self) -> bool:
        """Whether .id is ROTATION_MIN_SDK_VERSION_ATTR_ID."""
        return self.id == ROTATION_MIN_SDK_VERSION_ATTR_ID

    @property
    def is_rotation_on_dev_release(self) -> bool:
        """Whether .id is ROTATION_ON_DEV_RELEASE_ATTR_ID."""
        return self.id == ROTATION_ON_DEV_RELEASE_ATTR_ID

    @property
    def signing_lineage(self) -> SigningLineage:
        """Get signing lineage from proof-of-rotation struct (if .struct matches)."""
        if not isinstance(self.struct, SigningLineage):
            raise TypeError("Not a SigningLineage.")
        return self.struct

    def for_json(self) -> Mapping[str, Any]:
        """Convert to JSON."""
        x = dict(is_stripping_protection=self.is_stripping_protection,
                 is_proof_of_rotation=self.is_proof_of_rotation,
                 is_rotation_min_sdk_version=self.is_rotation_min_sdk_version,
                 is_rotation_on_dev_release=self.is_rotation_on_dev_release)
        return {**super().for_json(), **{k: v for k, v in x.items() if v}}

    @classmethod
    def parse(_cls, data: bytes) -> Tuple[AdditionalAttribute, ...]:
        """
        Parse APK Signature Scheme v2/v3 Block -> signer -> signed data ->
        additional attributes.

        NB: returns a tuple of AdditionalAttribute.

        Uses parse_additional_attributes().
        """
        return parse_additional_attributes(data)

    def dump(self) -> bytes:
        """
        Dump APK Signature Scheme v2/v3 Block -> signer -> signed data ->
        additional attributes -> attribute.

        Uses dump_additional_attribute().
        """
        return dump_additional_attribute(self)


@dataclass(frozen=True)
class Signature(APKSigToolBase):
    """APK Signature Scheme v2/v3 Block -> signer -> signature."""
    signature_algorithm_id: int
    signature: bytes
    algoritm_id_info: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "algoritm_id_info", aid_info(self.signature_algorithm_id))

    @classmethod
    def parse(_cls, data: bytes) -> Tuple[Signature, ...]:
        """
        Parse APK Signature Scheme v2/v3 Block -> signer -> signatures.

        NB: returns a tuple of Signature

        Uses parse_signatures().
        """
        return parse_signatures(data)

    def dump(self) -> bytes:
        """
        Dump APK Signature Scheme v2/v3 Block -> signer -> signatures ->
        signature.

        Uses dump_signature().
        """
        return dump_signature(self)


@dataclass(frozen=True)
class PublicKey(APKSigToolBase):
    """APK Signature Scheme v2/v3 Block -> signer -> public key."""
    raw_data: bytes
    _public_key: Any = field(init=False, repr=False, compare=False)     # Any=X509CertPubKeyInfo
    public_key_info: PublicKeyInfo = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_public_key", X509CertPubKeyInfo.load(self.raw_data))
        object.__setattr__(self, "public_key_info", public_key_info(self.public_key))

    @property   # type: ignore[no-any-unimported]
    def public_key(self) -> X509CertPubKeyInfo:
        return self._public_key

    def dump(self) -> bytes:
        """Dump PublicKey (.raw_data)."""
        return self.raw_data


@dataclass(frozen=True)
class V2SignedData(APKSigToolBase):
    """APK Signature Scheme v2/v3 Block -> signer -> signed data (v2)."""
    raw_data: bytes
    digests: Tuple[Digest, ...]
    certificates: Tuple[Certificate, ...]
    additional_attributes: Tuple[AdditionalAttribute, ...]
    zero_padding_size: int = 0

    @classmethod
    def parse(_cls, data: bytes) -> V2SignedData:
        """
        Parse APK Signature Scheme v2 Block -> v2 signer -> signed data.

        Uses parse_signed_data(version=2).
        """
        signed_data = parse_signed_data(data, version=2)
        assert isinstance(signed_data, V2SignedData)
        return signed_data

    def dump(self, *, expect_raw_data: bool = True, verify_raw_data: bool = True) -> bytes:
        """
        Dump APK Signature Scheme v2 Block -> v2 signer -> signed data.

        Uses dump_signed_data().
        """
        return dump_signed_data(self, expect_raw_data=expect_raw_data,
                                verify_raw_data=verify_raw_data)


@dataclass(frozen=True)
class V3SignedData(APKSigToolBase):
    """APK Signature Scheme v2/v3 Block -> signer -> signed data (v3)."""
    raw_data: bytes
    digests: Tuple[Digest, ...]
    certificates: Tuple[Certificate, ...]
    min_sdk: int
    max_sdk: int
    additional_attributes: Tuple[AdditionalAttribute, ...]
    zero_padding_size: int = 0

    @classmethod
    def parse(_cls, data: bytes) -> V3SignedData:
        """
        Parse APK Signature Scheme v3 Block -> v3 signer -> signed data.

        Uses parse_signed_data(version=3).
        """
        signed_data = parse_signed_data(data, version=3)
        assert isinstance(signed_data, V3SignedData)
        return signed_data

    def dump(self, *, expect_raw_data: bool = True, verify_raw_data: bool = True) -> bytes:
        """
        Dump APK Signature Scheme v3 Block -> v3 signer -> signed data.

        Uses dump_signed_data().
        """
        return dump_signed_data(self, expect_raw_data=expect_raw_data,
                                verify_raw_data=verify_raw_data)


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

        Uses parse_signer(version=2).
        """
        signer = parse_signer(data, version=2)
        assert isinstance(signer, V2Signer)
        return signer

    def dump(self) -> bytes:
        """
        Dump APK Signature Scheme v2 Block -> v2 signer.

        Uses dump_signer().
        """
        return dump_signer(self)


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

        Uses parse_signer(version=3).
        """
        signer = parse_signer(data, version=3)
        assert isinstance(signer, V3Signer)
        return signer

    def dump(self) -> bytes:
        """
        Dump APK Signature Scheme v3 Block -> v3 signer.

        Uses dump_signer().
        """
        return dump_signer(self)


@dataclass(frozen=True)
class APKSigningBlock(APKSigToolBase):
    """APK Signing Block."""
    pairs: Tuple[Pair, ...]

    @classmethod
    def parse(_cls, data: bytes, apkfile: Optional[str] = None, *,
              allow_nonzero_verity: bool = False,
              allow_unsafe: Tuple[str, ...] = (),
              sdk: Optional[int] = None) -> APKSigningBlock:
        """
        Parse APK Signing Block.

        Uses parse_apk_signing_block().
        """
        return parse_apk_signing_block(
            data, apkfile=apkfile, allow_nonzero_verity=allow_nonzero_verity,
            allow_unsafe=allow_unsafe, sdk=sdk)

    def dump(self) -> bytes:
        """
        Dump APK Signing Block.

        Uses dump_apk_signing_block().
        """
        return dump_apk_signing_block(self)

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
    def verify_result(self, apkfile: str, *, allow_unsafe: Tuple[str, ...] = (),
                      sdk: Optional[int] = None) -> APKVerificationResult:
        """
        Verify APK file using the APK Signature Scheme v2/v3 Blocks found in
        this APKSigningBlock.

        WARNING: verification is considered EXPERIMENTAL and SHOULD NOT BE
        RELIED ON, please use apksigner instead.

        Returns APKVerificationResult.

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
        return APKVerificationResult(tuple(verified), tuple(failed))

    def clean(self, *, keep: Tuple[int, ...] = ()) -> APKSigningBlock:
        """
        Clean APK Signing Block.

        Uses clean_parsed_apk_signing_block().
        """
        return clean_parsed_apk_signing_block(self, keep=keep)


@dataclass(frozen=True)
class APKSignatureSchemeBlock(Block):
    """APK Signature Scheme v2/v3 Block."""
    version: SchemeVersion
    signers: Tuple[Union[V2Signer, V3Signer], ...]
    verified: Union[None, Literal[False], Tuple[Tuple[str, str], ...]] = None
    verification_error: Optional[str] = None

    def __post_init__(self) -> None:
        assert self.version in (2, 3, "3.1")
        if isinstance(self.verified, tuple):
            assert len(self.verified) >= 1
        else:
            assert self.verified in (None, False)
        assert (self.verification_error is not None) == (self.verified == False)    # noqa: E712
        if self.is_v2:
            assert all(isinstance(s, V2Signer) for s in self.signers)
        else:
            assert all(isinstance(s, V3Signer) for s in self.signers)

    @property
    def is_v2(self) -> bool:
        """Whether .version is 2."""
        return self.version == 2

    @property
    def is_v3(self) -> bool:
        """Whether .version is 3."""
        return self.version == 3

    @property
    def is_v31(self) -> bool:
        """Whether .version is '3.1'."""
        return self.version == "3.1"

    @property
    def pair_id(self) -> int:
        """
        Pair ID (APK_SIGNATURE_SCHEME_V2_BLOCK_ID for v2,
        APK_SIGNATURE_SCHEME_V3_BLOCK_ID for v3,
        APK_SIGNATURE_SCHEME_V31_BLOCK_ID for v3.1).
        """
        if self.is_v2:
            return APK_SIGNATURE_SCHEME_V2_BLOCK_ID
        if self.is_v3:
            return APK_SIGNATURE_SCHEME_V3_BLOCK_ID
        if self.is_v31:
            return APK_SIGNATURE_SCHEME_V31_BLOCK_ID
        assert False

    @classmethod
    def parse(_cls, version: SchemeVersion, data: bytes, apkfile: Optional[str] = None, *,
              allow_unsafe: Tuple[str, ...] = (),
              sdk: Optional[int] = None) -> APKSignatureSchemeBlock:
        """
        Parse APK Signature Scheme v2/v3 Block.

        Uses parse_apk_signature_scheme_block().
        """
        return parse_apk_signature_scheme_block(version, data, allow_unsafe=allow_unsafe,
                                                apkfile=apkfile, sdk=sdk)

    def dump(self) -> bytes:
        """
        Dump APK Signature Scheme v3/v3 Block.

        Uses dump_apk_signature_scheme_block().
        """
        return dump_apk_signature_scheme_block(self)

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
    size: int

    PAIR_ID: ClassVar[int] = VERITY_PADDING_BLOCK_ID

    def dump(self) -> bytes:
        """Dump VerityPaddingBlock (.size null bytes)."""
        return b"\x00" * self.size


@dataclass(frozen=True)
class NonZeroVerityPaddingBlock(Block):
    """Verity padding block (nonzero padding)."""
    raw_data: bytes

    PAIR_ID: ClassVar[int] = VERITY_PADDING_BLOCK_ID


@dataclass(frozen=True)
class DependencyInfoBlock(Block):
    """Google dependency info block (opaque, encrypted)."""
    raw_data: bytes

    PAIR_ID: ClassVar[int] = DEPENDENCY_INFO_BLOCK_ID


@dataclass(frozen=True)
class GooglePlayFrostingBlock(Block):
    """Google Play frosting block (opaque)."""
    raw_data: bytes

    PAIR_ID: ClassVar[int] = GOOGLE_PLAY_FROSTING_BLOCK_ID


@dataclass(frozen=True)
class SourceStampBlock(Block):
    """Google source stamp block (opaque)."""
    raw_data: bytes
    version: Literal[1, 2]

    @property
    def pair_id(self) -> int:
        """
        Pair ID (either SOURCE_STAMP_V1_BLOCK_ID for v1 or
        SOURCE_STAMP_V2_BLOCK_ID for v2).
        """
        return (SOURCE_STAMP_V1_BLOCK_ID if self.version == 1 else
                SOURCE_STAMP_V2_BLOCK_ID)


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

    def __post_init__(self) -> None:
        assert all(algo in JAR_HASHERS_STR for algo, _ in self.digests)

    def dump(self) -> bytes:
        """Dump JAREntry (.raw_data)."""
        if not self.raw_data:
            raise ValueError("JAREntry without .raw_data")
        return self.raw_data


@dataclass(frozen=True)
class JARManifestBase(APKSigToolBase):
    """Base class for JARManifest and JARSignatureFile."""
    raw_data: bytes
    entries: Tuple[JAREntry, ...]
    version: str
    created_by: Optional[str]
    _headers_len: int


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

    def dump(self) -> bytes:
        """
        Dump JAR manifest (MANIFEST.MF).

        Uses dump_apk_v1_manifest().
        """
        return dump_apk_v1_manifest(self)


@dataclass(frozen=True)
class JARSignatureFile(JARManifestBase):
    """JAR signature file (.SF)."""
    filename: str
    digests_manifest: Tuple[Tuple[str, str], ...]
    digests_manifest_main_attributes: Optional[Tuple[Tuple[str, str], ...]]
    x_android_apk_signed: Optional[Tuple[int, ...]]

    def __post_init__(self) -> None:
        assert all(algo in JAR_HASHERS_STR for algo, _ in self.digests_manifest)
        assert all(algo in JAR_HASHERS_STR for algo, _ in self.digests_manifest_main_attributes or ())

    @classmethod
    def parse(_cls, filename: str, data: bytes) -> JARSignatureFile:
        """
        Parse JAR signature file (.SF).

        Uses parse_apk_v1_signature_file().
        """
        return parse_apk_v1_signature_file(filename, data)

    def dump(self) -> bytes:
        """
        Dump JAR signature file (.SF).

        Uses dump_apk_v1_signature_file().
        """
        return dump_apk_v1_signature_file(self)


@dataclass(frozen=True)
class PKCS7AuthenticatedAttributes(APKSigToolBase):
    """PKCS #7 authenticatedAttributes."""
    raw_data: bytes
    message_digest: bytes


@dataclass(frozen=True)
class PKCS7SignerInfo(APKSigToolBase):
    """PKCS #7 signerInfo."""
    encrypted_digest: bytes
    digest_algorithm: Optional[str]
    authenticated_attributes: Optional[PKCS7AuthenticatedAttributes]


@dataclass(frozen=True)
class JARSignatureBlockFile(APKSigToolBase):
    """JAR signature block file (.RSA, .DSA, or .EC)."""
    raw_data: bytes
    filename: str
    _certificate: Any = field(init=False, repr=False, compare=False)    # Any=X509Cert
    _public_key: Any = field(init=False, repr=False, compare=False)     # Any=X509CertPubKeyInfo
    certificate_info: CertificateInfo = field(init=False)
    public_key_info: PublicKeyInfo = field(init=False)
    signer_infos: Tuple[PKCS7SignerInfo, ...] = field(init=False)

    def __post_init__(self) -> None:
        infos, cert = _load_apk_v1_signature_block_file_signer_infos_cert(self.raw_data)
        object.__setattr__(self, "_certificate", cert)
        object.__setattr__(self, "_public_key", self.certificate.public_key)
        object.__setattr__(self, "certificate_info", x509_certificate_info(self.certificate))
        object.__setattr__(self, "public_key_info", public_key_info(self.public_key))
        object.__setattr__(self, "signer_infos", infos)

    @property   # type: ignore[no-any-unimported]
    def certificate(self) -> X509Cert:
        return self._certificate

    @property   # type: ignore[no-any-unimported]
    def public_key(self) -> X509CertPubKeyInfo:
        return self._public_key

    def dump(self) -> bytes:
        """Dump JARSignatureBlockFile (.raw_data)."""
        return self.raw_data


@dataclass(frozen=True)
class JARSignature(APKSigToolBase):
    """v1 (JAR) signature."""
    manifest: JARManifest
    signature_files: Tuple[JARSignatureFile, ...]
    signature_block_files: Tuple[JARSignatureBlockFile, ...]
    verified: Union[None, Literal[False], Tuple[Tuple[str, str], ...]] = None
    verification_error: Optional[str] = None
    unverified_mf: Optional[Tuple[str, ...]] = None

    def __post_init__(self) -> None:
        assert [_fn_base(x) for x in self.signature_files] \
            == [_fn_base(x) for x in self.signature_block_files]
        if isinstance(self.verified, tuple):
            assert len(self.verified) >= 1
        else:
            assert self.verified in (None, False)
        assert (self.verification_error is not None) == (self.verified == False)    # noqa: E712
        assert (self.unverified_mf is not None) == (self.verified not in (None, False))

    @property
    def required_signature_versions(self) -> FrozenSet[int]:
        """Require signature versions (from X-Android-APK-Signed)."""
        return frozenset(v for sf in self.signature_files for v in sf.x_android_apk_signed or ())

    def for_json(self) -> Mapping[str, Any]:
        """Convert to JSON."""
        x = dict(required_signature_versions=tuple(sorted(self.required_signature_versions)))
        return {**super().for_json(), **x}

    @classmethod
    def parse(_cls, extracted_meta: ZipInfoDataPairs, apkfile: Optional[str] = None, *,
              allow_unsafe: Tuple[str, ...] = (), strict: bool = True) -> JARSignature:
        """
        Parse v1 signature metadata files from extract_meta().

        Uses parse_apk_v1_signature().
        """
        return parse_apk_v1_signature(extracted_meta, apkfile=apkfile,
                                      allow_unsafe=allow_unsafe, strict=strict)

    def dump(self) -> ZipInfoDataPairs:
        """
        Dump v1 signature metadata files.

        Uses dump_apk_v1_signature().
        """
        return dump_apk_v1_signature(self)

    # FIXME
    # WARNING: verification is considered EXPERIMENTAL
    def verify(self, apkfile: str, *, allow_unsafe: Tuple[str, ...] = (),
               strict: bool = True) -> JARVerificationSuccess:
        """
        Verify APK file using this v1 (JAR) signature.

        WARNING: verification is considered EXPERIMENTAL and SHOULD NOT BE
        RELIED ON, please use apksigner instead.

        Raises VerificationError on failure.

        Uses verify_apk_v1_signature().
        """
        return verify_apk_v1_signature(self, apkfile=apkfile, strict=strict,
                                       allow_unsafe=allow_unsafe)


@dataclass(frozen=True)
class JARVerificationResult(APKSigToolBase, abc.ABC):
    """JAR (v1) verification result."""

    @property
    @abc.abstractmethod
    def is_verified(self) -> bool:
        ...

    def for_json(self) -> Mapping[str, Any]:
        """Convert to JSON."""
        return {**super().for_json(), **dict(is_verified=self.is_verified)}


@dataclass(frozen=True)
class JARVerificationSuccess(JARVerificationResult):
    """
    JAR (v1) verification sucess.

    .verified_signers is a tuple of (cert_sha256_fingerprint,
    pubkey_sha256_fingerprint) pairs.

    .unverified_mf is a tuple of filenames in the ZIP but not in the manifest.
    """
    signature: JARSignature
    verified_signers: Tuple[Tuple[str, str], ...]
    unverified_mf: Tuple[str, ...]

    @property
    def is_verified(self) -> bool:
        """True."""
        return True


@dataclass(frozen=True)
class JARVerificationFailure(JARVerificationResult):
    """JAR (v1) verification failure."""
    error: str

    @property
    def is_verified(self) -> bool:
        """False."""
        return False


@dataclass(frozen=True)
class APKVerificationResult(APKSigToolBase):
    """
    APK (v2/v3) verification result.

    .verified is a tuple of (version, signers) of verification successes.

    .failed is a tuple of (version, exception) tuples of verification failures.
    """
    verified: Tuple[Tuple[Union[int, str], Tuple[Tuple[str, str], ...]], ...]
    failed: Tuple[Tuple[Union[int, str], Exception], ...]

    @property
    def is_verified(self) -> bool:
        """The APK is verified if .verified is not empty and .failed is."""
        return bool(self.verified and not self.failed)

    @property
    def is_v2_verified(self) -> bool:
        """Whether .is_verified w/ v2."""
        return self.is_verified and 2 in [v for v, _ in self.verified]

    @property
    def is_v3_verified(self) -> bool:
        """Whether .is_verified w/ v3."""
        return self.is_verified and 3 in [v for v, _ in self.verified]

    @property
    def is_v31_verified(self) -> bool:
        """Whether .is_verified w/ v3.1."""
        return self.is_verified and "3.1" in [v for v, _ in self.verified]

    @property
    def verified_signature_versions(self) -> FrozenSet[Union[int, str]]:
        """
        Verified signature versions (2, 3, and/or '3.1').

        NB: having verified signature versions doesn't mean .is_verified is True!
        """
        return frozenset(v for v, _ in self.verified)

    def for_json(self) -> Mapping[str, Any]:
        """Convert to JSON."""
        vsvs = versions_sorted(self.verified_signature_versions)
        x = dict(is_verified=self.is_verified, verified_signature_versions=vsvs)
        return {**super().for_json(), **x}


@dataclass(frozen=True)
class VerificationResult(APKSigToolBase):
    """Combined verification result."""
    error: Optional[str]
    jar_result: Optional[JARVerificationResult]
    apk_result: APKVerificationResult
    common_signers: Optional[Tuple[Tuple[str, str], ...]]

    @property
    def is_verified(self) -> bool:
        """Whether .error is None."""
        return self.error is None

    @property
    def is_v1_verified(self) -> bool:
        """Whether .is_verified w/ version 1."""
        return self.is_verified and self.jar_result is not None \
            and self.jar_result.is_verified

    @property
    def is_v2_verified(self) -> bool:
        """Whether .is_verified w/ version 2."""
        return self.is_verified and self.apk_result.is_v2_verified

    @property
    def is_v3_verified(self) -> bool:
        """Whether .is_verified w/ version 3."""
        return self.is_verified and self.apk_result.is_v3_verified

    @property
    def is_v31_verified(self) -> bool:
        """Whether .is_verified w/ version 3.1."""
        return self.is_verified and self.apk_result.is_v31_verified

    @property
    def verified_signature_versions(self) -> FrozenSet[Union[int, str]]:
        """
        Verified signature versions (1, 2, 3, and/or '3.1').

        NB: having verified signature versions doesn't mean .is_verified is True!
        """
        vsvs = self.apk_result.verified_signature_versions
        return frozenset([1]) | vsvs if self.is_v1_verified else vsvs

    def for_json(self) -> Mapping[str, Any]:
        """Convert to JSON."""
        vsvs = versions_sorted(self.verified_signature_versions)
        x = dict(is_verified=self.is_verified, verified_signature_versions=vsvs)
        return {**super().for_json(), **x}


def _assert(b: bool, what: Optional[str] = None) -> None:
    """
    assert that is not removed with optimization.

    >>> from apksigtool import _assert, AssertionFailed
    >>> _assert(1 == 1, "all good")
    >>> try:
    ...     _assert(1 == 2, "oops")
    ... except AssertionFailed as e:
    ...     print(e)
    Assertion failed: oops

    """
    if not b:
        raise AssertionFailed("Assertion failed" + (f": {what}" if what else ""))


# FIXME
def _err(*a: str) -> None:
    sys.stdout.flush()  # FIXME
    print(*a, file=sys.stderr)
    sys.stderr.flush()  # FIXME


def _fn_base(x: Any) -> str:
    return cast(str, x.filename.rsplit(".", 1)[0])


def parse_apk_signing_block(data: bytes, apkfile: Optional[str] = None, *,
                            allow_nonzero_verity: bool = False,
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
        data, allow_nonzero_verity=allow_nonzero_verity,
        allow_unsafe=allow_unsafe, apkfile=apkfile, sdk=sdk)))


# FIXME: check if sb_size % 4096 == 0? when?
# https://source.android.com/docs/security/features/apksigning/v2#apk-signing-block-format
def _parse_apk_signing_block(data: bytes, apkfile: Optional[str] = None, *,
                             allow_nonzero_verity: bool = False,
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
        elif pair_id == APK_SIGNATURE_SCHEME_V31_BLOCK_ID:
            value = parse_apk_signature_scheme_block(
                "3.1", pair_val, allow_unsafe=allow_unsafe, apkfile=apkfile, sdk=sdk)
        elif pair_id == VERITY_PADDING_BLOCK_ID:
            if all(b == 0 for b in pair_val):
                value = VerityPaddingBlock(len(pair_val))
            elif allow_nonzero_verity:
                value = NonZeroVerityPaddingBlock(pair_val)
            else:
                _assert(False, "verity zero padding")
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
def clean_apk_signing_block(data: bytes, *, keep: Tuple[int, ...] = (),
                            parse: bool = False) -> bytes:
    """
    Clean APK Signing Block: remove everything that's not an APK Signature
    Scheme v2/v3 Block or verity padding block (or has a pair_id in keep).

    Returns cleaned block (bytes).

    >>> import apksigtool as ast
    >>> apk = "test/apks/apks/v3-only-with-stamp.apk"
    >>> _, data = ast.extract_v2_sig(apk)
    >>> blk = ast.parse_apk_signing_block(data)
    >>> [hex(p.id) for p in blk.pairs]
    ['0xf05368c0', '0x6dff800d', '0x42726577']
    >>> blk.verify(apk)
    >>> data_cleaned = ast.clean_apk_signing_block(data)
    >>> blk_cleaned = ast.parse_apk_signing_block(data_cleaned)
    >>> [hex(p.id) for p in blk_cleaned.pairs]
    ['0xf05368c0', '0x42726577']
    >>> blk_cleaned.verify(apk)
    >>> data_cleaned == ast.clean_apk_signing_block(data, parse=True)
    True

    """
    if parse:
        return parse_apk_signing_block(data).clean(keep=keep).dump()
    else:
        return _clean_apk_signing_block(data, keep=keep)


# FIXME
def clean_parsed_apk_signing_block(block: APKSigningBlock, *,
                                   keep: Tuple[int, ...] = ()) -> APKSigningBlock:
    """Clean APKSigningBlock."""
    allow = (APK_SIGNATURE_SCHEME_V2_BLOCK_ID,
             APK_SIGNATURE_SCHEME_V3_BLOCK_ID,
             APK_SIGNATURE_SCHEME_V31_BLOCK_ID,
             VERITY_PADDING_BLOCK_ID) + keep
    pairs = tuple(p for p in block.pairs if p.id in allow)
    return dataclasses.replace(block, pairs=pairs)


# FIXME
def _clean_apk_signing_block(data: bytes, *, keep: Tuple[int, ...] = ()) -> bytes:
    """Clean APK Signing Block w/o parsing its contents."""
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
        elif pair_id == APK_SIGNATURE_SCHEME_V31_BLOCK_ID:
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


def dump_apk_signing_block(block: APKSigningBlock) -> bytes:
    """
    Dump APK Signing Block.

    >>> import apksigtool as ast
    >>> apk = "test/apks/apks/golden-aligned-v1v2v3-out.apk"
    >>> _, data = ast.extract_v2_sig(apk)
    >>> blk = ast.parse_apk_signing_block(data)
    >>> [hex(p.id) for p in blk.pairs]
    ['0x7109871a', '0xf05368c0', '0x42726577']
    >>> blk.dump() == data
    True

    >>> import dataclasses as dc, shutil, tempfile
    >>> v2_id = ast.APK_SIGNATURE_SCHEME_V2_BLOCK_ID
    >>> pairs_no_v2 = tuple(p for p in blk.pairs if not p.id == v2_id)
    >>> blk_no_v2 = dc.replace(blk, pairs=pairs_no_v2)
    >>> [hex(p.id) for p in blk_no_v2.pairs]
    ['0xf05368c0', '0x42726577']
    >>> blk_rev = dc.replace(blk, pairs=blk.pairs[::-1])
    >>> [hex(p.id) for p in blk_rev.pairs]
    ['0x42726577', '0xf05368c0', '0x7109871a']
    >>> with tempfile.TemporaryDirectory() as tmpdir:
    ...     out = os.path.join(tmpdir, "out.apk")
    ...     _ = shutil.copy(apk, out)
    ...     r1 = ast.verify_apk_and_check_signers(out, check_v1=True)
    ...     r1.is_verified, ast.versions_sorted(r1.verified_signature_versions)
    ...     ast.replace_apk_signing_block(out, blk_no_v2.dump())
    ...     r2 = ast.verify_apk_and_check_signers(out, check_v1=True)
    ...     r2.is_verified, r2.error, ast.versions_sorted(r2.verified_signature_versions)
    ...     r3 = ast.verify_apk_and_check_signers(out)
    ...     r3.is_verified
    ...     ast.replace_apk_signing_block(out, blk_rev.dump())
    ...     r4 = ast.verify_apk_and_check_signers(out, check_v1=True)
    ...     r4.is_verified, ast.versions_sorted(r4.verified_signature_versions)
    (True, (1, 2, 3))
    (False, 'Missing required v2 signature(s)', (3,))
    True
    (True, (1, 2, 3))

    """
    data = b"".join(map(dump_pair, block.pairs))
    size = int.to_bytes(len(data) + 24, 8, "little")
    return size + data + size + b"APK Sig Block 42"


def dump_pair(pair: Pair) -> bytes:
    """Dump Pair."""
    dump = pair.value.dump()
    _assert(pair.length == len(dump) + 4, "pair length")
    return struct.pack("<QL", pair.length, pair.id) + dump


def parse_apk_signature_scheme_block(
        version: SchemeVersion, data: bytes, apkfile: Optional[str] = None, *,
        allow_unsafe: Tuple[str, ...] = (),
        sdk: Optional[int] = None) -> APKSignatureSchemeBlock:
    """
    Parse APK Signature Scheme v2/v3 Block (and attempt to verify -- setting
    .verified to #signers or False instead of None -- if apkfile is not
    None).

    Returns APKSignatureSchemeBlock (with .version, .signers, .verified,
    .verification_error).
    """
    signers = tuple(_parse_apk_signature_scheme_block(data, version))
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


def _parse_apk_signature_scheme_block(
        data: bytes, version: SchemeVersion) -> Iterator[Union[V2Signer, V3Signer]]:
    """Yield V2Signer/V3Signer(s) for each parse_signer()."""
    seq_len, data = int.from_bytes(data[:4], "little"), data[4:]
    _assert(seq_len == len(data), "APK Signature Scheme Block size")
    while data:
        signer, data = _split_len_prefixed_field(data)
        yield parse_signer(signer, version=version)


def dump_apk_signature_scheme_block(block: APKSignatureSchemeBlock) -> bytes:
    """Dump APK Signature Scheme v2/v3 Block."""
    data = b"".join(_as_len_prefixed_field(dump_signer(s)) for s in block.signers)
    return int.to_bytes(len(data), 4, "little") + data


def parse_signer(data: bytes, version: SchemeVersion) -> Union[V2Signer, V3Signer]:
    """
    Parse APK Signature Scheme v2/v3 Block -> signer.

    Returns V2Signer/V3Signer (with .signed_data, .signatures, .public_key;
    V3Signer also .min_sdk, .max_sdk).
    """
    result: List[Any] = []
    sigdata, data = _split_len_prefixed_field(data)
    result.append(parse_signed_data(sigdata, version=version))
    if version != 2:
        minSDK, maxSDK = struct.unpack("<LL", data[:8])
        data = data[8:]
        result.append(minSDK)
        result.append(maxSDK)
    sigs, data = _split_len_prefixed_field(data)
    result.append(parse_signatures(sigs))
    pubkey, data = _split_len_prefixed_field(data)
    result.append(PublicKey(pubkey))
    _assert(not data, "signer extraneous data")
    return V2Signer(*result) if version == 2 else V3Signer(*result)


def dump_signer(signer: Union[V2Signer, V3Signer]) -> bytes:
    """Dump APK Signature Scheme v2/v3 Block -> signer."""
    sigdata = _as_len_prefixed_field(dump_signed_data(signer.signed_data))
    sigs = _dump_tuple(dump_signature, signer.signatures)
    pubkey = _as_len_prefixed_field(signer.public_key.raw_data)
    if isinstance(signer, V3Signer):
        minmax = struct.pack("<LL", signer.min_sdk, signer.max_sdk)
    else:
        minmax = b""
    return sigdata + minmax + sigs + pubkey


def parse_signed_data(
        data: bytes, version: SchemeVersion) -> Union[V2SignedData, V3SignedData]:
    """
    Parse APK Signature Scheme v2/v3 Block -> signer -> signed data.

    Returns V2SignedData/V3SignedData (with .raw_data, .digests, .certificates,
    .additional_attributes; V3SignedData also .min_sdk, .max_sdk).
    """
    result: List[Any] = [data]
    digests, data = _split_len_prefixed_field(data)
    result.append(parse_digests(digests))
    certs, data = _split_len_prefixed_field(data)
    result.append(parse_certificates(certs))
    if version != 2:
        minSDK, maxSDK = struct.unpack("<LL", data[:8])
        data = data[8:]
        result.append(minSDK)
        result.append(maxSDK)
    attrs, data = _split_len_prefixed_field(data)
    result.append(parse_additional_attributes(attrs))
    _assert(all(b == 0 for b in data), "signed data zero padding")
    result.append(len(data))
    return V2SignedData(*result) if version == 2 else V3SignedData(*result)


def dump_signed_data(signed_data: Union[V2SignedData, V3SignedData], *,
                     expect_raw_data: bool = True, verify_raw_data: bool = True) -> bytes:
    """
    Dump APK Signature Scheme v2/v3 Block -> signer -> signed data.

    >>> import apksigtool as ast, dataclasses as dc
    >>> apk = "test/apks/apks/golden-aligned-v1v2v3-out.apk"
    >>> blk = ast.parse_apk_signing_block(ast.extract_v2_sig(apk)[1])
    >>> sd1 = blk.pairs[0].value.signers[0].signed_data
    >>> sd2 = blk.pairs[1].value.signers[0].signed_data
    >>> sd1_nord = dc.replace(sd1, raw_data=b"")
    >>> sd2_nord = dc.replace(sd2, raw_data=b"")
    >>> sd1.dump() == sd1_nord.dump(expect_raw_data=False, verify_raw_data=False)
    True
    >>> sd2.dump() == sd2_nord.dump(expect_raw_data=False, verify_raw_data=False)
    True
    >>> sd1_nord.zero_padding_size, sd2_nord.zero_padding_size
    (4, 0)
    >>> ast.parse_signed_data(sd1.dump(), version=2) == sd1
    True
    >>> ast.parse_signed_data(sd2.dump(), version=3) == sd2
    True

    """
    _assert(not expect_raw_data or bool(signed_data.raw_data), "raw signed data expected")
    if not verify_raw_data and signed_data.raw_data:
        return signed_data.raw_data
    digests = _dump_tuple(dump_digest, signed_data.digests)
    certs = _dump_tuple(dump_certificate, signed_data.certificates)
    attrs = _dump_tuple(dump_additional_attribute, signed_data.additional_attributes)
    if isinstance(signed_data, V3SignedData):
        minmax = struct.pack("<LL", signed_data.min_sdk, signed_data.max_sdk)
    else:
        minmax = b""
    data = digests + certs + minmax + attrs + b"\x00" * signed_data.zero_padding_size
    _assert(not verify_raw_data or signed_data.raw_data == data, "raw signed data")
    return data


def parse_digests(data: bytes) -> Tuple[Digest, ...]:
    """
    Parse APK Signature Scheme v2/v3 Block -> signer -> signed data -> digests.

    Returns tuple of Digest (with .signature_algorithm_id, .digest).
    """
    return tuple(_parse_digests(data))


def _parse_digests(data: bytes) -> Iterator[Digest]:
    """Yield Digest(s)."""
    while data:
        digest, data = _split_len_prefixed_field(data)
        sig_algo_id = int.from_bytes(digest[:4], "little")
        _assert(int.from_bytes(digest[4:8], "little") == len(digest) - 8, "digest size")
        yield Digest(sig_algo_id, digest[8:])


def dump_digest(digest: Digest) -> bytes:
    """
    Dump APK Signature Scheme v2/v3 Block -> signer -> signed data -> digests ->
    digest.
    """
    sig_algo_id = int.to_bytes(digest.signature_algorithm_id, 4, "little")
    dig_len = int.to_bytes(len(digest.digest), 4, "little")
    return _as_len_prefixed_field(sig_algo_id + dig_len + digest.digest)


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
        cert, data = _split_len_prefixed_field(data)
        yield Certificate(cert)


def dump_certificate(certificate: Certificate) -> bytes:
    """
    Dump APK Signature Scheme v2/v3 Block -> signer -> signed data ->
    certificates -> certificate.
    """
    return _as_len_prefixed_field(certificate.raw_data)


def parse_additional_attributes(data: bytes) -> Tuple[AdditionalAttribute, ...]:
    """
    Parse APK Signature Scheme v2/v3 Block -> signer -> signed data ->
    additional attributes.

    Returns tuple of AdditionalAttribute (with .id, .value).
    """
    return tuple(_parse_additional_attributes(data))


# FIXME
def _parse_additional_attributes(data: bytes) -> Iterator[AdditionalAttribute]:
    """Yield AdditionalAttribute(s)."""
    while data:
        attr, data = _split_len_prefixed_field(data)
        attr_id, attr_data = int.from_bytes(attr[:4], "little"), attr[4:]
        if attr_id == PROOF_OF_ROTATION_ATTR_ID:
            attr_struct = parse_proof_of_rotation_attr(attr_data)
        else:
            attr_struct = None
        yield AdditionalAttribute(attr_id, attr_data, attr_struct)


def dump_additional_attribute(attribute: AdditionalAttribute) -> bytes:
    """
    Dump APK Signature Scheme v2/v3 Block -> signer -> signed data -> additional
    attributes -> attribute.
    """
    attr_id = int.to_bytes(attribute.id, 4, "little")
    return _as_len_prefixed_field(attr_id + attribute.value)


def parse_proof_of_rotation_attr(data: bytes) -> SigningLineage:
    """
    Parse APK Signature Scheme v2/v3 Block -> signer -> signed data ->
    additional attributes -> proof of rotation struct (signing lineage).

    Returns SigningLineage.
    """
    nodes: List[SigningLineageNode] = []
    version, data = int.from_bytes(data[:4], "little"), data[4:]
    _assert(version == PROOF_OF_ROTATION_VERSION, "lineage version")
    while data:
        lineage_data, data = _split_len_prefixed_field(data)
        nodes.append(_parse_lineage_node(lineage_data))
    return SigningLineage(version, tuple(nodes))


def _parse_lineage_node(data: bytes) -> SigningLineageNode:
    signed_data, data = _split_len_prefixed_field(data)
    flags, sig_algo_id = struct.unpack("<LL", data[:8])
    signature, data = _split_len_prefixed_field(data[8:])
    _assert(not data, "lineage node extraneous data")
    cert, psai_data = _split_len_prefixed_field(signed_data)
    parent_sig_algo_id = int.from_bytes(psai_data, "little")
    return SigningLineageNode(
        signed_data, Certificate(cert), parent_sig_algo_id,
        SigningLineageNode.Flags(flags), Signature(sig_algo_id, signature))


def parse_signatures(data: bytes) -> Tuple[Signature, ...]:
    """
    Parse APK Signature Scheme v2/v3 Block -> signer -> signatures.

    Returns tuple of Signature (with .signature_algorithm_id, .signature).
    """
    return tuple(_parse_signatures(data))


def _parse_signatures(data: bytes) -> Iterator[Signature]:
    """Yield Signature(s)."""
    while data:
        sig, data = _split_len_prefixed_field(data)
        sig_algo_id = int.from_bytes(sig[:4], "little")
        _assert(int.from_bytes(sig[4:8], "little") == len(sig) - 8, "signature size")
        yield Signature(sig_algo_id, sig[8:])


def dump_signature(signature: Signature) -> bytes:
    """Dump APK Signature Scheme v2/v3 Block -> signer -> signatures -> signature."""
    sig_algo_id = int.to_bytes(signature.signature_algorithm_id, 4, "little")
    sig_len = int.to_bytes(len(signature.signature), 4, "little")
    return _as_len_prefixed_field(sig_algo_id + sig_len + signature.signature)


def _split_len_prefixed_field(data: bytes) -> Tuple[bytes, bytes]:
    """
    Parse length-prefixed field (length is little-endian, uint32) at beginning
    of data.

    Returns (field data, remaining data).
    """
    _assert(len(data) >= 4, "prefixed field must be at least 4 bytes")
    field_len = int.from_bytes(data[:4], "little")
    _assert(len(data) >= 4 + field_len, "prefixed field size")
    return data[4:4 + field_len], data[4 + field_len:]


def _as_len_prefixed_field(data: bytes) -> bytes:
    """Create length-prefixed field (length is little-endian, uint32)."""
    return int.to_bytes(len(data), 4, "little") + data


def _dump_tuple(f: Callable[[T], bytes], xs: Tuple[T, ...],
                len_prefixed: bool = True) -> bytes:
    data = b"".join(map(f, xs))
    return _as_len_prefixed_field(data) if len_prefixed else data


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
        pubkey = serialization.load_der_public_key(pk.raw_data)
        assert isinstance(pubkey, PubKeyTypes)
        if (key_algo := pk_algo.upper()) not in allow_unsafe:
            if (f := UNSAFE_KEY_SIZE[key_algo]) is not None and f(pk.public_key.bit_size):
                raise VerificationError(f"Unsafe {key_algo} key size: {pk.public_key.bit_size}")
        for sig in signer.signatures:
            if sig.signature_algorithm_id not in HASHERS:
                raise VerificationError(f"Unknown signature algorithm ID: {hex(sig.signature_algorithm_id)}")
            algo, _, halgo, pad, _ = HASHERS[sig.signature_algorithm_id]
            if pk_algo != algo:
                raise VerificationError(f"Public key algorithm mismatch: expected {algo}, got {pk_algo}")
            verify_signature(pubkey, sig.signature, signer.signed_data.raw_data, halgo, pad)
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


def _apk_digest(apkfile: str, sb_offset: int, hasher: Any, chunk_type: int) -> bytes:
    """Calculate APK digest (either chunked or verity)."""
    if chunk_type == CHUNKED:
        return apk_digest_chunked(apkfile, sb_offset, hasher)
    elif chunk_type == VERITY:
        return apk_digest_verity(apkfile, sb_offset, hasher)
    else:
        raise ValueError(f"Unknown chunk type: {chunk_type}")


def apk_digest_chunked(apkfile: str, sb_offset: int, hasher: Any) -> bytes:
    """Calculate chunked digest for APK."""
    def f(size: int) -> None:
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


def apk_digest_verity(apkfile: str, sb_offset: int, hasher: Any) -> bytes:
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


def _chunk_digest(chunk: bytes, hasher: Any) -> bytes:
    data = b"\xa5" + int.to_bytes(len(chunk), 4, "little") + chunk
    return cast(bytes, hasher(data).digest())


def _top_level_chunked_digest(digests: List[bytes], hasher: Any) -> bytes:
    data = b"\x5a" + int.to_bytes(len(digests), 4, "little") + b"".join(digests)
    return cast(bytes, hasher(data).digest())


def _verity_block_digest(block: bytes, hasher: Any) -> bytes:
    _assert(len(block) == VERITY_BLOCK_SIZE, "verity block size")
    return cast(bytes, hasher(VERITY_SALT + block).digest())


def _top_level_verity_digest(digests: List[bytes], total_size: int, hasher: Any) -> bytes:
    data = _verity_pad(b"".join(digests))
    while len(data) > VERITY_BLOCK_SIZE:
        data = _verity_pad(b"".join(_verity_block_digest(c, hasher)
                                    for c in _chunks(data, VERITY_BLOCK_SIZE)))
    tot = int.to_bytes(total_size, 8, "little")
    return cast(bytes, hasher(VERITY_SALT + data).digest()) + tot


def _verity_pad(data: bytes) -> bytes:
    if len(data) % VERITY_BLOCK_SIZE != 0:
        data += b"\x00" * (VERITY_BLOCK_SIZE - (len(data) % VERITY_BLOCK_SIZE))
    return data


def _chunks(data: bytes, blocksize: int) -> Iterator[bytes]:
    """Yield chunks of blocksize from data."""
    while data:
        chunk, data = data[:blocksize], data[blocksize:]
        yield chunk


# FIXME: check & audit!
# WARNING: verification is considered EXPERIMENTAL
# https://source.android.com/docs/security/features/apksigning/v3#proof-of-rotation-and-self-trusted-old-certs-structs
def verify_signing_lineage(lineage: SigningLineage, *, allow_unsafe: Tuple[str, ...] = ()) -> None:
    """
    Verify SigningLineage.

    WARNING: verification is considered EXPERIMENTAL and SHOULD NOT BE RELIED
    ON, please use apksigner instead.

    Raises VerificationError on failure.
    """
    last, seen = None, set()
    for i, node in enumerate(lineage.nodes):
        if (fingerprint := node.certificate.certificate_info.fingerprint) in seen:
            raise VerificationError(f"Duplicate certificate: {fingerprint}")
        if last:
            if node.parent_signature_algorithm_id != last.signature.signature_algorithm_id:
                raise VerificationError("Signature algorithm IDs of parent and node are not identical")
            pk = last.certificate.public_key
            pubkey = serialization.load_der_public_key(pk.dump())
            if (key_algo := pk.algorithm.upper()) not in allow_unsafe:
                if (f := UNSAFE_KEY_SIZE[key_algo]) is not None and f(pk.bit_size):
                    raise VerificationError(f"Unsafe {key_algo} key size: {pk.bit_size}")
            if last.signature.signature_algorithm_id not in HASHERS:
                raise VerificationError(f"Unknown signature algorithm ID: {hex(last.signature.signature_algorithm_id)}")
            _, _, halgo, pad, _ = HASHERS[last.signature.signature_algorithm_id]
            verify_signature(pubkey, node.signature.signature, node.signed_data, halgo, pad)
        else:
            _assert(node.parent_signature_algorithm_id == 0, "zero first parent signature algorithm ID")
            _assert(not node.signature.signature, "empty first signature")
        if i == len(lineage.nodes) - 1:
            _assert(node.signature.signature_algorithm_id == 0, "zero last signature algorithm ID")
        seen.add(fingerprint)
        last = node


# https://docs.oracle.com/javase/8/docs/technotes/guides/jar/jar.html
def parse_apk_v1_signature(extracted_meta: ZipInfoDataPairs, apkfile: Optional[str] = None,
                           *, allow_unsafe: Tuple[str, ...] = (),
                           strict: bool = True) -> JARSignature:
    """Parse v1 signature metadata files from extract_meta()."""
    manifest = None
    sig_files = {}
    sig_block_files = {}
    for info, data in extracted_meta:
        if not apksigcopier.is_meta(info.filename):
            raise ParseError(f"Not a v1 signature file: {info.filename!r}")
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
            raise ParseError(f"Unexpected metadata file: {info.filename!r}")
    if manifest is None:
        raise ParseError("Missing manifest")
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
        verification_error = unverified_mf = None
        try:
            result = sig.verify(apkfile, allow_unsafe=allow_unsafe, strict=strict)
            verified = result.verified_signers
            unverified_mf = result.unverified_mf
        except VerificationError as e:
            verified, verification_error = False, str(e)
        return dataclasses.replace(
            sig, verified=verified, verification_error=verification_error,
            unverified_mf=unverified_mf)
    return sig


def dump_apk_v1_signature(signature: JARSignature) -> ZipInfoDataPairs:
    """
    Dump v1 signature metadata files.

    NB: does not set correct ZipInfo metadata.

    >>> import apksigtool as ast, dataclasses as dc
    >>> noraw = lambda x: dc.replace(x, raw_data=b"")
    >>> noraw_ents = lambda x, es: dc.replace(x, raw_data=b"", entries=es)
    >>> apk = "test/apks/apks/golden-aligned-v1v2v3-out.apk"
    >>> meta = ast.extract_meta(apk)
    >>> [x.filename for x, _ in meta]
    ['META-INF/RSA-2048.SF', 'META-INF/RSA-2048.RSA', 'META-INF/MANIFEST.MF']
    >>> sig = ast.parse_apk_v1_signature(meta)
    >>> mf = noraw_ents(sig.manifest, tuple(map(noraw, sig.manifest.entries)))
    >>> sf = noraw_ents(sig.signature_files[0], tuple(map(noraw, sig.signature_files[0].entries)))
    >>> sbf = sig.signature_block_files[0]
    >>> meta_dump = ast.JARSignature(mf, (sf,), (sbf,)).dump()
    >>> [x.filename for x, _ in meta_dump]
    ['META-INF/RSA-2048.SF', 'META-INF/RSA-2048.RSA', 'META-INF/MANIFEST.MF']
    >>> [(x.filename, y) for x, y in meta] == [(x.filename, y) for x, y in meta_dump]
    True

    """
    meta = []
    for sf, sbf in zip(signature.signature_files, signature.signature_block_files):
        meta += [(sf.filename, sf.dump()), (sbf.filename, sbf.raw_data)]
    meta.append(("META-INF/MANIFEST.MF", signature.manifest.dump()))
    return tuple((zipfile.ZipInfo(fn), data) for fn, data in meta)


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
                       created_by=created_by, built_by=built_by, _headers_len=headers_len)


def dump_apk_v1_manifest(manifest: JARManifest) -> bytes:
    """Dump JAR manifest (MANIFEST.MF)."""
    return _dump_apk_v1_manifest(manifest)


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
        x_android_apk_signed=x_android_apk_signed, filename=filename, _headers_len=headers_len)


def dump_apk_v1_signature_file(sf: JARSignatureFile) -> bytes:
    """Dump JAR signature file (.SF)."""
    return _dump_apk_v1_manifest(sf)


def _digests_from_dict(ent: Dict[str, str], suffix: str = "") -> Iterator[Tuple[str, str]]:
    for k, v in ent.items():
        if m := re.fullmatch(JAR_DIGEST_HEADER + suffix, k):
            try:
                base64.b64decode(v, validate=True)
            except binascii.Error:
                _assert(False, "digest must be valid base64")
            yield m[1].replace("-", ""), v


# FIXME
def _parse_apk_v1_manifest(
        data: bytes) -> Tuple[Dict[str, str], int, Tuple[Tuple[Dict[str, str], bytes], ...]]:
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
def _dump_apk_v1_manifest(manifest: Union[JARManifest, JARSignatureFile], *,
                          headers: Optional[Tuple[Tuple[str, str], ...]] = None,
                          endl: str = "\r\n", wrap: int = 70) -> bytes:
    """
    Dump JAR manifest (MANIFEST.MF) or signature file (.SF).

    >>> import apksigtool as ast, dataclasses as dc
    >>> noraw = lambda x: dc.replace(x, raw_data=b"")
    >>> noraw_ents = lambda x, es: dc.replace(x, raw_data=b"", entries=es)
    >>> apk = "test/apks/apks/golden-aligned-v1v2v3-out.apk"
    >>> sig = ast.parse_apk_v1_signature(ast.extract_meta(apk))
    >>> mf_ents = tuple(map(noraw, sig.manifest.entries))
    >>> mf_dump = noraw_ents(sig.manifest, mf_ents).dump()
    >>> mf_dump == sig.manifest.raw_data
    True
    >>> sf_ents = tuple(map(noraw, sig.signature_files[0].entries))
    >>> sf_dump = noraw_ents(sig.signature_files[0], sf_ents).dump()
    >>> sf_dump == sig.signature_files[0].raw_data
    True

    """
    if manifest.raw_data:
        return manifest.raw_data
    if headers is None:
        hs = []
        if isinstance(manifest, JARManifest):
            hs.append(("Manifest-Version", manifest.version))
            if manifest.built_by:
                hs.append(("Built-By", manifest.built_by))
            if manifest.created_by:
                hs.append(("Created-By", manifest.created_by))
        elif isinstance(manifest, JARSignatureFile):
            hs.append(("Signature-Version", manifest.version))
            if manifest.created_by:
                hs.append(("Created-By", manifest.created_by))
            for algo, digest in manifest.digests_manifest:
                hs.append(_mf_hdr_dig(algo, digest, "-Manifest"))
            if manifest.digests_manifest_main_attributes:
                for algo, digest in manifest.digests_manifest_main_attributes:
                    hs.append(_mf_hdr_dig(algo, digest, "-Manifest-Main-Attributes"))
            if manifest.x_android_apk_signed:
                xaas = ", ".join(map(str, manifest.x_android_apk_signed))
                hs.append(("X-Android-APK-Signed", xaas))
        headers = tuple(hs)
    raw_ents = b"".join(_dump_jar_entry(e, endl, wrap) for e in manifest.entries)
    return _mf_hdrs_join(headers, endl, wrap).encode() + raw_ents


def _dump_jar_entry(entry: JAREntry, endl: str = "\r\n", wrap: int = 70) -> bytes:
    if entry.raw_data:
        return entry.raw_data
    hs = [("Name", entry.filename)]
    for algo, digest in entry.digests:
        hs.append(_mf_hdr_dig(algo, digest))
    return _mf_hdrs_join(tuple(hs), endl, wrap).encode()


# FIXME: MD5?
def _mf_hdr_dig(algo: str, digest: str, suffix: str = "") -> Tuple[str, str]:
    a = algo if algo == "SHA1" else algo[:3] + "-" + algo[3:]   # FIXME
    return f"{a}-Digest{suffix}", digest


def _mf_hdrs_join(hs: Tuple[Tuple[str, str], ...], endl: str, wrap: int) -> str:
    return "".join(_mf_hdr_wrap(f"{k}: {v}", endl, wrap) + endl for k, v in hs) + endl


def _mf_hdr_wrap(s: str, endl: str, wrap: int) -> str:
    w, t = wrap, ""
    while len(s) > w:
        t += s[:w] + endl + " "
        s = s[w:]
        w = wrap - 1    # account for the space
    return t + s


# FIXME
# FIXME: improve error messages
# FIXME: consider at least one good sinfo enough when not strict?
# WARNING: verification is considered EXPERIMENTAL
# https://docs.oracle.com/javase/tutorial/deployment/jar/intro.html
# https://docs.oracle.com/javase/8/docs/technotes/guides/jar/jar.html#Signature_Validation
def verify_apk_v1_signature(signature: JARSignature, apkfile: str, *,
                            allow_unsafe: Tuple[str, ...] = (),
                            strict: bool = True) -> JARVerificationSuccess:
    """
    Verify v1 (JAR) signature.

    WARNING: verification is considered EXPERIMENTAL and SHOULD NOT BE RELIED
    ON, please use apksigner instead.

    Verifies more strictly than the spec when strict is True,

    Raises an error for unsafe hash algorithms (like SHA1) and key sizes (or
    skips those digests when appropriate and strict is False) when allow_unsafe
    is False.

    Raises VerificationError on failure.

    Returns JARVerificationSuccess.
    """
    verified = []
    manifest = {}
    for entry in signature.manifest.entries:
        if entry.filename in manifest:
            raise VerificationError(f"Duplicate manifest entry: {entry.filename!r}")
        manifest[entry.filename] = entry
    for sf, sbf in zip(signature.signature_files, signature.signature_block_files):
        if not sbf.signer_infos:
            raise VerificationError(f"No signer infos in {sbf.filename!r}")
        if (key_algo := sbf.public_key_info.algorithm) not in allow_unsafe:
            if (f := UNSAFE_KEY_SIZE[key_algo]) is not None and f(sbf.public_key.bit_size):
                raise VerificationError(f"Unsafe {key_algo} key size: {sbf.public_key.bit_size}")
        pad = PKCS1v15 if sbf.filename.endswith(".RSA") else None
        pubkey = serialization.load_der_public_key(sbf.public_key.dump())
        assert isinstance(pubkey, PubKeyTypes)
        for sinfo in sbf.signer_infos:
            def halgo_f() -> Halgo:
                return ECDSA(halgo()) if sbf.filename.endswith(".EC") else halgo()
            if (algo := sinfo.digest_algorithm) is None:
                raise VerificationError("Unknown hash algorithm")
            if algo not in allow_unsafe and UNSAFE_HASH_ALGO[algo]:
                raise VerificationError(f"Unsafe hash algorithm: {algo}")
            halgo = JAR_HASHERS_STR[algo][2]
            if sinfo.authenticated_attributes:
                message_digest = JAR_HASHERS_STR[algo][1](sf.raw_data).digest()
                if sinfo.authenticated_attributes.message_digest != message_digest:
                    raise VerificationError("Authenticated attributes digest mismatch")
                msg = sinfo.authenticated_attributes.raw_data
            else:
                msg = sf.raw_data
            verify_signature(pubkey, sinfo.encrypted_digest, msg, halgo_f, pad)
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
                    hdrs = signature.manifest.raw_data[:signature.manifest._headers_len]
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
            if set(manifest) - set(e.filename for e in sf.entries):
                raise VerificationError(f"Manifest entries missing from {sf.filename!r}")
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
    for filename in unverified_mf:
        if not (filename.endswith("/") or apksigcopier.is_meta(filename)):
            raise VerificationError(f"ZIP entry not in manifest: {filename!r}")
    if not verified:
        raise VerificationError("No signers")
    return JARVerificationSuccess(signature, tuple(verified), unverified_mf)


# FIXME
# https://www.rfc-editor.org/rfc/rfc2315
def _load_apk_v1_signature_block_file_signer_infos_cert(    # type: ignore[no-any-unimported]
        data: bytes) -> Tuple[Tuple[PKCS7SignerInfo, ...], X509Cert]:
    signer_infos = []
    try:
        cinf = pyasn1_decode(data, asn1Spec=rfc2315.ContentInfo())[0]
        _assert(cinf["contentType"] == rfc2315.signedData,
                "signature block file PKCS #7 contentType must be signedData")
        sdat = pyasn1_decode(cinf["content"], asn1Spec=rfc2315.SignedData())[0]
        for sinf in sdat["signerInfos"]:
            dalg = sinf["digestAlgorithm"]["algorithm"]
            attr = sinf["authenticatedAttributes"]
            edig = sinf["encryptedDigest"].asOctets()
            algo = JAR_HASHERS_OID.get(dalg, [None])[0]
            signer_infos.append(PKCS7SignerInfo(edig, algo, _parse_auth_attrs(attr)))
    except PyAsn1Error:
        raise ParseError("Failed to parse signature block file PKCS #7 data")   # pylint: disable=W0707
    certs = load_der_pkcs7_certificates(data)
    _assert(len(certs) == 1, "signature block file must contain exactly 1 certificate")
    return tuple(signer_infos), X509Cert.load(certs[0].public_bytes(serialization.Encoding.DER))


# FIXME
def _create_signature_block_file(sf: JARSignatureFile, *, cert: bytes, key: PrivKey,
                                 hash_algo: str) -> Tuple[bytes, str]:
    def halgo_f() -> Halgo:
        return ECDSA(halgo()) if alg == "EC" else halgo()
    alg, = [e for c, e in PRIVKEY_TYPE.items() if isinstance(key, c)]
    oid, _, halgo = JAR_HASHERS_STR[hash_algo]
    dea = DIGEST_ENCRYPTION_ALGORITHM[alg][hash_algo]
    pad = PKCS1v15 if alg == "RSA" else None
    crt = pyasn1_decode(cert, asn1Spec=rfc2315.Certificate())[0]
    sig = create_signature(key, sf.raw_data, halgo_f, pad)
    sdat = rfc2315.SignedData()
    sdat["version"] = 1
    sdat["digestAlgorithms"][0]["algorithm"] = oid
    sdat["contentInfo"] = rfc2315.ContentInfo()
    sdat["contentInfo"]["contentType"] = rfc2315.ContentType(rfc2315.data)
    sdat["certificates"][0]["certificate"] = crt
    sinf = sdat["signerInfos"][0]
    sinf["version"] = 1
    sinf["issuerAndSerialNumber"]["issuer"] = crt["tbsCertificate"]["issuer"]
    sinf["issuerAndSerialNumber"]["serialNumber"] = crt["tbsCertificate"]["serialNumber"]
    sinf["digestAlgorithm"]["algorithm"] = oid
    sinf["digestEncryptionAlgorithm"]["algorithm"] = dea
    sinf["encryptedDigest"] = sig
    cinf = rfc2315.ContentInfo()
    cinf["contentType"] = rfc2315.ContentType(rfc2315.signedData)
    cinf["content"] = pyasn1_univ.Any(pyasn1_encode(sdat))
    return pyasn1_encode(cinf), alg


def _parse_auth_attrs(  # type: ignore[no-any-unimported]
        attr: rfc2315.Attributes) -> Optional[PKCS7AuthenticatedAttributes]:
    if not len(attr):   # pylint: disable=C1802
        return None
    id_contentType = pyasn1_univ.ObjectIdentifier("1.2.840.113549.1.9.3")
    id_messageDigest = pyasn1_univ.ObjectIdentifier("1.2.840.113549.1.9.4")
    _assert(len(attr) >= 2, "PKCS #7 authenticatedAttributes must contain at least 2 attributes")
    ctypes = [a for a in attr if a["type"] == id_contentType]
    mdigests = [a for a in attr if a["type"] == id_messageDigest]
    _assert(len(ctypes) == 1, "PKCS #7 authenticatedAttributes must contain exactly 1 "
                              "PKCS #9 contentType attribute")
    _assert(len(mdigests) == 1, "PKCS #7 authenticatedAttributes must contain exactly 1 "
                                "PKCS #9 messageDigest attribute")
    _assert(len(ctypes[0]["values"]) == 1, "PKCS #9 contentType attribute must contain exactly 1 value")
    _assert(len(mdigests[0]["values"]) == 1, "PKCS #9 messageDigest attribute must contain exactly 1 value")
    ctype = pyasn1_decode(ctypes[0]["values"][0], asn1Spec=rfc2315.ContentType())[0]
    digest = pyasn1_decode(mdigests[0]["values"][0])[0].asOctets()
    _assert(ctype == rfc2315.data, "PKCS #9 contentType must be PKCS #7 data")
    data = pyasn1_univ.SetOf()
    data.extend(attr)
    return PKCS7AuthenticatedAttributes(pyasn1_encode(data), digest)


# FIXME: type checking?!
# WARNING: verification is considered EXPERIMENTAL
def verify_signature(key: PubKey, sig: bytes, msg: bytes, halgo: HalgoFun,
                     pad: Optional[PadFun]) -> None:
    """
    Verify signature (sig) from key on message (msg) using appropriate hashing
    algorithm and padding.

    WARNING: verification is considered EXPERIMENTAL and SHOULD NOT BE RELIED
    ON, please use apksigner instead.

    Raises VerificationError (as a result of InvalidSignature) on failure.
    """
    padding = pad() if pad is not None else None
    algorithm = halgo()
    try:
        if isinstance(key, RSAPublicKey):
            assert padding is not None
            assert isinstance(algorithm, HashAlgorithm)
            key.verify(sig, msg, padding, algorithm)
        elif isinstance(key, DSAPublicKey):
            assert isinstance(algorithm, HashAlgorithm)
            key.verify(sig, msg, algorithm)
        else:
            assert isinstance(algorithm, ECDSA)
            key.verify(sig, msg, algorithm)
    except InvalidSignature:
        raise VerificationError("Invalid signature")    # pylint: disable=W0707


# FIXME: type checking?!
# WARNING: signing is considered EXPERIMENTAL
def create_signature(key: PrivKey, msg: bytes, halgo: HalgoFun,
                     pad: Optional[PadFun]) -> bytes:
    """
    Create signature from key on message (msg) using appropriate hashing
    algorithm and padding.

    WARNING: signing is considered EXPERIMENTAL and SHOULD NOT BE RELIED ON,
    please use apksigner instead.
    """
    padding = pad() if pad is not None else None
    algorithm = halgo()
    if isinstance(key, RSAPrivateKey):
        assert padding is not None
        assert isinstance(algorithm, HashAlgorithm)
        return key.sign(msg, padding, algorithm)
    elif isinstance(key, DSAPrivateKey):
        assert isinstance(algorithm, HashAlgorithm)
        return key.sign(msg, algorithm)
    else:
        assert isinstance(algorithm, ECDSA)
        return key.sign(msg, algorithm)


def x509_certificate_info(cert: X509Cert) -> CertificateInfo:   # type: ignore[no-any-unimported]
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


def public_key_info(key: X509CertPubKeyInfo) -> PublicKeyInfo:  # type: ignore[no-any-unimported]
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
            p("  SIZE:", pair.value.size)
        elif isinstance(pair.value, NonZeroVerityPaddingBlock):
            p("  NONZERO VERITY PADDING BLOCK")
            p("  SIZE:", len(pair.value.raw_data))
        elif isinstance(pair.value, DependencyInfoBlock):
            p("  DEPENDENCY INFO BLOCK")
        elif isinstance(pair.value, GooglePlayFrostingBlock):
            p("  GOOGLE PLAY FROSTING BLOCK")
        elif isinstance(pair.value, SourceStampBlock):
            p(f"  SOURCE STAMP v{pair.value.version} BLOCK")
        else:
            p("  UNKNOWN BLOCK")
        if verbose and hasattr(pair.value, "raw_data"):
            _show_hex(pair.value.raw_data, 2, file=file, wrap=wrap)


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
        if not block.is_v2:
            assert isinstance(signer, V3Signer)
            p("      MIN SDK:", signer.signed_data.min_sdk)
            p("      MAX SDK:", signer.signed_data.max_sdk)
        for j, attr in enumerate(signer.signed_data.additional_attributes):
            p("      ADDITIONAL ATTRIBUTE", j)
            p("        ADDITIONAL ATTRIBUTE ID:", hex(attr.id))
            if attr.is_stripping_protection:
                p("        STRIPPING PROTECTION ATTR")
            elif attr.is_proof_of_rotation:
                p("        PROOF OF ROTATION ATTR")
                p("        VERSION:", attr.signing_lineage.version)
                for k, node in enumerate(attr.signing_lineage.nodes):
                    p("        NODE", k)
                    p("          SIGNED DATA")
                    p("            CERTIFICATE")
                    cert = node.certificate
                    cert_info, pk_info = cert.certificate_info, cert.public_key_info
                    show_x509_certificate_info(cert_info, pk_info, 14, file=file, verbose=verbose, wrap=wrap)
                    _show_aid(node, 12, file=file, verbose=verbose, wrap=wrap)
                    p("          FLAGS:", node.flags)
                    _show_aid(node.signature, 10, file=file, verbose=verbose, wrap=wrap)
                    _show_hex(node.signature.signature, 10, file=file, what="SIGNATURE", wrap=wrap)
                try:
                    attr.signing_lineage.verify()
                except VerificationError as e:
                    p(f"        NOT VERIFIED ({e})")
                else:
                    p("        VERIFIED")
                continue
            elif attr.is_rotation_min_sdk_version:
                p("        ROTATION MIN SDK VERSION ATTR")
            elif attr.is_rotation_on_dev_release:
                p("        ROTATION ON DEV RELEASE ATTR")
            _show_hex(attr.value, 8, file=file, wrap=wrap)
        if signer.signed_data.zero_padding_size:
            p("      ZERO PADDING SIZE:", signer.signed_data.zero_padding_size)
        if not block.is_v2:
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
    p(" " * indent + "X.509 SUBJECT:", repr(info.subject)[1:-1])
    if verbose:
        p(" " * indent + "X.509 ISSUER:", repr(info.issuer)[1:-1])
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
              what: str = "VALUE", wrap: bool = False) -> None:
    """Print hex value (w/ indent etc.) to file (stdout)."""
    out = " " * indent + f"{what} (HEX): " + hexlify(data).decode()
    print(_wrap(out, indent, wrap), file=file)


def _show_aid(x: Union[Digest, Signature, SigningLineageNode], indent: int, *,
              file: TextIO = sys.stdout, verbose: bool = False,
              wrap: bool = False) -> None:
    """Print signature algorithm ID (w/ indent etc.) to file (stdout)."""
    if isinstance(x, SigningLineageNode):
        aid, aid_s = x.parent_signature_algorithm_id, aid_info(x.parent_signature_algorithm_id)
    else:
        aid, aid_s = x.signature_algorithm_id, x.algoritm_id_info
    if not verbose:
        aid_s = aid_s.split(",")[0]
    out = " " * indent + f"SIGNATURE ALGORITHM ID: {hex(aid)} ({aid_s})"
    print(_wrap(out, indent, wrap), file=file)


def _printer(file: TextIO, wrap: bool) -> Callable[..., None]:
    def p(*a: Any) -> None:
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
            result = signature.verify(apkfile, allow_unsafe=allow_unsafe, strict=strict)
        except VerificationError as e:
            p(f"NOT VERIFIED ({e})")
        else:
            p(f"VERIFIED ({len(result.verified_signers)} signer(s))")
            if verbose and result.unverified_mf:
                p("UNVERIFIED FILES (IN ZIP, NOT IN MANIFEST)")
                for filename in result.unverified_mf:
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
    for i, sinfo in enumerate(sbf.signer_infos):
        p("  SIGNER INFO", i)
        _show_hex(sinfo.encrypted_digest, 4, file=file, what="ENCRYPTED DIGEST", wrap=wrap)
        p("    DIGEST ALGORITHM:", sinfo.digest_algorithm or "UNKNOWN")
        if sinfo.authenticated_attributes:
            _show_hex(sinfo.authenticated_attributes.raw_data, 4, file=file,
                      what="AUTHENTICATED ATTRIBUTES", wrap=wrap)


def show_json(obj: APKSigToolBase, *, file: TextIO = sys.stdout) -> None:
    """Print parse tree as JSON to file (stdout)."""
    import simplejson   # FIXME: casting None to str because of wrong type stub
    simplejson.dump(obj, file, indent=2, sort_keys=True, encoding=cast(str, None),
                    default=json_dump_default, for_json=True)
    print(file=file)


def json_dump_default(obj: Any) -> str:
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


def asdict(obj: APKSigToolBase) -> Dict[str, Any]:
    """dataclasses.asdict() with a dict_factory that skips attributes that start with _."""
    def dict_factory(pairs: Iterable[Tuple[str, Any]]) -> Dict[str, Any]:
        return dict((k, v) for k, v in pairs if not k.startswith("_"))
    return dataclasses.asdict(obj, dict_factory=dict_factory)


def versions_sorted(xs: Iterable[Union[int, str]]) -> Tuple[Union[int, str], ...]:
    """
    Sorted as numbers.

    >>> from apksigtool import versions_sorted
    >>> versions_sorted((3, 10, '4.2', 2, '2.0', '3.9', '3.10', '3.1'))
    (2, '2.0', 3, '3.1', '3.9', '3.10', '4.2', 10)

    """
    return tuple(sorted(xs, key=lambda x: [int(n) for n in str(x).split(".")]))


def extract_v2_sig(apkfile: str) -> Tuple[int, bytes]:
    """
    Extract APK Signing Block and offset from APK.

    When successful, returns (sb_offset, sig_block); otherwise raises
    apksigcopier.NoAPKSigningBlock.

    Uses apksigcopier.extract_v2_sig().
    """
    extracted_v2_sig = apksigcopier.extract_v2_sig(apkfile)
    assert extracted_v2_sig is not None
    return extracted_v2_sig


def extract_meta(signed_apk: str) -> Tuple[Tuple[zipfile.ZipInfo, bytes], ...]:
    """
    Extract v1 signature metadata files from signed APK.

    Returns a tuple of (ZipInfo, data) pairs.

    Uses apksigcopier.extract_meta().
    """
    return tuple(apksigcopier.extract_meta(signed_apk))


def extract_v1_certs(   # type: ignore[no-any-unimported]
        extracted_meta: ZipInfoDataPairs) -> Tuple[Tuple[Union[int, str], X509Cert], ...]:
    """Extract certificate(s) from v1 signature metadata files."""
    return tuple(_extract_v1_certs(extracted_meta))


def _extract_v1_certs(  # type: ignore[no-any-unimported]
        extracted_meta: ZipInfoDataPairs) -> Iterator[Tuple[Union[int, str], X509Cert]]:
    e_meta = tuple(extracted_meta)
    if not e_meta or [i.filename for i, _ in e_meta] == [JAR_MANIFEST]:
        return
    for sbf in JARSignature.parse(e_meta).signature_block_files:
        yield 1, sbf.certificate


def extract_v2_certs(   # type: ignore[no-any-unimported]
        sig_block: bytes) -> Tuple[Tuple[Union[int, str], X509Cert], ...]:
    """Extract v2/v3 certificate(s) from APK Signing Block."""
    return tuple(_extract_v2_certs(sig_block))


def _extract_v2_certs(  # type: ignore[no-any-unimported]
        sig_block: bytes) -> Iterator[Tuple[Union[int, str], X509Cert]]:
    for pair in APKSigningBlock.parse(sig_block).pairs:
        if isinstance(pair.value, APKSignatureSchemeBlock):
            for signer in pair.value.signers:
                for cert in signer.signed_data.certificates:
                    yield pair.value.version, cert.certificate


def load_extracted_meta_from_dir(path: str) -> Tuple[Tuple[zipfile.ZipInfo, bytes], ...]:
    """
    Loads previously extracted v1 metadata files from a directory.

    Returns a tuple of (ZipInfo, data) pairs.
    """
    return tuple(_load_extracted_meta_from_dir(path))


def _load_extracted_meta_from_dir(path: str) -> Iterator[Tuple[zipfile.ZipInfo, bytes]]:
    for ext in JAR_META_EXTS:
        for fn in sorted(glob.glob(os.path.join(path, "*." + ext))):
            info = zipfile.ZipInfo("META-INF/" + os.path.basename(fn))
            with open(fn, "rb") as fh:
                yield info, fh.read()


# FIXME
# FIXME: handle common signers properly
# FIXME: handle key rotation etc.
# WARNING: verification is considered EXPERIMENTAL
def verify_apk_and_check_signers(
        apkfile: str, *, allow_unsafe: Tuple[str, ...] = (), check_v1: bool = False,
        quiet: bool = True, sdk_version: Optional[int] = None,
        signed_by: Optional[Tuple[str, str]] = None,
        verbose: bool = False) -> VerificationResult:
    """
    Verify APK signatures and check whether signers match between v1/v2/v3.

    WARNING: verification is considered EXPERIMENTAL and SHOULD NOT BE RELIED
    ON, please use apksigner instead.

    Returns VerificationResult.
    """
    all_signers = []
    required_sig_versions: Set[Union[int, str]] = set()
    if check_v1:
        jar_result = _verify_v1(apkfile, allow_unsafe=allow_unsafe, expected=False, quiet=quiet)
        if jar_result and jar_result.is_verified:
            assert isinstance(jar_result, JARVerificationSuccess)
            all_signers.append(set(jar_result.verified_signers))
            required_sig_versions = set(jar_result.signature.required_signature_versions)
    else:
        jar_result = None
    apk_result = verify_apk(apkfile, allow_unsafe=allow_unsafe, sdk=sdk_version)
    for version, signers in apk_result.verified:
        required_sig_versions.discard(version)
        all_signers.append(set(signers))
        if not quiet:
            print(f"v{version} verified ({len(signers)} signer(s))")
    for version, e in apk_result.failed:
        if not quiet:
            _err(f"v{version} not verified ({e})")
    common_signers = reduce(lambda x, y: x & y, all_signers) if all_signers else set()
    result = (jar_result, apk_result, tuple(sorted(common_signers)) or None)
    if not apk_result.is_verified or (jar_result and not jar_result.is_verified):
        return VerificationResult("Not verified", *result)
    if required_sig_versions:
        if not quiet:
            for n in sorted(required_sig_versions):
                _err(f"v{n} signature(s) not found but required")
        vsns = ", ".join(f"v{n}" for n in sorted(required_sig_versions))
        return VerificationResult(f"Missing required {vsns} signature(s)", *result)
    if not common_signers:
        if not quiet:
            _err("no common signers")
        return VerificationResult("No common signers", *result)
    if signed_by:
        if signed_by[1]:
            signer_ok = signed_by in common_signers
        else:
            signer_ok = signed_by[0] in [c for c, _ in common_signers]
        if not signer_ok:
            if not quiet:
                _err("expected signer not in common signers")
            return VerificationResult("Expected signer not in common signers", *result)
    if verbose:
        for cert, pk in sorted(common_signers):
            print("common signer:")
            print(f"  {cert} (sha256 fingerprint of certificate)")
            print(f"  {pk} (sha256 fingerprint of public key)")
    return VerificationResult(None, *result)


# FIXME: warn about unverified files?
def _verify_v1(apk: str, *, allow_unsafe: Tuple[str, ...] = (),
               expected: bool = True, quiet: bool = True, strict: bool = True,
               signed_by: Optional[Tuple[str, str]] = None) -> Optional[JARVerificationResult]:
    res = verify_apk_v1(apk, allow_unsafe=allow_unsafe, expected=expected, strict=strict)
    if not res:
        if not quiet:
            _err("v1 signature(s) not found")
    elif res.is_verified:
        assert isinstance(res, JARVerificationSuccess)
        if not quiet:
            print(f"v1 verified ({len(res.verified_signers)} signer(s))")
        if signed_by:
            if signed_by[1]:
                signer_ok = signed_by in res.verified_signers
            else:
                signer_ok = signed_by[0] in [c for c, _ in res.verified_signers]
            if not signer_ok:
                if not quiet:
                    _err("expected signer not in signers")
                return JARVerificationFailure("Expected signer not in signers")
    else:
        assert isinstance(res, JARVerificationFailure)
        if not quiet:
            _err(f"v1 not verified ({res.error})")
    return res


# FIXME
# WARNING: verification is considered EXPERIMENTAL
def verify_apk(apkfile: str, sig_block: Optional[bytes] = None, *,
               allow_unsafe: Tuple[str, ...] = (),
               sdk: Optional[int] = None) -> APKVerificationResult:
    """
    Verify APK file using the APK Signature Scheme v2/v3 Blocks found parsing
    the APK Signing Block.

    WARNING: verification is considered EXPERIMENTAL and SHOULD NOT BE RELIED
    ON, please use apksigner instead.

    If sig_block is None, it will be extracted from the APK using
    extract_v2_sig().

    Returns APKVerificationResult.
    """
    if sig_block is None:
        _, sig_block = extract_v2_sig(apkfile)
    return APKSigningBlock.parse(sig_block).verify_result(
        apkfile, allow_unsafe=allow_unsafe, sdk=sdk)


# FIXME
# FIXME: rollback protections
# WARNING: verification is considered EXPERIMENTAL
def verify_apk_v1(apkfile: str, *, allow_unsafe: Tuple[str, ...] = (), expected: bool = True,
                  strict: bool = True) -> Optional[JARVerificationResult]:
    """
    Verify APK file using the v1 (JAR) signatures.

    WARNING: verification is considered EXPERIMENTAL and SHOULD NOT BE RELIED
    ON, please use apksigner instead.

    Returns None when no v1 signature was found and expected is False, otherwise
    JARVerificationSuccess on success and JARVerificationFailure on failure.
    """
    e_meta = extract_meta(apkfile)
    if not e_meta or [i.filename for i, _ in e_meta] == [JAR_MANIFEST]:
        if expected:
            return JARVerificationFailure("Missing v1 signature")
        return None
    sig = JARSignature.parse(e_meta)
    try:
        return sig.verify(apkfile, allow_unsafe=allow_unsafe, strict=strict)
    except VerificationError as err:
        return JARVerificationFailure(str(err))


# NB: modifies the APK file in place!
def clean_apk(apkfile: str, *, check: bool = False, keep: Tuple[int, ...] = (),
              sdk: Optional[int] = None) -> bool:
    """
    Clean APK file: remove everything that's not an APK Signature Scheme v2/v3
    Block or verity padding block (or has a pair_id in keep) from its APK
    Signing Block.

    NB: modifies the APK file in place!.

    Does not modify the APK file when the cleaned block is equal to the
    original.

    Raises VerificationError when check is True and verify_apk() has failures or
    no successes.

    Returns True when the APK was modified, False otherwise.
    """
    _, sig_block = old_v2_sig = extract_v2_sig(apkfile)
    if check:
        result = verify_apk(apkfile, sig_block, sdk=sdk)
        if not result.is_verified:
            raise VerificationError("Verification failed")
    sig_block_cleaned = clean_apk_signing_block(sig_block, keep=keep)
    if sig_block == sig_block_cleaned:
        return False
    replace_apk_signing_block(apkfile, sig_block_cleaned, old_v2_sig=old_v2_sig)
    return True


# NB: modifies the APK file in place!
def replace_apk_signing_block(apkfile: str, new_sig_block: bytes, *,
                              old_v2_sig: Optional[Tuple[int, bytes]] = None) -> None:
    """
    Replace APK Signing Block.

    NB: modifies the APK file in place!.
    """
    old_sb_offset, old_sig_block = old_v2_sig or extract_v2_sig(apkfile)
    data_out = apksigcopier.zip_data(apkfile)
    offset = len(new_sig_block) - len(old_sig_block)
    with open(apkfile, "r+b") as fh:
        fh.seek(old_sb_offset)
        fh.write(new_sig_block)
        fh.write(data_out.cd_and_eocd)
        fh.truncate()
        fh.seek(data_out.eocd_offset + offset + 16)
        fh.write(int.to_bytes(data_out.cd_offset + offset, 4, "little"))


# FIXME
# FIXME: sb_offset, verity padding
# WARNING: signing is considered EXPERIMENTAL
def sign_apk(unsigned_apk: str, output_apk: str, *, cert: bytes, key: PrivKey,
             v1: bool = True, v2: bool = True, v3: bool = True) -> None:
    """
    Sign APK using v1 (JAR) and/or v2/v3 (APK Signing Block) signature(s).

    WARNING: signing is considered EXPERIMENTAL and SHOULD NOT BE RELIED ON,
    please use apksigner instead.
    """
    date_time = apksigcopier.copy_apk(unsigned_apk, output_apk)
    if v1:
        xaas = tuple(n for n, b in ((2, v2), (3, v3)) if b) or None
        v1_sig = create_v1_signature(output_apk, cert=cert, key=key, x_android_apk_signed=xaas)
        apksigcopier.patch_meta(v1_sig, output_apk, date_time=date_time)
    if v2 or v3:
        sb_offset = apksigcopier.zip_data(output_apk).cd_offset     # FIXME
        pairs = []
        if v2:
            block = create_v2_signature(output_apk, cert=cert, key=key, sb_offset=sb_offset)
            pairs.append(Pair.from_block(block))
        if v3:
            block = create_v3_signature(output_apk, cert=cert, key=key, sb_offset=sb_offset)
            pairs.append(Pair.from_block(block))
        sig_block = APKSigningBlock(tuple(pairs)).dump()
        apksigcopier.patch_v2_sig((sb_offset, sig_block), output_apk)


# FIXME
def create_v1_signature(apkfile: str, *, cert: bytes, key: PrivKey,
                        hash_algo: Optional[str] = None,
                        x_android_apk_signed: Optional[Tuple[int, ...]] = None) -> ZipInfoDataPairs:
    """
    Create v1 (JAR) signature.

    WARNING: signing is considered EXPERIMENTAL and SHOULD NOT BE RELIED ON,
    please use apksigner instead.
    """
    alg, = [e for c, e in PRIVKEY_TYPE.items() if isinstance(key, c)]
    if hash_algo is None:
        hash_algo = HASH_ALGOS[alg][0]
    elif hash_algo not in HASH_ALGOS[alg]:
        raise ValueError(f"Unsupported hash algorithm for {alg}: {hash_algo}")
    hasher = JAR_HASHERS_STR[hash_algo][1]
    created_by = f"{NAME} v{__version__}"
    mf_entries = []
    sf_entries = []
    with zipfile.ZipFile(apkfile, "r") as zf:
        if len(set(zi.filename for zi in zf.infolist())) != len(zf.infolist()):
            raise SigningError("Duplicate ZIP entries")
        for info in sorted(zf.infolist(), key=lambda info: info.header_offset):
            if info.filename.endswith("/"):
                continue
            h = hasher()
            with zf.open(info.filename) as fh:
                while data := fh.read(4096):
                    h.update(data)
            file_digest = base64.b64encode(h.digest()).decode()
            mf_entry = JAREntry(raw_data=b"", filename=info.filename,
                                digests=((hash_algo, file_digest),))
            mf_entry = dataclasses.replace(mf_entry, raw_data=_dump_jar_entry(mf_entry))
            mf_entry_digest = base64.b64encode(hasher(mf_entry.raw_data).digest()).decode()
            mf_entries.append(mf_entry)
            sf_entry = JAREntry(raw_data=b"", filename=info.filename,
                                digests=((hash_algo, mf_entry_digest),))
            sf_entry = dataclasses.replace(sf_entry, raw_data=_dump_jar_entry(sf_entry))
            sf_entries.append(sf_entry)
    mf = JARManifest(raw_data=b"", entries=tuple(mf_entries), version="1.0",
                     created_by=created_by, built_by=None, _headers_len=0)
    mf = dataclasses.replace(mf, raw_data=mf.dump())
    mf_digest = base64.b64encode(hasher(mf.raw_data).digest()).decode()
    sf = JARSignatureFile(
        raw_data=b"", entries=tuple(sf_entries), version="1.0", created_by=created_by,
        digests_manifest=((hash_algo, mf_digest),), digests_manifest_main_attributes=None,
        x_android_apk_signed=x_android_apk_signed, filename="META-INF/CERT.SF", _headers_len=0)
    sf = dataclasses.replace(sf, raw_data=sf.dump())
    sbf_raw, sbf_ext = _create_signature_block_file(sf, cert=cert, key=key, hash_algo=hash_algo)
    sbf = JARSignatureBlockFile(raw_data=sbf_raw, filename=f"META-INF/CERT.{sbf_ext}")
    return JARSignature(mf, (sf,), (sbf,)).dump()


# FIXME
def create_v2_signature(apkfile: str, *, cert: bytes, key: PrivKey, sb_offset: int,
                        hash_algo: Optional[str] = None) -> APKSignatureSchemeBlock:
    """
    Create a v2 signature (APK Signature Scheme v2 Block).

    WARNING: signing is considered EXPERIMENTAL and SHOULD NOT BE RELIED ON,
    please use apksigner instead.
    """
    return _create_apk_signature_scheme_block(
        apkfile, cert=cert, key=key, sb_offset=sb_offset, hash_algo=hash_algo, v3=None)


# FIXME
def create_v3_signature(apkfile: str, *, cert: bytes, key: PrivKey, sb_offset: int,
                        hash_algo: Optional[str] = None, min_sdk: int = MIN_SDK,
                        max_sdk: int = MAX_SDK) -> APKSignatureSchemeBlock:
    """
    Create a v3 signature (APK Signature Scheme v3 Block).

    WARNING: signing is considered EXPERIMENTAL and SHOULD NOT BE RELIED ON,
    please use apksigner instead.
    """
    v3 = (min_sdk, max_sdk)
    return _create_apk_signature_scheme_block(
        apkfile, cert=cert, key=key, sb_offset=sb_offset, hash_algo=hash_algo, v3=v3)


# FIXME
def _create_apk_signature_scheme_block(apkfile: str, *, cert: bytes, key: PrivKey,
                                       sb_offset: int, hash_algo: Optional[str],
                                       v3: Optional[Tuple[int, int]]) -> APKSignatureSchemeBlock:
    alg, = [e for c, e in PRIVKEY_TYPE.items() if isinstance(key, c)]
    if hash_algo is None:
        hash_algo = HASH_ALGOS[alg][0]
    elif hash_algo not in HASH_ALGOS[alg]:
        raise ValueError(f"Unsupported hash algorithm for {alg}: {hash_algo}")
    aid = SIGNATURE_ALGORITHM[alg][hash_algo]
    _, hasher, halgo, pad, chunk_type = HASHERS[aid]
    digest = Digest(aid, _apk_digest(apkfile, sb_offset, hasher, chunk_type))
    certificate = Certificate(cert)
    signed_data: Union[V2SignedData, V3SignedData]
    if v3:
        signed_data = V3SignedData(b"", (digest,), (certificate,), *v3, ())
    else:
        signed_data = V2SignedData(b"", (digest,), (certificate,), ())
    signed_data_raw = signed_data.dump(expect_raw_data=False, verify_raw_data=False)
    signed_data = dataclasses.replace(signed_data, raw_data=signed_data_raw)
    signature = Signature(aid, create_signature(key, signed_data_raw, halgo, pad))
    public_key = PublicKey(X509Cert.load(cert).public_key.dump())
    signer: Union[V2Signer, V3Signer]
    if v3:
        signer = V3Signer(cast(V3SignedData, signed_data), *v3, (signature,), public_key)
    else:
        signer = V2Signer(cast(V2SignedData, signed_data), (signature,), public_key)
    return APKSignatureSchemeBlock(3 if v3 else 2, (signer,))


def do_parse(apk_or_block: str, *, allow_nonzero_verity: bool = False,
             block: bool = False, json: bool = False, no_verify: bool = False,
             sdk_version: Optional[int] = None, verbose: bool = False,
             wrap: bool = False) -> None:
    """
    Parse APK Signing Block (from the file apk_or_block, which is expected to be
    an extracted block when block=True, an APK otherwise) and output a parse
    tree (indented with spaces) or JSON (when json=True).
    """
    if block:
        apkfile = None
        with open(apk_or_block, "rb") as fh:
            sig_block = fh.read()
    else:
        apkfile = apk_or_block if not no_verify else None
        _, sig_block = extract_v2_sig(apk_or_block)
    if json:
        blk = APKSigningBlock.parse(sig_block, apkfile=apkfile, sdk=sdk_version,
                                    allow_nonzero_verity=allow_nonzero_verity)
        show_json(blk)
    else:
        blk = APKSigningBlock.parse(sig_block, allow_nonzero_verity=allow_nonzero_verity)
        show_parse_tree(blk, apkfile=apkfile, sdk=sdk_version, verbose=verbose, wrap=wrap)


def do_parse_v1(apk_or_dir: str, *, allow_unsafe: Tuple[str, ...] = (),
                json: bool = False, no_strict: bool = False,
                no_verify: bool = False, verbose: bool = False,
                wrap: bool = False) -> None:
    """
    Parse APK v1 (JAR) signatures (from the file/directory apk_or_dir: an APK or
    a directory with extracted metadata files) and output a parse tree (indented
    with spaces) or JSON (when json=True).
    """
    if os.path.isdir(apk_or_dir):
        apkfile = None
        e_meta = load_extracted_meta_from_dir(apk_or_dir)
    else:
        apkfile = apk_or_dir if not no_verify else None
        e_meta = extract_meta(apk_or_dir)
    if json:
        sig = JARSignature.parse(e_meta, allow_unsafe=allow_unsafe,
                                 apkfile=apkfile, strict=not no_strict)
        show_json(sig)
    else:
        sig = JARSignature.parse(e_meta)
        show_v1_signature(sig, allow_unsafe=allow_unsafe, apkfile=apkfile,
                          strict=not no_strict, verbose=verbose, wrap=wrap)


def do_extract_certs(apk_or_block_or_dir: str, output_dir: str, *, block: bool = False,
                     v1_only: apksigcopier.NoAutoYesBoolNone = apksigcopier.NO) -> None:
    """
    Extract X.509 certificates (in DER form) from apk_or_block_or_dir -- an APK,
    extracted APK Signing Block (when block=True), or extracted files in a
    directory -- to output_dir (as v1cert0.der, v2cert0.der, etc.)
    """
    v1_only = apksigcopier.noautoyes(v1_only)
    v1_certs = sig_block = None
    if block:
        with open(apk_or_block_or_dir, "rb") as fh:
            sig_block = fh.read()
    elif os.path.isdir(apk_or_block_or_dir):
        v1_certs = extract_v1_certs(load_extracted_meta_from_dir(apk_or_block_or_dir))
        if v1_only != apksigcopier.YES:
            sigblock_file = os.path.join(apk_or_block_or_dir, apksigcopier.SIGBLOCK)
            if os.path.exists(sigblock_file):
                with open(sigblock_file, "rb") as fh:
                    sig_block = fh.read()
            elif v1_only == apksigcopier.NO:
                raise ParseError("No APK Signing Block")
    else:
        v1_certs = extract_v1_certs(extract_meta(apk_or_block_or_dir))
        if v1_only != apksigcopier.YES:
            expected = v1_only == apksigcopier.NO
            v2_sig = apksigcopier.extract_v2_sig(apk_or_block_or_dir, expected=expected)
            if v2_sig is not None:
                _, sig_block = v2_sig
    v2_certs = extract_v2_certs(sig_block) if sig_block else None
    certs = (v1_certs or ()) + (v2_certs or ())
    if not certs:
        raise ParseError("No certificates")
    counters: Dict[Union[int, str], int] = {}
    for version, cert in certs:
        counters.setdefault(version, 0)
        name = f"v{version}cert{counters[version]}.der"
        counters[version] += 1
        with open(os.path.join(output_dir, name), "wb") as fh:
            fh.write(cert.dump())


# WARNING: verification is considered EXPERIMENTAL
def do_verify(apk: str, *, allow_unsafe: Tuple[str, ...] = (),
              check_v1: bool = False, quiet: bool = False,
              sdk_version: Optional[int] = None,
              signed_by: Optional[Tuple[str, str]] = None,
              verbose: bool = False) -> None:
    """
    Verify APK using the APK Signature Scheme v2/v3 Blocks in its APK Signing
    Block.

    WARNING: verification is considered EXPERIMENTAL and SHOULD NOT BE RELIED
    ON, please use apksigner instead.

    Raises VerificationError on failure.
    """
    _err("WARNING: verification is considered EXPERIMENTAL, please use apksigner instead.")
    if allow_unsafe:
        algs = ", ".join(sorted(set(allow_unsafe)))
        _err(f"WARNING: unsafe hash algorithms and/or key sizes allowed: {algs}.")
    res = verify_apk_and_check_signers(apk, allow_unsafe=allow_unsafe, check_v1=check_v1,
                                       quiet=quiet, sdk_version=sdk_version,
                                       signed_by=signed_by, verbose=verbose)
    if not res.is_verified:
        raise VerificationError("Verification failed")


# WARNING: verification is considered EXPERIMENTAL
def do_verify_v1(apk: str, *, allow_unsafe: Tuple[str, ...] = (),
                 no_strict: bool = False, quiet: bool = False,
                 rollback_is_error: bool = False,
                 signed_by: Optional[Tuple[str, str]] = None) -> None:
    """
    Verify APK v1 (JAR) signatures.

    WARNING: verification is considered EXPERIMENTAL and SHOULD NOT BE RELIED
    ON, please use apksigner instead.

    Raises VerificationError on failure.

    Raises RollbackError when other signature versions are required by
    X-Android-APK-Signed and rollback_is_error=True.
    """
    _err("WARNING: verification is considered EXPERIMENTAL, please use apksigner instead.")
    if allow_unsafe:
        algs = ", ".join(sorted(set(allow_unsafe)))
        _err(f"WARNING: unsafe hash algorithms and/or key sizes allowed: {algs}.")
    res = _verify_v1(apk, allow_unsafe=allow_unsafe, quiet=quiet,
                     strict=not no_strict, signed_by=signed_by)
    if not res or not res.is_verified:
        raise VerificationError("Verification failed")
    assert isinstance(res, JARVerificationSuccess)
    if required_sv := res.signature.required_signature_versions:
        what = "Error" if rollback_is_error else "Warning"
        vsns = ", ".join(f"v{n}" for n in sorted(required_sv))
        _err(f"{what}: rollback protections require {vsns} signature(s) as well.")
        if rollback_is_error:
            raise RollbackError(f"Requires {vsns} signature(s)")


def do_clean(apk_or_block: str, *, block: bool = False, check: bool = False,
             keep: Tuple[int, ...] = (), sdk_version: Optional[int] = None) -> None:
    """
    Clean the file apk_or_block (which is expected to be an extracted block when
    block=True, an APK otherwise): remove everything that's not an APK Signature
    Scheme v2/v3 Block or verity padding block (or has a pair_id in keep) from
    its APK Signing Block.

    NB: modifies the APK file in place!
    """
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
    print("cleaned" if cleaned else "nothing to clean")


# WARNING: signing is considered EXPERIMENTAL
def do_sign(unsigned_apk: str, output_apk: str, *, cert: str, key: str,
            no_v1: bool = False, no_v2: bool = False, no_v3: bool = False,
            password: Optional[str] = None) -> None:
    """
    Sign unsigned_apk using v1 (JAR) and/or v2/v3 (APK Signing Block)
    signature(s) -- using cert as the certificate file and key as the private
    key file (encrypted with password if not None) -- and save as output_apk.

    WARNING: signing is considered EXPERIMENTAL and SHOULD NOT BE RELIED ON,
    please use apksigner instead.
    """
    _err("WARNING: signing is considered EXPERIMENTAL, please use apksigner instead.")
    with open(cert, "rb") as fh:
        cert_bytes = fh.read()
    with open(key, "rb") as fh:
        key_bytes = fh.read()
    try:
        passwd = password.encode() if password else None
        privkey = serialization.load_der_private_key(key_bytes, passwd)
    except (TypeError, ValueError) as e:
        raise PasswordError(e.args[0]) if "password" in e.args[0].lower() else e
    if not isinstance(privkey, PrivKeyTypes):
        raise SigningError(f"Unsupported private key type: {privkey.__class__.__name__}")
    sign_apk(unsigned_apk, output_apk, cert=cert_bytes, key=privkey,
             v1=not no_v1, v2=not no_v2, v3=not no_v3)


def main() -> None:
    """CLI; requires click."""

    global WRAP_COLUMNS
    if (columns := os.environ.get("APKSIGTOOL_WRAP_COLUMNS", "")).isdigit():
        WRAP_COLUMNS = int(columns)

    import click

    NAY = click.Choice(apksigcopier.NOAUTOYES)
    unsafe = tuple(UNSAFE_HASH_ALGO.items()) + tuple(UNSAFE_KEY_SIZE.items())
    UNSAFE = click.Choice(tuple(k for k, v in unsafe if v))

    @click.group(help="""
        apksigtool - parse/verify/clean/sign android apk (signing block)
    """)
    @click.version_option(__version__)
    def cli() -> None:
        pass

    @cli.command(help="""
        Parse APK Signing Block (from APK or extracted block) and output a parse
        tree (indented with spaces) or JSON.
    """)
    @click.option("--allow-nonzero-verity", is_flag=True,
                  help="Allow verity padding that is not all zeroes.")
    @click.option("--block", is_flag=True,
                  help="APK_OR_BLOCK is an extracted block, not an APK.")
    @click.option("--json", is_flag=True, help="JSON output.")
    @click.option("--no-verify", is_flag=True, help="Don't try verifying APK.")
    @click.option("--sdk-version", type=click.INT, help="For v3 signers specifying min/max SDK.")
    @click.option("-v", "--verbose", is_flag=True, help="Be verbose (no-op w/ --json).")
    @click.option("--wrap", is_flag=True, help="Wrap output (no-op w/ --json).")
    @click.argument("apk_or_block", type=click.Path(exists=True, dir_okay=False))
    def parse(*args: Any, **kwargs: Any) -> None:
        do_parse(*args, **kwargs)

    @cli.command(help="""
        Parse APK v1 (JAR) signatures (from APK or extracted files in a
        directory) and output a parse tree (indented with spaces) or JSON.
    """)
    @click.option("--allow-unsafe", multiple=True, default=(), type=UNSAFE,
                  help="Allow specified unsafe hash algorithm(s) (e.g. SHA1) or "
                       "key sizes for specified encryption(s) (e.g. RSA).")
    @click.option("--json", is_flag=True, help="JSON output.")
    @click.option("--no-strict", is_flag=True, help="Don't be stricter than the spec.")
    @click.option("--no-verify", is_flag=True, help="Don't try verifying APK.")
    @click.option("-v", "--verbose", is_flag=True, help="Be verbose (no-op w/ --json).")
    @click.option("--wrap", is_flag=True, help="Wrap output (no-op w/ --json).")
    @click.argument("apk_or_dir", type=click.Path(exists=True, dir_okay=True))
    def parse_v1(*args: Any, **kwargs: Any) -> None:
        do_parse_v1(*args, **kwargs)

    @cli.command(help="""
        Extract X.509 certificates (in DER form) from APK, extracted APK Signing
        Block, or extracted files in a directory.
    """)
    @click.option("--block", is_flag=True,
                  help="APK_OR_BLOCK_OR_DIR is an extracted block, not an APK or directory.")
    @click.option("--v1-only", type=NAY, default=apksigcopier.NO, show_default=True,
                  help="Expect only a v1 signature.")
    @click.argument("apk_or_block_or_dir", type=click.Path(exists=True, dir_okay=True))
    @click.argument("output_dir", type=click.Path(exists=True, file_okay=False))
    def extract_certs(*args: Any, **kwargs: Any) -> None:
        do_extract_certs(*args, **kwargs)

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
    @click.option("--signed-by", metavar="CERT:PUBKEY",
                  help="Assure the APK is signed by the specified signer: "
                       "certificate and public key sha256 fingerprint (hex).")
    @click.option("-v", "--verbose", is_flag=True, help="Show signer(s).")
    @click.argument("apk", type=click.Path(exists=True, dir_okay=False))
    @click.pass_context
    def verify(ctx: click.Context, /, *args: Any, **kwargs: Any) -> None:
        if kwargs["signed_by"]:
            kwargs["signed_by"] = _parse_signed_by(kwargs["signed_by"], ctx, verify)
        try:
            do_verify(*args, **kwargs)
        except VerificationError:
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
    @click.option("--signed-by", metavar="CERT:PUBKEY",
                  help="Assure the APK is signed by the specified signer: "
                       "certificate and public key sha256 fingerprint (hex).")
    @click.argument("apk", type=click.Path(exists=True, dir_okay=False))
    @click.pass_context
    def verify_v1(ctx: click.Context, /, *args: Any, **kwargs: Any) -> None:
        if kwargs["signed_by"]:
            kwargs["signed_by"] = _parse_signed_by(kwargs["signed_by"], ctx, verify_v1)
        try:
            do_verify_v1(*args, **kwargs)
        except VerificationError:
            sys.exit(4)
        except RollbackError:
            sys.exit(5)

    def _parse_signed_by(signed_by: str, ctx: click.Context,
                         cmd: click.Command) -> Tuple[str, str]:
        try:
            cert, fpr = signed_by.split(":")
            return cert, fpr
        except ValueError as e:
            p, = [x for x in cmd.params if x.name == "signed_by"]
            raise click.exceptions.BadParameter(e.args[0], ctx, p)

    @cli.command(help="""
        Clean APK (or extracted block): remove everything that's not an APK
        Signature Scheme v2/v3 Block or verity padding block (or has a pair_id
        in keep) from its APK Signing Block.

        NB: modifies the APK file in place!
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
    def clean(ctx: click.Context, /, *args: Any, **kwargs: Any) -> None:
        try:
            kwargs["keep"] = tuple(int(x, 16) for p in kwargs["keep"] for x in p.split(","))
        except ValueError as e:
            p, = [x for x in clean.params if x.name == "keep"]
            raise click.exceptions.BadParameter(e.args[0], ctx, p)
        do_clean(*args, **kwargs)

    # FIXME
    # FIXME: --verbose, --min-sdk, --max-sdk, PEM, keystore, ...
    # FIXME: rotation, multiple signers
    @cli.command(help="""
        Sign APK using v1 (JAR) and/or v2/v3 (APK Signing Block) signature(s).

        WARNING: signing is considered EXPERIMENTAL and SHOULD NOT BE RELIED ON,
        please use apksigner instead.
    """)
    @click.option("--cert", "--certificate", metavar="CERT", required=True,
                  type=click.Path(exists=True, dir_okay=False), help="Certificate (DER).")
    @click.option("--key", "--private-key", metavar="PRIVKEY", required=True,
                  type=click.Path(exists=True, dir_okay=False), help="Private key (DER).")
    @click.option("--no-v1", is_flag=True, help="Don't add a v1 signature.")
    @click.option("--no-v2", is_flag=True, help="Don't add a v2 signature.")
    @click.option("--no-v3", is_flag=True, help="Don't add a v3 signature.")
    @click.option("--prompt", "--password-prompt", is_flag=True,
                  help="Private key is encrypted; prompt for password.")
    @click.argument("unsigned_apk", type=click.Path(exists=True, dir_okay=False))
    @click.argument("output_apk", type=click.Path(dir_okay=False))
    def sign(*args: Any, prompt: bool, **kwargs: Any) -> None:
        if kwargs["no_v1"] and kwargs["no_v2"] and kwargs["no_v3"]:
            raise click.exceptions.BadParameter("all versions (v1, v2, and v3) excluded")
        if prompt:
            password = click.prompt("Password", hide_input=True)
        else:
            password = os.environ.get("APKSIGTOOL_PRIVKEY_PASSWORD")
        do_sign(*args, **kwargs, password=password or None)

    try:
        cli(prog_name=NAME)
    except (APKSigToolError, APKSigCopierError, zipfile.BadZipFile) as e:
        _err(f"Error: {e}.")
        sys.exit(3)


if __name__ == "__main__":
    main()

# vim: set tw=80 sw=4 sts=4 et fdm=marker :
