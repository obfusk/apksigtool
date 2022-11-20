<!-- {{{1

    File        : README.md
    Maintainer  : FC Stegerman <flx@obfusk.net>
    Date        : 2022-11-20

    Copyright   : Copyright (C) 2022  FC Stegerman
    Version     : v0.1.0
    License     : AGPLv3+

}}}1 -->

[![GitHub Release](https://img.shields.io/github/release/obfusk/apksigtool.svg?logo=github)](https://github.com/obfusk/apksigtool/releases)
[![PyPI Version](https://img.shields.io/pypi/v/apksigtool.svg)](https://pypi.python.org/pypi/apksigtool)
[![Python Versions](https://img.shields.io/pypi/pyversions/apksigtool.svg)](https://pypi.python.org/pypi/apksigtool)
[![CI](https://github.com/obfusk/apksigtool/workflows/CI/badge.svg)](https://github.com/obfusk/apksigtool/actions?query=workflow%3ACI)
[![AGPLv3+](https://img.shields.io/badge/license-AGPLv3+-blue.svg)](https://www.gnu.org/licenses/agpl-3.0.html)

<!-- FIXME
<a href="https://repology.org/project/apksigtool/versions">
  <img src="https://repology.org/badge/vertical-allrepos/apksigtool.svg?header="
    alt="Packaging status" align="right" />
</a>

<a href="https://repology.org/project/python:apksigtool/versions">
  <img src="https://repology.org/badge/vertical-allrepos/python:apksigtool.svg?header="
    alt="Packaging status" align="right" />
</a>
-->

# apksigtool

## parse/verify/clean android apk signing blocks & apks

`apksigtool` is a tool for parsing [android APK Signing
Blocks](https://source.android.com/docs/security/features/apksigning/v2#apk-signing-block)
(either embedded in an APK or extracted as a separate file, e.g. using
[`apksigcopier`](https://github.com/obfusk/apksigcopier)) and verifying [APK
signatures](https://source.android.com/docs/security/features/apksigning).  It
can also clean them (i.e. remove everything that's not an APK Signature Scheme
v2/v3 Block or verity padding block), which can be useful for [reproducible
builds](https://reproducible-builds.org).

**WARNING: verification and signing are considered EXPERIMENTAL and SHOULD NOT BE RELIED ON,
please use [`apksigner`](https://developer.android.com/studio/command-line/apksigner) instead.**

### Parse

Parse tree (some output elided):

```bash
$ apksigtool parse some.apk
PAIR ID: 0x7109871a
  APK SIGNATURE SCHEME v2 BLOCK
  SIGNER 0
    SIGNED DATA
      DIGEST 0
        SIGNATURE ALGORITHM ID: 0x104 (RSASSA-PKCS1-v1_5 with SHA2-512 digest)
  [...]
  VERIFIED (1 signer(s))
PAIR ID: 0xf05368c0
  APK SIGNATURE SCHEME v3 BLOCK
  SIGNER 0
    SIGNED DATA
      DIGEST 0
        SIGNATURE ALGORITHM ID: 0x104 (RSASSA-PKCS1-v1_5 with SHA2-512 digest)
  [...]
  VERIFIED (1 signer(s))
PAIR ID: 0x42726577
  VERITY PADDING BLOCK
```

Extracted `APKSigningBlock` instead of APK:

```bash
$ mkdir meta
$ apksigcopier extract some.apk meta
$ apksigtool parse --block meta/APKSigningBlock
[...]
```

v1 (JAR) signature (some output elided):

```bash
$ apksigtool parse-v1 some.apk
JAR MANIFEST
  VERSION: 1.0
  CREATED BY: Android Gradle 7.1.3
  BUILT BY: Signflinger
JAR SIGNATURE FILE
  FILENAME: META-INF/CERT.SF
  VERSION: 1.0
  CREATED BY: Android Gradle 7.1.3
  SHA256 MANIFEST DIGEST: [...]
  ANDROID APK SIGNED: 2
JAR SIGNATURE BLOCK FILE
  FILENAME: META-INF/CERT.RSA
  CERTIFICATE
    [...]
  SIGNATURE
    VALUE (HEX): [...]
  HASH ALGORITHM: SHA256
VERIFIED (1 signature(s))
```

#### JSON

NB: elided binary values (`digest`, `fingerprint`, `raw_data`, `signature`) are
represented as hex (e.g. `foo` would be represented as `666f6f`).

```bash
$ apksigtool parse --json some.apk
```

<!-- {{{1 -->
<details>
<summary>full JSON output (long, some data elided)</summary>

```json
{
  "_type": "APKSigningBlock",
  "pairs": [
    {
      "_type": "Pair",
      "id": 1896449818,
      "length": 1437,
      "value": {
        "_type": "APKSignatureSchemeBlock",
        "signers": [
          {
            "_type": "V2Signer",
            "public_key": {
              "_type": "PublicKey",
              "public_key_info": {
                "_type": "PublicKeyInfo",
                "algorithm": "RSA",
                "bit_size": 2048,
                "fingerprint": "[...]",
                "hash_algorithm": null
              },
              "raw_data": "[...]"
            },
            "signatures": [
              {
                "_type": "Signature",
                "algoritm_id_info": "RSASSA-PKCS1-v1_5 with SHA2-256 digest, content digested using SHA2-256 in 1 MB chunks",
                "signature": "[...]",
                "signature_algorithm_id": 259
              }
            ],
            "signed_data": {
              "_type": "V2SignedData",
              "additional_attributes": [
                {
                  "_type": "AdditionalAttribute",
                  "id": 3203395597,
                  "is_proof_of_rotation_struct": false,
                  "is_stripping_protection": true,
                  "value": "03000000"
                }
              ],
              "certificates": [
                {
                  "_type": "Certificate",
                  "certificate_info": {
                    "_type": "CertificateInfo",
                    "fingerprint": "[...]",
                    "hash_algorithm": "SHA256",
                    "issuer": "Common Name: [...], Organizational Unit: [...]",
                    "not_valid_after": "2022-10-27 12:34:56+00:00",
                    "not_valid_before": "2022-10-26 12:34:56+00:00",
                    "serial_number": 42,
                    "signature_algorithm": "RSASSA_PKCS1V15",
                    "subject": "Common Name: [...], Organizational Unit: [...]"
                  },
                  "public_key_info": {
                    "_type": "PublicKeyInfo",
                    "algorithm": "RSA",
                    "bit_size": 2048,
                    "fingerprint": "[...]",
                    "hash_algorithm": null
                  },
                  "raw_data": "[...]"
                }
              ],
              "digests": [
                {
                  "_type": "Digest",
                  "algoritm_id_info": "RSASSA-PKCS1-v1_5 with SHA2-256 digest, content digested using SHA2-256 in 1 MB chunks",
                  "digest": "[...]",
                  "signature_algorithm_id": 259
                }
              ],
              "raw_data": "[...]"
            }
          }
        ],
        "verification_error": null,
        "verified": 1,
        "version": 2
      }
    },
    {
      "_type": "Pair",
      "id": 4031998144,
      "length": 1437,
      "value": {
        "_type": "APKSignatureSchemeBlock",
        "signers": [
          {
            "_type": "V3Signer",
            "max_sdk": 2147483647,
            "min_sdk": 24,
            [...]
            "signed_data": {
              [...]
              "max_sdk": 2147483647,
              "min_sdk": 24,
              [...]
            }
          }
        ],
        "verification_error": null,
        "verified": 1,
        "version": 3
      }
    },
    {
      "_type": "Pair",
      "id": 1114793335,
      "length": 1166,
      "value": {
        "_type": "VerityPaddingBlock"
      }
    }
  ]
}
```

</details>
<!-- }}}1 -->

To extract e.g. pair types or IDs:

```bash
$ apksigtool parse --json some.apk | jq -r '.pairs[].value._type'
APKSignatureSchemeBlock
APKSignatureSchemeBlock
VerityPaddingBlock
$ apksigtool parse --json some.apk | jq -r '.pairs[].id' | awk '{printf "0x%x\n", $1}'
0x7109871a
0xf05368c0
0x42726577
```

To extract e.g. public key info:

```bash
$ apksigtool parse --json some.apk | jq '.pairs[].value.signers[]?.public_key.public_key_info'
```

```json
{
  "_type": "PublicKeyInfo",
  "algorithm": "RSA",
  "bit_size": 2048,
  "fingerprint": "[...]",
  "hash_algorithm": null
}
[...]
```

To extract e.g. certificate info:

```bash
$ apksigtool parse --json some.apk | jq '.pairs[].value.signers[]?.signed_data.certificates[].certificate_info'
```

```json
{
  "_type": "CertificateInfo",
  "fingerprint": "[...]",
  "hash_algorithm": "SHA256",
  "issuer": "Common Name: [...], Organizational Unit: [...]",
  "not_valid_after": "2022-10-27 12:34:56+00:00",
  "not_valid_before": "2022-10-26 12:34:56+00:00",
  "serial_number": 42,
  "signature_algorithm": "RSASSA_PKCS1V15",
  "subject": "Common Name: [...], Organizational Unit: [...]"
}
[...]
```

v1 (JAR) signature:

```bash
$ apksigtool parse-v1 --json some.apk | jq -r .manifest.created_by
Android Gradle 7.1.3
```

### Verify

**WARNING: verification is considered EXPERIMENTAL and SHOULD NOT BE RELIED ON, please use
[`apksigner`](https://developer.android.com/studio/command-line/apksigner) instead.**

```bash
$ apksigtool verify some.apk
WARNING: verification is considered EXPERIMENTAL, please use apksigner instead.
v2 verified (1 signer(s))
v3 verified (1 signer(s))
```

```bash
$ apksigtool verify-v1 some.apk
WARNING: verification is considered EXPERIMENTAL, please use apksigner instead.
v1 verified (1 signature(s))
Warning: rollback protections require v2, v3 signature(s) as well.
```

### Clean

NB: modifies in place!

```bash
$ cp some.apk cleaned.apk
$ apksigtool clean cleaned.apk
cleaned
$ apksigtool clean cleaned.apk
nothing to clean
```

Use `--check` to get errors when parsing or verification (when not
using `--block`) fails:

``` bash
$ cp some.apk cleaned.apk
$ apksigtool clean --check cleaned.apk
[...]
```

Extracted `APKSigningBlock` instead of APK:

```bash
$ mkdir meta
$ apksigcopier extract some.apk meta
$ apksigtool clean --block meta/APKSigningBlock
cleaned
```

### Sign

**WARNING: signing is considered EXPERIMENTAL and SHOULD NOT BE RELIED ON, please use
[`apksigner`](https://developer.android.com/studio/command-line/apksigner) instead.**

You'll need a certificate & private key in DER form; you can e.g. generate one
using `openssl`.

NB: these are **examples only**, make sure the RSA/DSA key size or ECDSA curve
you use is appropriate for your specific security requirements.

```bash
# RSA
$ openssl req -x509 -newkey rsa:4096 -sha512 -outform DER -out cert.der -days 10000 -nodes \
  -subj '/CN=test key' -keyout - | openssl pkcs8 -topk8 -nocrypt -outform DER -out privkey.der

# alternatively, DSA
$ openssl dsaparam -genkey -outform DER -out privkey.der 2048
$ openssl req -x509 -key privkey.der -outform DER -out cert.der -days 10000 -subj '/CN=test key'

# alternatively, EC
$ openssl ecparam -genkey -name prime256v1 -outform DER -out privkey.der
$ openssl req -x509 -key privkey.der -outform DER -out cert.der -days 10000 -subj '/CN=test key'
```

Sign an APK:

```bash
$ apksigtool sign --cert cert.der --key privkey.der unsigned.apk output.apk
```

### Help

```bash
$ apksigtool --help
$ apksigtool parse --help       # verify --help, clean --help, etc.
```

<!--
$ man apksigtool                # requires the man page to be installed
-->

## Python API

### APK Signing Block

```python
>>> import apksigtool
>>> _, data = apksigtool.extract_v2_sig(apk)
>>> blk = apksigtool.APKSigningBlock.parse(data)    # parse APK Signing Block
>>> blk = apksigtool.parse_apk_signing_block(data)  # same as above

>>> apksigtool.show_parse_tree(blk)                 # print parse tree
>>> apksigtool.show_json(blk)                       # JSON

>>> blk.verify(apk)                                 # [EXPERIMENTAL] raises on failure
>>> result = verified, failed = blk.verify_results(apk)
>>> result = apksigtool.verify_apk(apk)             # uses .verify_results()
```

### Cleaning

```python
>>> import apksigtool
>>> _, data = apksigtool.extract_v2_sig(apk)
>>> data_cleaned = apksigtool.clean_apk_signing_block(data)

>>> apksigtool.clean_apk(some_apk)                  # NB: modifies existing APK!
```

### v1 (JAR) signatures

```python
>>> import apksigcopier, apksigtool
>>> meta = tuple(apksigcopier.extract_meta(apk))
>>> sig = apksigtool.JARSignature.parse(meta)       # parse v1 signature
>>> sig = apksigtool.parse_apk_v1_signature(meta)   # same as above

>>> apksigtool.show_v1_signature(sig)               # print parse tree
>>> apksigtool.show_json(sig)                       # JSON

>>> result = sig.verify(apk)                        # [EXPERIMENTAL] raises on failure
```

<!--
## FAQ

... FIXME ...
-->

## Tab Completion

NB: the syntax for the environment variable changed in click >= 8.0,
use e.g. `source_bash` instead of `bash_source` for older versions.

For Bash, add this to `~/.bashrc`:

```bash
eval "$(_APKSIGTOOL_COMPLETE=bash_source apksigtool)"
```

For Zsh, add this to `~/.zshrc`:

```zsh
eval "$(_APKSIGTOOL_COMPLETE=zsh_source apksigtool)"
```

For Fish, add this to `~/.config/fish/completions/apksigtool.fish`:

```fish
eval (env _APKSIGTOOL_COMPLETE=fish_source apksigtool)
```

## Installing

<!-- FIXME
### Using pip

```bash
$ pip install apksigtool
```

NB: depending on your system you may need to use e.g. `pip3 --user`
instead of just `pip`.
-->

### From git

NB: this installs the latest development version, not the latest
release.

```bash
$ git clone https://github.com/obfusk/apksigtool.git
$ cd apksigtool
$ pip install -e .
```

NB: you may need to add e.g. `~/.local/bin` to your `$PATH` in order
to run `apksigtool`.

To update to the latest development version:

```bash
$ cd apksigtool
$ git pull --rebase
```

## Dependencies

* Python >= 3.8 + [apksigcopier](https://github.com/obfusk/apksigcopier) +
  asn1crypto + click + cryptography + pyasn1 + pyasn1-modules + simplejson.

### Debian/Ubuntu

```bash
$ apt install apksigcopier python3-{asn1crypto,click,cryptography,pyasn1{,-modules},simplejson}
```

## License

[![AGPLv3+](https://www.gnu.org/graphics/agplv3-155x51.png)](https://www.gnu.org/licenses/agpl-3.0.html)

<!-- vim: set tw=70 sw=2 sts=2 et fdm=marker : -->
