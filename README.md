<!-- {{{1

    File        : README.md
    Maintainer  : FC Stegerman <flx@obfusk.net>
    Date        : 2022-10-26

    Copyright   : Copyright (C) 2022  FC Stegerman
    Version     : v0.1.0
    License     : AGPLv3+

}}}1 -->

[![GitHub Release](https://img.shields.io/github/release/obfusk/apksigtool.svg?logo=github)](https://github.com/obfusk/apksigtool/releases)
[![PyPI Version](https://img.shields.io/pypi/v/apksigtool.svg)](https://pypi.python.org/pypi/apksigtool)
[![Python Versions](https://img.shields.io/pypi/pyversions/apksigtool.svg)](https://pypi.python.org/pypi/apksigtool)
[![CI](https://github.com/obfusk/apksigtool/workflows/CI/badge.svg)](https://github.com/obfusk/apksigtool/actions?query=workflow%3ACI)
[![AGPLv3+](https://img.shields.io/badge/license-AGPLv3+-blue.svg)](https://www.gnu.org/licenses/agpl-3.0.html)

<!--
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

**WARNING: verification is considered EXPERIMENTAL and SHOULD NOT BE RELIED ON, please use
[`apksigner`](https://developer.android.com/studio/command-line/apksigner) instead.**

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
  VERIFIED
PAIR ID: 0xf05368c0
  APK SIGNATURE SCHEME v3 BLOCK
  SIGNER 0
    SIGNED DATA
      DIGEST 0
        SIGNATURE ALGORITHM ID: 0x104 (RSASSA-PKCS1-v1_5 with SHA2-512 digest)
  [...]
  VERIFIED
PAIR ID: 0x42726577
  VERITY PADDING BLOCK
```

JSON (filtered):

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

JSON (full):

```bash
$ apksigtool parse --json some.apk
```

<details>
<summary>full JSON output (long, some data elided)</summary>

NB: elided binary values (`digest`, `fingerprint`, `raw_data`, `signature`) are
represented as hex (e.g. "foo" would be represented as "666f6f").

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
                "fingerprint": "...",
                "hash_algorithm": null
              },
              "raw_data": "..."
            },
            "signatures": [
              {
                "_type": "Signature",
                "algoritm_id_info": "RSASSA-PKCS1-v1_5 with SHA2-256 digest, content digested using SHA2-256 in 1 MB chunks",
                "signature": "...",
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
                    "fingerprint": "...",
                    "hash_algorithm": "SHA256",
                    "issuer": "Common Name: ..., Organizational Unit: ...",
                    "not_valid_after": "2022-10-27 12:34:56+00:00",
                    "not_valid_before": "2022-10-26 12:34:56+00:00",
                    "serial_number": 42,
                    "signature_algorithm": "RSASSA_PKCS1V15",
                    "subject": "Common Name: ..., Organizational Unit: ..."
                  },
                  "public_key_info": {
                    "_type": "PublicKeyInfo",
                    "algorithm": "RSA",
                    "bit_size": 2048,
                    "fingerprint": "...",
                    "hash_algorithm": null
                  },
                  "raw_data": "..."
                }
              ],
              "digests": [
                {
                  "_type": "Digest",
                  "algoritm_id_info": "RSASSA-PKCS1-v1_5 with SHA2-256 digest, content digested using SHA2-256 in 1 MB chunks",
                  "digest": "...",
                  "signature_algorithm_id": 259
                }
              ],
              "raw_data": "..."
            }
          }
        ],
        "verification_error": null,
        "verified": true,
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
            ...
            "signed_data": {
              ...
              "max_sdk": 2147483647,
              "min_sdk": 24,
              ...
            }
          }
        ],
        "verification_error": null,
        "verified": true,
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

Extracted APKSigningBlock instead of APK:

```bash
$ mkdir meta
$ apksigcopier extract some.apk meta
$ apksigtool parse --block meta/APKSigningBlock
[...]
```

### Verify

**WARNING: verification is considered EXPERIMENTAL and SHOULD NOT BE RELIED ON, please use
[`apksigner`](https://developer.android.com/studio/command-line/apksigner) instead.**

```bash
$ apksigtool verify some.apk
WARNING: verification is considered EXPERIMENTAL, please use apksigner instead.
v2 verified
v3 verified
```

### Clean

NB: modifies in-place!

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

Extracted APKSigningBlock instead of APK:

```bash
$ mkdir meta
$ apksigcopier extract some.apk meta
$ apksigtool clean --block meta/APKSigningBlock
cleaned
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

Parse:

```python
>>> from apksigtool import ...
>>> apk_signing_block = parse_apk_signing_block(data, apkfile=None, sdk=None)
```

Parse tree & JSON:

```python
>>> show_parse_tree(apk_signing_block, verbose=False, apkfile=None, sdk=None, file=sys.stdout)
>>> show_json(apk_signing_block, file=sys.stdout)
```

Verify:

```python
>>> apk_signing_block.verify(apkfile, sdk=None)                   # raises on failure
>>> verified, failed = apk_signing_block.verify_results(apkfile, sdk=None)
>>> verify_apk(apkfile, sig_block=None, sdk=None)                 # verify APK (uses the above)
```

Low-level verification API:

```python
>>> verify_apk_signature_scheme(signers, apkfile, sdk=None)       # does the verification
>>> APKSignatureSchemeBlock(...).verify(apkfile, sdk=None)        # uses the above
```

Clean:

```python
>>> data_cleaned = clean_apk_signing_block(data, keep=())         # clean block
>>> cleaned = clean_apk(apkfile, keep=(), check=False, sdk=None)  # clean APK
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

<!--
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
  asn1crypto + click + cryptography + simplejson.

### Debian/Ubuntu

```bash
$ apt install apksigcopier python3-{asn1crypto,click,cryptography,simplejson}
```

## License

[![AGPLv3+](https://www.gnu.org/graphics/agplv3-155x51.png)](https://www.gnu.org/licenses/agpl-3.0.html)

<!-- vim: set tw=70 sw=2 sts=2 et fdm=marker : -->
