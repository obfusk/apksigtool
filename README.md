<!-- {{{1

    File        : README.md
    Maintainer  : FC Stegerman <flx@obfusk.net>
    Date        : 2022-10-20

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

## parse/verify/clean android apk signing blocks

... FIXME ...

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

JSON:

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

Extracted APKSigningBlock instead of APK:

```bash
$ mkdir meta
$ apksigcopier extract some.apk meta
$ apksigtool parse --block meta/APKSigningBlock
[...]
```

### Verify

```bash
$ apksigtool verify some.apk
WARNING: THIS IS A PROTOTYPE; DO NOT USE IN PRODUCTION!
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

```python
>>> from apksigtool import ...
```

... FIXME ...

## FAQ

... FIXME ...

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

* Python >= 3.8 + apksigcopier + asn1crypto + click + cryptography + simplejson.

### Debian/Ubuntu

```bash
$ apt install apksigcopier python3-{asn1crypto,click,cryptography,simplejson}
```

## License

[![AGPLv3+](https://www.gnu.org/graphics/agplv3-155x51.png)](https://www.gnu.org/licenses/agpl-3.0.html)

<!-- vim: set tw=70 sw=2 sts=2 et fdm=marker : -->
