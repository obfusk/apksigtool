<!-- {{{1

    File        : README.md
    Maintainer  : FC Stegerman <flx@obfusk.net>
    Date        : 2022-08-07

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

## parse & verify android apk signing blocks

... FIXME ...

## Python API

... FIXME ...

## FAQ

... FIXME ...

## Tab Completion

NB: the syntax for the environment variable changed in click >= 8.0,
use e.g. `source_bash` instead of `bash_source` for older versions.

For Bash, add this to `~/.bashrc`:

```bash
eval "$(_APKSIGCOPIER_COMPLETE=bash_source apksigtool)"
```

For Zsh, add this to `~/.zshrc`:

```zsh
eval "$(_APKSIGCOPIER_COMPLETE=zsh_source apksigtool)"
```

For Fish, add this to `~/.config/fish/completions/apksigtool.fish`:

```fish
eval (env _APKSIGCOPIER_COMPLETE=fish_source apksigtool)
```

## Installing

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

* Python >= 3.5 + apksigcopier + asn1crypto + click + cryptography + simplejson.

### Debian/Ubuntu

```bash
$ apt install apksigcopier python3-{asn1crypto,click,cryptography,simplejson}
```

## License

[![AGPLv3+](https://www.gnu.org/graphics/agplv3-155x51.png)](https://www.gnu.org/licenses/agpl-3.0.html)

<!-- vim: set tw=70 sw=2 sts=2 et fdm=marker : -->
