from pathlib import Path
import setuptools

# from apksigtool import __version__
__version__ = "0.1.0"

info = Path(__file__).with_name("README.md").read_text(encoding = "utf8")

setuptools.setup(
    name              = "apksigtool",
    url               = "https://github.com/obfusk/apksigtool",
    description       = "parse/verify/clean android apk signing blocks & apks",
    long_description  = info,
    long_description_content_type = "text/markdown",
    version           = __version__,
    author            = "FC Stegerman",
    author_email      = "flx@obfusk.net",
    license           = "AGPLv3+",
    classifiers       = [
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Telecommunications Industry",
        "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: POSIX :: Linux",
        "Operating System :: POSIX",
        "Operating System :: Unix",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
      # "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Topic :: Software Development",
        "Topic :: Utilities",
    ],
    keywords          = "android apk signing",
    entry_points      = dict(console_scripts = ["apksigtool = apksigtool:main"]),
    packages          = ["apksigtool"],
    package_data      = dict(apksigtool = ["py.typed"]),
    python_requires   = ">=3.8",
    install_requires  = ["apksigcopier", "asn1crypto", "click>=6.0", "cryptography",
                         "pyasn1", "pyasn1-modules", "simplejson"],
)
