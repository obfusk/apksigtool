SHELL     := /bin/bash
PYTHON    ?= python3

PYCOV     := $(PYTHON) -mcoverage run --source apksigtool
PYCOVCLI  := $(PYCOV) -a apksigtool/__init__.py

export PYTHONWARNINGS := default

.PHONY: all install test test-cli doctest coverage lint lint-extra clean cleanup
.PHONY: test-signing test-apks test-apks-apksigner test-apks-verify \
        test-apks-verify-check-v1 test-apks-verify-v1 test-apks-parse \
        test-apks-parse-v1 test-apks-parse-json test-apks-parse-json-v1 \
        test-apks-clean-DESTRUCTIVE test-apks-clean-check-DESTRUCTIVE

all: # TODO: apksigtool.1

install:
	$(PYTHON) -mpip install -e .

test: test-cli doctest lint lint-extra

test-cli:
	# TODO
	apksigtool --version

doctest:
	# NB: uses test/apks/apks/*.apk
	$(PYTHON) -m doctest apksigtool/__init__.py

coverage:
	# NB: uses test/apks/apks/*.apk & modifies .tmp
	mkdir -p .tmp
	cp test/apks/apks/v3-only-with-stamp.apk .tmp/test.apk
	openssl req -x509 -newkey rsa:2048 -sha512 -outform DER -out .tmp/cert.der \
	    -days 10000 -nodes -subj '/CN=test key' -keyout - \
	  | openssl pkcs8 -topk8 -nocrypt -outform DER -out .tmp/privkey.der
	$(PYCOV) -m doctest apksigtool/__init__.py
	$(PYCOVCLI) verify    --check-v1 test/apks/apks/golden-aligned-v1v2v3-out.apk
	$(PYCOVCLI) verify-v1            test/apks/apks/golden-aligned-v1v2v3-out.apk
	$(PYCOVCLI) parse     --verbose  test/apks/apks/golden-aligned-v1v2v3-out.apk >/dev/null
	$(PYCOVCLI) parse-v1  --verbose  test/apks/apks/golden-aligned-v1v2v3-out.apk >/dev/null
	$(PYCOVCLI) parse     --json     test/apks/apks/golden-aligned-v1v2v3-out.apk >/dev/null
	$(PYCOVCLI) parse-v1  --json     test/apks/apks/golden-aligned-v1v2v3-out.apk >/dev/null
	$(PYCOVCLI) clean                .tmp/test.apk
	$(PYCOVCLI) sign --cert .tmp/cert.der --key .tmp/privkey.der \
	  test/apks/apks/golden-aligned-in.apk .tmp/out.apk
	$(PYCOVCLI) verify    --check-v1 .tmp/out.apk
	$(PYTHON) -mcoverage html
	$(PYTHON) -mcoverage report

test-signing:
	# NB: uses test/apks/apks/*.apk & modifies .tmp
	mkdir -p .tmp
	openssl req -x509 -newkey rsa:2048 -sha512 -outform DER -out .tmp/cert-rsa.der \
	    -days 10000 -nodes -subj '/CN=test key' -keyout - \
	  | openssl pkcs8 -topk8 -nocrypt -outform DER -out .tmp/privkey-rsa.der
	openssl dsaparam -genkey -outform DER -out .tmp/privkey-dsa.der 2048
	openssl req -x509 -key .tmp/privkey-dsa.der -outform DER -out .tmp/cert-dsa.der \
	  -days 10000 -subj '/CN=test key'
	openssl ecparam -genkey -name prime256v1 -outform DER -out .tmp/privkey-ec.der
	openssl req -x509 -key .tmp/privkey-ec.der -outform DER -out .tmp/cert-ec.der \
	  -days 10000 -subj '/CN=test key'
	apksigtool sign --cert .tmp/cert-rsa.der --key .tmp/privkey-rsa.der \
	  test/apks/apks/golden-aligned-in.apk .tmp/out-rsa.apk
	apksigtool sign --cert .tmp/cert-dsa.der --key .tmp/privkey-dsa.der \
	  test/apks/apks/golden-aligned-in.apk .tmp/out-dsa.apk
	apksigtool sign --cert .tmp/cert-ec.der --key .tmp/privkey-ec.der \
	  test/apks/apks/golden-aligned-in.apk .tmp/out-ec.apk
	apksigtool verify --check-v1 .tmp/out-rsa.apk
	apksigtool verify --check-v1 .tmp/out-dsa.apk
	apksigtool verify --check-v1 .tmp/out-ec.apk
	apksigner verify --verbose .tmp/out-rsa.apk
	apksigner verify --verbose .tmp/out-dsa.apk
	apksigner verify --verbose .tmp/out-ec.apk

test-apks: test-apks-apksigner test-apks-verify test-apks-verify-check-v1 \
           test-apks-verify-v1 test-apks-parse test-apks-parse-v1 \
           test-apks-parse-json test-apks-parse-json-v1

test-apks-apksigner:
	cd test && diff -Naur test-apksigner.out <( ./test-apksigner.sh )

test-apks-verify:
	cd test && diff -Naur test-verify.out <( ./test-verify.sh \
	  | grep -vF 'WARNING: verification is considered EXPERIMENTAL' )

test-apks-verify-check-v1:
	cd test && diff -Naur test-verify-check-v1.out <( ./test-verify-check-v1.sh \
	  | grep -vF 'WARNING: verification is considered EXPERIMENTAL' )

test-apks-verify-v1:
	cd test && diff -Naur test-verify-v1.out <( ./test-verify-v1.sh \
	  | grep -vF 'WARNING: verification is considered EXPERIMENTAL' )

test-apks-parse:
	cd test && diff -Naur test-parse.out <( ./test-parse.sh \
	  | grep -vF 'WARNING: verification is considered EXPERIMENTAL' )

test-apks-parse-v1:
	cd test && diff -Naur test-parse-v1.out <( ./test-parse-v1.sh \
	  | grep -vF 'WARNING: verification is considered EXPERIMENTAL' )

test-apks-parse-json:
	cd test && diff -Naur test-parse-json.out <( ./test-parse-json.sh \
	  | grep -vF 'WARNING: verification is considered EXPERIMENTAL' )

test-apks-parse-json-v1:
	cd test && diff -Naur test-parse-json-v1.out <( ./test-parse-json-v1.sh \
	  | grep -vF 'WARNING: verification is considered EXPERIMENTAL' )

test-apks-clean-DESTRUCTIVE:
	# WARNING: modifies test/apks/apks/*.apk
	cd test && diff -Naur test-clean.out <( ./test-clean.sh \
	  | grep -vF 'WARNING: verification is considered EXPERIMENTAL' )

test-apks-clean-check-DESTRUCTIVE:
	# WARNING: modifies test/apks/apks/*.apk
	cd test && diff -Naur test-clean-check.out <( ./test-clean-check.sh \
	  | grep -vF 'WARNING: verification is considered EXPERIMENTAL' )

lint:
	flake8 apksigtool/__init__.py
	pylint apksigtool/__init__.py

lint-extra:
	# TODO
	mypy --strict --ignore-missing-imports apksigtool/__init__.py

clean: cleanup
	rm -fr apksigtool.egg-info/

cleanup:
	find -name '*~' -delete -print
	rm -fr __pycache__/ .mypy_cache/
	rm -fr build/ dist/
	rm -fr .coverage htmlcov/
	rm -fr apksigtool.1
	rm -fr .tmp/

%.1: %.1.md
	pandoc -s -t man -o $@ $<

.PHONY: _package _publish

_package:
	SOURCE_DATE_EPOCH="$$( git log -1 --pretty=%ct )" \
	  $(PYTHON) setup.py sdist bdist_wheel
	twine check dist/*

_publish: cleanup _package
	read -r -p "Are you sure? "; \
	[[ "$$REPLY" == [Yy]* ]] && twine upload dist/*
