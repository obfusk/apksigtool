SHELL   := /bin/bash
PYTHON  ?= python3

export PYTHONWARNINGS := default

.PHONY: all install test test-cli lint lint-extra clean cleanup
.PHONY: test-apks test-apks-verify test-apks-parse test-apks-parse-json
.PHONY: test-apks-clean-DESTRUCTIVE test-apks-clean-check-DESTRUCTIVE

all: # TODO: apksigtool.1

install:
	$(PYTHON) -mpip install -e .

test: test-cli lint lint-extra

test-cli:
	# TODO
	apksigtool --version
	$(PYTHON) -m doctest apksigtool

test-apks: test-apks-verify test-apks-parse test-apks-parse-json

test-apks-verify:
	cd test/apks && diff -Naur ../test-verify.out <( ../test-verify.sh \
	  | grep -vF 'WARNING: verification is considered EXPERIMENTAL' )

test-apks-parse:
	cd test/apks && diff -Naur ../test-parse.out <( ../test-parse.sh \
	  | grep -vF 'WARNING: verification is considered EXPERIMENTAL' )

test-apks-parse-json:
	cd test/apks && diff -Naur ../test-parse-json.out <( ../test-parse-json.sh \
	  | grep -vF 'WARNING: verification is considered EXPERIMENTAL' )

test-apks-clean-DESTRUCTIVE:
	# WARNING: modifies test/apks/apks/*.apk
	cd test/apks && diff -Naur ../test-clean.out <( ../test-clean.sh \
	  | grep -vF 'WARNING: verification is considered EXPERIMENTAL' )

test-apks-clean-check-DESTRUCTIVE:
	# WARNING: modifies test/apks/apks/*.apk
	cd test/apks && diff -Naur ../test-clean-check.out <( ../test-clean-check.sh \
	  | grep -vF 'WARNING: verification is considered EXPERIMENTAL' )

lint:
	flake8 apksigtool.py
	pylint apksigtool.py

lint-extra:
	# TODO
	mypy --ignore-missing-imports apksigtool.py

clean: cleanup
	rm -fr apksigtool.egg-info/

cleanup:
	find -name '*~' -delete -print
	rm -fr __pycache__/ .mypy_cache/
	rm -fr build/ dist/
	rm -fr .coverage htmlcov/
	rm -fr apksigtool.1

%.1: %.1.md
	pandoc -s -t man -o $@ $<

.PHONY: _package _publish

_package:
	$(PYTHON) setup.py sdist bdist_wheel
	twine check dist/*

_publish: cleanup _package
	read -r -p "Are you sure? "; \
	[[ "$$REPLY" == [Yy]* ]] && twine upload dist/*
