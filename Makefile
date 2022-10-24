SHELL   := /bin/bash
PYTHON  ?= python3

export PYTHONWARNINGS := default

.PHONY: all install test test-cli test-apks lint lint-extra clean cleanup

all: apksigtool.1

install:
	$(PYTHON) -mpip install -e .

test: test-cli lint lint-extra

test-cli:
	# TODO
	apksigtool --version
	$(PYTHON) -m doctest apksigtool

test-apks:
	cd test/apks && diff -Naur ../test-verify.out <( ../test-verify.sh \
	  | grep -vF -e CryptographyDeprecationWarning -e cryptography.exceptions \
	             -e 'WARNING: THIS IS A PROTOTYPE' )
	cd test/apks && diff -Naur ../test-parse.out <( ../test-parse.sh \
	  | grep -vF -e CryptographyDeprecationWarning -e cryptography.exceptions \
	             -e 'WARNING: THIS IS A PROTOTYPE' )
	cd test/apks && diff -Naur ../test-parse-json.out <( ../test-parse-json.sh \
	  | grep -vF -e CryptographyDeprecationWarning -e cryptography.exceptions \
	             -e 'WARNING: THIS IS A PROTOTYPE' )

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
