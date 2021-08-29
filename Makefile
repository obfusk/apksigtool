SHELL   := /bin/bash
PYTHON  ?= python3

export PYTHONWARNINGS := default

.PHONY: all install test test-cli lint lint-extra clean cleanup

all: apksigtool.1

install:
	$(PYTHON) -mpip install -e .

test: test-cli lint lint-extra

test-cli:
	# TODO
	apksigtool --version
	$(PYTHON) -m doctest apksigtool

lint:
	flake8 apksigtool.py
	pylint apksigtool.py

lint-extra:
	mypy apksigtool.py

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
