#!/usr/bin/env python
# -*- coding: UTF-8 -*-

"""Test for acme_client."""

from acme_powerdns import cli


def test_cli_main():
    cli.renew_certificates([
        '-c', '.testdata/settings.yml'
    ])
