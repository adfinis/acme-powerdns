#!/usr/bin/env python
# -*- coding: UTF-8 -*-

"""Test for acme_client."""

import pytest

from acme_powerdns import cli


@pytest.mark.xfail
def test_cli_main():
    cli.renew_certificates([
        '-c', '.testdata/settings.yml'
    ])
