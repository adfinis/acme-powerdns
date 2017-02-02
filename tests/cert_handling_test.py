#!/usr/bin/env python
# -*- coding: UTF-8 -*-

"""Test for acme_client."""

import pytest
import OpenSSL

from acme_powerdns import cert_handling


@pytest.fixture(scope='session')
def crth():
    return cert_handling.CertHandling(
        '.testenv/cert.csr',
        '.testenv/cert.pem',
    )


@pytest.fixture(scope='session')
def crth_fail():
    return cert_handling.CertHandling(
        '',
        '',
    )


def test_cert_handling_load_cert_req():
    with pytest.raises(ValueError):
        assert type(crth_fail().load_cert_req()) == OpenSSL.crypto.X509Req
    assert type(crth().load_cert_req()) == OpenSSL.crypto.X509Req


def test_cert_handling_load_cert():
    with pytest.raises(ValueError):
        assert type(crth_fail().load_cert()) == OpenSSL.crypto.X509
    assert type(crth().load_cert()) == OpenSSL.crypto.X509


def test_cert_handling_enddate():
    assert type(crth().enddate()) == int


def test_cert_handling_get_alternative_names():
    l = crth().get_alternative_names()
    assert type(l) == list
    assert l == []
