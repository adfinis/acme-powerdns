#!/usr/bin/env python
# -*- coding: UTF-8 -*-

"""Test for acme_client."""

import pytest
import OpenSSL

from acme_powerdns import cert_handling


@pytest.fixture(scope='session')
def crth():
    ch = cert_handling.CertHandling()
    ch.set_csr('.testdata/csr/www.example.com.csr')
    ch.set_cert('.testdata/live/www.test.subpage.ch/cert.pem')
    return ch


@pytest.fixture(scope='session')
def crth_empty():
    ch = cert_handling.CertHandling()
    ch.set_csr('')
    ch.set_cert('')
    return ch


@pytest.fixture(scope='session')
def crth_none():
    ch = cert_handling.CertHandling()
    return ch


def test_cert_handling_load_cert_req():
    with pytest.raises(ValueError):
        assert type(crth_empty().load_cert_req()) == OpenSSL.crypto.X509Req
    with pytest.raises(ValueError):
        assert type(crth_none().load_cert_req()) == OpenSSL.crypto.X509Req
    assert type(crth().load_cert_req()) == OpenSSL.crypto.X509Req


def test_cert_handling_load_cert():
    with pytest.raises(ValueError):
        assert type(crth_empty().load_cert()) == OpenSSL.crypto.X509
    with pytest.raises(ValueError):
        assert type(crth_none().load_cert()) == OpenSSL.crypto.X509
    assert type(crth().load_cert()) == OpenSSL.crypto.X509


def test_cert_handling_enddate():
    assert type(crth().enddate()) == int


def test_cert_handling_get_alternative_names():
    l = crth().get_alternative_names()
    assert type(l) == list
