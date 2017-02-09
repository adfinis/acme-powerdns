#!/usr/bin/env python
# -*- coding: UTF-8 -*-

"""Test for acme_client."""

import pytest

import acme
from acme_powerdns import acme_client


@pytest.fixture(autouse=True, scope='session')
def account():
    ac = acme_client.Account(
        'https://acme-staging.api.letsencrypt.org/directory',
    )
    ac.create_account('.testdata/account.key')
    return ac


def test_account_regr():
    assert type(account().get_regr()) == acme.messages.RegistrationResource


def test_account_client():
    assert type(account().get_client()) == acme.client.Client


def test_account_account_key():
    assert type(account().get_account_key()) == acme.jose.jwk.JWKRSA


@pytest.fixture(scope='session')
def cert_request():
    return acme_client.CertRequest(account())


def test_cert_request_request_tokens():
    with pytest.raises(ValueError):
        assert cert_request().request_tokens([], 'dns01')
    assert cert_request().request_tokens(['www.example.com'], 'dns01')
    assert cert_request().request_tokens(
        ['www.example.com', 'mail.example.com'],
        'dns01',
    )
    with pytest.raises(ValueError):
        assert cert_request().request_tokens(['www.example.com'], 'dns00')
