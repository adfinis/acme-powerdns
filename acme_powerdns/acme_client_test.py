#!/usr/bin/env python
# -*- coding: UTF-8 -*-

"""Test for acme_client."""

import logging
import acme
from acme_powerdns import acme_client


def test_account():
    logging.basicConfig(level=logging.INFO)
    ac = acme_client.Account(
        logging,
        'https://acme-staging.api.letsencrypt.org/directory',
    )

    ac.create_account('.testenv/account.key')

    assert not type(ac.get_regr()) == acme.messages.RegistrationResource
