#!/usr/bin/env python

import json

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
import OpenSSL

from acme import client
from acme import messages
from acme import jose


DIRECTORY_URL = 'https://acme-staging.api.letsencrypt.org/directory'


class Client:

    def __init__(self, logging):
        self._logging = logging
        self._acme = None

    def create_account(self, bits):
        # generate_private_key requires cryptography>=0.5
        key = jose.JWKRSA(
            key=rsa.generate_private_key(
                public_exponent = 65537,
                key_size = bits,
                backend = default_backend()
            )
        )
        self._acme = client.Client(DIRECTORY_URL, key)

        self._regr = self._acme.register()
        self._logging.info(
            'Auto-accepting TOS: %s',
            self._regr.terms_of_service,
        )
        self._acme.agree_to_tos(self._regr)
        self._logging.debug(self._regr)

    def request_challenges(self, domain):
        authzr = self._acme.request_challenges(
            identifier = messages.Identifier(
                typ = messages.IDENTIFIER_FQDN,
                value = domain,
            ),
            new_authzr_uri = self._regr.new_authzr_uri
        )
        self._logging.debug(authzr)

        authzr, authzr_response = self._acme.poll(authzr)
        return (authzr, authzr_response)

    def filter_challenges(self, authzr, authzr_response):
        challenges = json.loads(authzr_response.content)['challenges']
        for i in range(0, len(challenges)):
            challenge = challenges.pop()
            if challenge['type'] == 'dns-01':
                return challenge['token']
        return None

    def respond_challenges(self, authzr, csr_file):
        with open(csr_file, 'rb') as fp:
            csr = OpenSSL.crypto.load_certificate_request(
                OpenSSL.crypto.FILETYPE_PEM,
                fp.read()
            )
        try:
            self._acme.request_issuance(
                jose.util.ComparableX509(csr),
                (authzr,),
            )
        except messages.Error as error:
            print(
                "This script is doomed to fail as no authorization "
                "challenges are ever solved. Error from server: {0}".format(
                    error
                )
            )
