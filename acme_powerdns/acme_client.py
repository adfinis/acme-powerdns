#!/usr/bin/env python
# -*- coding: UTF-8 -*-

# Copyright (c) 2017, Adfinis SyGroup AG
# All rights reserved.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

"""
import logging
from OpenSSL import crypto
from acme import challenges
from acme_powerdns import acme_client


logging.basicConfig(level=logging.INFO)

ac = acme_client.Client(
    logging,
    'https://acme-staging.api.letsencrypt.org/directory'
)
authzrs = list()

# create an ACME account
account_key = ac.create_account('account.key')

for domain in ['www.example.com', 'mail.example.com']:
    # request a challenge
    authzr, challb = ac.request_domain_challenges(
        domain,
        challenges.DNS01,
    )
    authzrs.append(authzr)

    chall_response, chall_validation = challb.response_and_validation(
        account_key
    )

    # TODO: save the chall_validation (and validate if it's available)

    # send the challenge answer to the directory
    ac.answer_challenge(challb, chall_response)

    # TODO: delete the chall_validation

# get the certificate and chain
(cert, chain) = ac.request_cert(settings.CSR, authzrs)
with open(settings.CRT, 'wb') as f:
    for crt in cert:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, crt))
"""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from OpenSSL import crypto

from acme import client
from acme import messages
from acme import jose


class Client:

    def __init__(self, logging, directory_url):
        """Initialize a new ACME client.

        Args:
            logging: a logging object.
            directory_url: the ACME directory url (e.g. staging directory).
        """
        self._logging = logging
        self._acme = None
        self._directory_url = directory_url

    def create_account(self, keyfile) -> jose.JWKRSA:
        """Create a new account on the directory server.
        If the account exists, nothing will happen.

        Args:
            keyfile: file with the private RSA account key.
        """
        with open(keyfile, 'rb') as kf:
            try:
                key_contents = kf.read()
                account_key = jose.JWKRSA(
                    key=serialization.load_pem_private_key(
                        key_contents,
                        None,
                        default_backend()
                    )
                )
            except BaseException as e:
                raise Exception("Key {} couldn't be loaded".format(e))

        try:
            self._acme = client.Client(
                self._directory_url,
                account_key,
            )

            self._regr = self._acme.register()
            self._logging.info(
                'Auto-accepting TOS: %s',
                self._regr.terms_of_service,
            )
            self._acme.agree_to_tos(self._regr)
            self._logging.debug(self._regr)
        except BaseException as e:
            raise SystemError("Account not created: {}".format(e))
        return account_key

    def request_domain_challenges(self,
                                  domain,
                                  ctype) -> (messages.AuthorizationResource,
                                             messages.ChallengeBody):
        """Request a challenge for a given domain.

        Args:
            domain: domain name.
            ctype: the challenge type (a acme.challenges.* object).

        Return: an authorization response and a challenge object.
        """
        try:
            authzr = self._acme.request_domain_challenges(
                domain,
                new_authzr_uri=self._regr.new_authzr_uri,
            )
            self._logging.debug(authzr)

            authzr, authzr_response = self._acme.poll(authzr)
        except BaseException as e:
            raise SystemError("Challenge requesting failed: {}".format(e))

        for c in authzr.body.combinations:
            if len(c) == 1 and isinstance(
                    authzr.body.challenges[c[0]].chall,
                    ctype):
                return (authzr, authzr.body.challenges[c[0]])
        raise LookupError('{} not in {}'.format(ctype, authzr))

    def answer_challenge(self, challb, chall_response):
        """Send a challenge confirmation message.

        Args:
            challb: a message of type challenge body.
            chall_response: the challenge response message.
        """
        try:
            self._acme.answer_challenge(challb, chall_response)
        except BaseException as e:
            raise SystemError("Challenge answering failed: {}".format(e))

    def request_cert(self, csr_file, authzrs) -> (list, list):
        """Request a certificate for a list of authorized domains.

        Args:
            csr_file: filename of the csr file.
            authzrs: a list of authorization responses.

        Return: a list of certificates and chains of type
                acme.jose.util.ComparableX509.
        """
        with open(csr_file, 'rb') as fp:
            try:
                csr = crypto.load_certificate_request(
                    crypto.FILETYPE_PEM,
                    fp.read()
                )
            except BaseException as e:
                raise ValueError("CSR in false format: {}".format(e))
        try:
            crt, updated_authzrs = self._acme.poll_and_request_issuance(
                jose.util.ComparableX509(csr),
                authzrs,
            )
        except BaseException as e:
            raise SystemError("Getting certificate failed: {}".format(e))
        try:
            cert = [crt.body]
            chain = self._acme.fetch_chain(crt)
        except BaseException as e:
            raise ValueError(
                "Extracting certificate and getting chain failed: {}".format(e)
            )
        return (cert, chain)


def _monkeypatch_post(self, url, obj,
                      content_type=client.ClientNetwork.JSON_CONTENT_TYPE,
                      check_response=True, **kwargs):
    data = self._wrap_in_jws(obj, self._get_nonce(url))
    response = self._send_request('POST', url, data=data, **kwargs)
    self._add_nonce(response)
    if check_response:
        return self._check_response(response, content_type=content_type)
    else:
        return response


def _monkeypatch_register(self, new_reg=None):
    new_reg = new_reg or messages.NewRegistration()
    response = self.net.post(
        self.directory[new_reg],
        new_reg,
        check_response=False,
    )
    loc = None
    if response.status_code == client.http_client.CONFLICT and \
            response.headers.get('Location'):
        reg = messages.UpdateRegistration()
        loc = response.headers.get('Location')
        response = self.net.post(loc, reg)
    return self._regr_from_response(response, uri=loc)


client.ClientNetwork.post = _monkeypatch_post
client.Client.register = _monkeypatch_register
