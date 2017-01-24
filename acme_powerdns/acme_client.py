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

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import OpenSSL

from acme import challenges
from acme import client
from acme import messages
from acme import jose


class Client:

    def __init__(self, logging, directory_url):
        """Initialize a new ACME client.

        logging: a logging object.
        directory_url: the ACME directory url (e.g. staging directory).
        """
        self._logging = logging
        self._acme = None
        self._directory_url = directory_url

    def create_account(self, keyfile):
        """Create a new account on the directory server.
        If the account exists, nothing will happen.

        keyfile: file with the private RSA account key.
        """
        # generate_private_key requires cryptography>=0.5
        with open(keyfile, 'rb') as kf:
            key_contents = kf.read()
            try:
                account_key = jose.JWKRSA(
                    key=serialization.load_pem_private_key(
                        key_contents,
                        None,
                        default_backend()
                    )
                )
            except TypeError as e:
                self._logging.error(e)

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
        return account_key

    def request_challenges(self, domain):
        authzr = self._acme.request_domain_challenges(
            domain,
            new_authzr_uri = self._regr.new_authzr_uri,
        )
        self._logging.debug(authzr)

        authzr, authzr_response = self._acme.poll(authzr)
        return authzr

    def filter_challenges(self, authzr):
        for c in authzr.body.combinations:
            if len(c) == 1 and isinstance(
                    authzr.body.challenges[c[0]].chall,
                    challenges.DNS01):
                return authzr.body.challenges[c[0]]
        return None

    def answer_challenge(self, challb, chall_response):
        self._acme.answer_challenge(challb, chall_response)

    def request_cert(self, csr_file, authzrs):
        with open(csr_file, 'rb') as fp:
            csr = OpenSSL.crypto.load_certificate_request(
                OpenSSL.crypto.FILETYPE_PEM,
                fp.read()
            )
        try:
            crt, updated_authzrs = self._acme.poll_and_request_issuance(
                jose.util.ComparableX509(csr),
                authzrs,
            )
        except messages.Error as error:
            self._logging.error(
                "Error from server: {}".format(
                    error
                )
            )
        cert = [crt.body]
        chain = self._acme.fetch_chain(crt)
        return (cert, chain)


def _monkeypatch_post(
        self,
        url,
        obj,
        content_type=client.ClientNetwork.JSON_CONTENT_TYPE,
        check_response=True,
        **kwargs):
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
