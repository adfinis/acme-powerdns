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
from OpenSSL import crypto
from acme_powerdns import acme_client


ac = acme_client.Account(
    'https://acme-staging.api.letsencrypt.org/directory'
)

# create an ACME account
ac.create_account(
    'account.key',
)

# create certificate request
with open('cert.csr', 'rb') as fp:
    csr = crypto.load_certificate_request(
        crypto.FILETYPE_PEM,
        fp.read()
    )
cr = acme_client.CertRequest(ac)
tokens = cr.request_tokens(
    [
        'www.example.com',
        'mail.example.com',
    ],
    'dns01',
)

for token in tokens:
    # TODO: create all tokens
    # save the token['validation'] for each token['domain']

cert, chain = cr.answer_challenges(
    csr,
)
with open('cert.pem', 'wb') as fp:
    for crt in cert:
        fp.write(crypto.dump_certificate(crypto.FILETYPE_PEM, crt))
with open('chain.pem', 'wb') as fp:
    for crt in chain:
        fp.write(crypto.dump_certificate(crypto.FILETYPE_PEM, crt))

for token in tokens:
    # TODO: create all tokens
    # delete the token['validation'] for each token['domain']
"""

import logging

from acme import challenges, client, jose, messages
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


class Account:
    """Create account at the directory.

    :ivar string directory_url: acme directory url.
    """

    def __init__(self, directory_url):
        self._logging = logging.getLogger(__name__)
        self._acme = None
        self._directory_url = directory_url

    def create_account(self, keyfile):
        """Create a new account on the directory server.
        If the account exists, nothing will happen.

        :param string keyfile: file with the private RSA account key.
        """
        with open(keyfile, 'rb') as kf:
            try:
                key_contents = kf.read()
                self._account_key = jose.JWKRSA(
                    key=serialization.load_pem_private_key(
                        key_contents,
                        None,
                        default_backend()
                    )
                )
            except BaseException as e:
                raise Exception("Key {0} couldn't be loaded".format(e))

        try:
            self._acme = client.Client(
                self._directory_url,
                self._account_key,
            )

            self._regr = self._acme.register()
            self._logging.info(
                'Auto-accepting TOS: %s',
                self._regr.terms_of_service,
            )
            self._acme.agree_to_tos(self._regr)
            self._logging.debug(self._regr)
        except BaseException as e:
            raise SystemError("Account not created: {0}".format(e))

    def get_regr(self) -> messages.RegistrationResource:
        """Get account registration resource.

        :returns: account registration resource.
        :rtype: :class:`acme.messages.RegistrationResource`
        """

        return self._regr

    def get_client(self) -> client.Client:
        """Get acme client object.

        :returns: account client object.
        :rtype: :class:`acme.client.Client`
        """

        return self._acme

    def get_account_key(self) -> jose.jwk.JWKRSA:
        """Get loaded account key.

        :returns: account key.
        :rtype: :class:`acme.jose.jwk.JWKRSA`
        """

        return self._account_key


class CertRequest:
    """Handle a certificate with the acme directory api.

    :ivar acme.client.Client client: a account client object.
    """

    def __init__(self, client):
        self._client = client
        self._acme = client.get_client()
        self._regr = client.get_regr()
        self._account_key = client.get_account_key()
        self._challenges = []

    def request_tokens(self, domains, ctype) -> list:
        """Request tokens for a list of domains.

        :param list domains: a list of domains (as string).
        :param string ctype: challenge type (one of "dns01", "http01",
                             "tlssni01").

        :returns: a list of dicts with domain and token.
        :rtype: list
        """
        tokens = []
        try:
            challenge_class = {
                'dns01': challenges.DNS01,
                'http01': challenges.HTTP01,
                'tlssni01': challenges.TLSSNI01,
            }[ctype]
        except KeyError:
            raise ValueError('Type {0} is not defined'.format(ctype))
        if domains == []:
            raise ValueError('Empty domain list')
        for domain in domains:
            # request a challenge
            try:
                authzr = self._acme.request_domain_challenges(
                    domain,
                    new_authzr_uri=self._regr.new_authzr_uri,
                )

                authzr, authzr_response = self._acme.poll(authzr)
            except BaseException as e:
                raise SystemError("Challenge requesting failed: {0}".format(e))

            challb = None
            for c in authzr.body.combinations:
                if len(c) == 1 and isinstance(
                        authzr.body.challenges[c[0]].chall,
                        challenge_class):
                    challb = authzr.body.challenges[c[0]]
            if challb is None:
                raise LookupError('{0} not in {1}'.format(ctype, authzr))

            response, validation = challb.response_and_validation(
                self._account_key
            )

            self._challenges.append({
                'authzr': authzr,
                'challb': challb,
                'response': response,
                'validation': validation,
            })
            tokens.append({
                'domain': domain,
                'validation': validation,
            })

        return tokens

    def answer_challenges(self, csr):
        """Answer all challenges.

        :param csr: certificate signing request.
        :type csr: :class:`OpenSSL.crypto.X509Req`

        :returns: certificate and certificate chain.
        :rtype: tuple
        """
        authzrs = []
        for authzr in self._challenges:
            try:
                self._acme.answer_challenge(
                    authzr['challb'],
                    authzr['response'],
                )
            except BaseException as e:
                raise SystemError("Challenge answering failed: {0}".format(e))
            authzrs.append(authzr['authzr'])

        try:
            crt, updated_authzrs = self._acme.poll_and_request_issuance(
                jose.util.ComparableX509(csr),
                authzrs,
            )
        except BaseException as e:
            raise SystemError("Requesting certificate failed: {0}".format(e))

        try:
            cert = [crt.body]
            chain = self._acme.fetch_chain(crt)
        except BaseException as e:
            raise ValueError(
                "Extracting certificate and getting chain failed: "
                "{0}".format(e)
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
