#!/usr/bin/env python

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import OpenSSL

from acme import challenges
from acme import client
from acme import messages
from acme import jose


DIRECTORY_URL = 'https://acme-staging.api.letsencrypt.org/directory'


class Client:

    def __init__(self, logging):
        self._logging = logging
        self._acme = None

    def create_account(self, keyfile):
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

        self._acme = client.Client(DIRECTORY_URL, account_key)

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
        return (authzr, authzr_response)

    def filter_challenges(self, authzr, authzr_response):
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
