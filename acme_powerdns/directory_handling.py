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

import os

from OpenSSL import crypto
from acme_powerdns import acme_client, cert_handling


class DirectoryHandling:
    """Handle a directory with certificate signing requests.

    Each certificate signing request inside this directory will be validated
    and the corresponding certificate will be stored inside another directory.

    :ivar logging logging: a logging object.
    :ivar str directory_url: url to the acme directory.
    :ivar str account_key: account key filename (a X509 private key in PEM
        format).
    :ivar str csr_dir: directory to search for certificate signing requests.
    :ivar str crt_topdir: certificate top directory (each csr will get a
        subdirectory).
    :ivar int days: number of days until enddate before a certificate get
        renewed.
    :ivar NSUpdate nsupdate: a NSUpdate object to create and delete dns
        entries.
    """

    def __init__(self, logging, directory_url, account_key, csr_dir,
                 cert_topdir, days=30, nsupdate=None):

        self._logging = logging
        self._directory_url = directory_url
        self._account_key = account_key
        self._days = days
        self._nsupdate = nsupdate
        self._csr_dir = csr_dir
        self._cert_topdir = cert_topdir
        self._ac = None

    def get_account(self):
        """Get a registered acme account.

        :returns: a registered acme account object.
        :rtype: :class:`acme_powerdns.acme_client.Account`
        """
        if self._ac is None:
            self._ac = acme_client.Account(
                self._logging,
                self._directory_url,
            )

            # create an ACME account
            self._ac.create_account(
                self._account_key,
            )

        return self._ac

    def handle(self):
        """Handle the directory and validate each certificate signing request.
        """

        for csr in os.listdir(self._csr_dir):
            # calculate csr filename
            csr = os.path.join(self._csr_dir, csr)
            if not os.path.isfile(csr):
                continue
            self._logging.info(
                'handle certificate signing request: {0}'.format(csr)
            )

            # get a cert handle
            cert_handle = cert_handling.CertHandling()
            cert_handle.set_csr(csr)

            # calculate cert filename
            cn = cert_handle.get_common_name()
            crt = os.path.join(self._cert_topdir, cn, 'cert.pem')
            cert_handle.set_cert(crt)
            self._logging.debug(
                'certificate filename: {0}'.format(crt)
            )

            # calculate chain filename
            chain = os.path.join(self._cert_topdir, cn, 'chain.pem')
            self._logging.debug(
                'certificate chain filename: {0}'.format(chain)
            )

            # calculate FQDNs
            fqdn = cert_handle.get_alternative_names()
            self._logging.debug(
                'fqdn list: {0}'.format(fqdn)
            )

            # calculate enddate
            enddate = cert_handle.enddate()
            self._logging.info('Certificate {0} expires in {1} days'.format(
                crt,
                enddate,
            ))
            if enddate < self._days:
                # create certificate request
                cr = acme_client.CertRequest(self.get_account())
                tokens = cr.request_tokens(
                    fqdn,
                    'dns01',
                )

                # create dns record
                for token in tokens:
                    self._nsupdate.create(
                        '_acme-challenge.{0}'.format(token['domain']),
                        token['validation'],
                    )

                # get cert and chain content
                cert_content, chain_content = cr.answer_challenges(
                    cert_handle._csr,
                )

                # write certificate content to file
                with open(crt, 'wb') as f:
                    for content in cert_content:
                        f.write(crypto.dump_certificate(
                            crypto.FILETYPE_PEM,
                            content,
                        ))
                # write chain content to file
                with open(chain, 'wb') as f:
                    for content in chain_content:
                        f.write(crypto.dump_certificate(
                            crypto.FILETYPE_PEM,
                            content,
                        ))

                # delete dns record
                for token in tokens:
                    self._nsupdate.delete(
                        '_acme-challenge.{0}'.format(token['domain']),
                        token['validation'],
                    )
