#!/usr/bin/env python3
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
# get a cert handle
cert_handle = cert_handling.CertHandling()
cert_handle.set_csr('cert.csr')

cn = cert_handle.get_common_name()
crt = os.path.join(cn, 'cert.pem')
chain = os.path.join(cn, 'chain.pem')
fqdn = cert_handle.get_alternative_names()
cert_handle.set_cert(crt)

if cert_handle.enddate() < 30:
    # create certificate request
    cr = acme_client.CertRequest(self.get_account())
    tokens = cr.request_tokens(
        fqdn,
        'dns01',
    )

    # create dns record
    for token in tokens:
        # TODO: create all tokens
        # save the token['validation'] for each token['domain']

    cert, chain = cr.answer_challenges(
        cert_handle._csr,
    )
    # write certificate content to file
    with open(crt, 'wb') as f:
        for crt in cert:
            f.write(crypto.dump_certificate(
                crypto.FILETYPE_PEM,
                crt,
            ))
    # write chain content to file
    with open(chain, 'wb') as f:
        for crt in chain:
            f.write(crypto.dump_certificate(
                crypto.FILETYPE_PEM,
                crt,
            ))

    for token in tokens:
        # TODO: create all tokens
        # delete the token['validation'] for each token['domain']
"""

import os
from datetime import datetime

from acme import crypto_util
from OpenSSL import crypto


class CertHandling:
    """Handle one certificate.
    Load and handle certificate and signing request.
    """

    def __init__(self):
        self._csr_file = None
        self._crt_file = None
        self._csr = None
        self._crt = None

    def set_csr(self, csr):
        """Set the certificate signing request filename for this object.

        :param str csr: certificate signing request filename.
        """

        self._csr_file = csr
        self._csr = self.load_cert_req()

    def set_cert(self, crt):
        """Set the certificate filename for this object.

        :param str crt: certificate filename.
        """

        self._crt_file = crt
        self._crt = self.load_cert()

    def load_cert_req(self) -> crypto.X509Req:
        """Load the certificate request of this object.

        :returns: Certificate request.
        :rtype: :class:`OpenSSL.crypto.X509Req`
        """

        if self._csr_file is None:
            raise ValueError('certificate request {0} not set'.format(
                self._csr_file,
            ))

        if os.path.isfile(self._csr_file):
            with open(self._csr_file, 'rb') as fp:
                csr = crypto.load_certificate_request(
                    crypto.FILETYPE_PEM,
                    fp.read()
                )
        else:
            raise ValueError('certificate request {0} does not exists'.format(
                self._csr_file,
            ))
        return csr

    def load_cert(self) -> crypto.X509:
        """Load the certificate of this object.

        :returns: Certificate.
        :rtype: :class:`OpenSSL.crypto.X509`
        """

        if self._crt_file is None:
            raise ValueError('certificate {0} not set'.format(
                self._crt_file,
            ))

        if os.path.isfile(self._crt_file):
            with open(self._crt_file, 'rb') as fp:
                crt = crypto.load_certificate(
                    crypto.FILETYPE_PEM,
                    fp.read()
                )
        else:
            crt = None
        return crt

    def enddate(self) -> int:
        """Calculate the difference in days until the enddate.

        :returns: Number of days.
        :rtype: `int`
        """

        if self._crt is None:
            return 0

        notafter = str(self._crt.get_notAfter())
        notafter = notafter.replace("b'", "").replace("'", "")

        try:
            expire_date = datetime.strptime(notafter, "%Y%m%d%H%M%SZ")
        except:
            return 0

        expire_in = expire_date - datetime.now()
        if expire_in.days > 0:
            return expire_in.days
        else:
            return 0

    def get_common_name(self) -> str:
        """Get subject common name from certificate signing request.

        :returns: Subject string.
        :rtype: `str`.
        """

        return self._csr.get_subject().commonName

    def get_alternative_names(self) -> list:
        """Get Subject Alternative Names from certificate.

        :returns: A list of Subject Alternative Names.
        :rtype: `list` of `unicode`.
        """

        return crypto_util._pyopenssl_cert_or_req_san(self._csr)
