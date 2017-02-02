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
from datetime import datetime

from acme import crypto_util
from OpenSSL import crypto


class CertHandling:
    """Handle one certificate.
    Load and handle certificate and signing request.

    :ivar string csr: certificate signing request filename.
    :ivar string crt: certificate filename.
    """

    def __init__(self, csr, crt):
        self._csr_file = csr
        self._crt_file = crt
        self._csr = self.load_cert_req()
        self._crt = self.load_cert()

    def load_cert_req(self) -> crypto.X509Req:
        """Load the certificate request of this object.

        :returns: Certificate request.
        :rtype: :class:`OpenSSL.crypto.X509Req`
        """

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

    def get_alternative_names(self) -> list:
        """Get Subject Alternative Names from certificate.

        :returns: A list of Subject Alternative Names.
        :rtype: `list` of `unicode`.
        """

        return crypto_util._pyopenssl_cert_or_req_san(self._csr)
