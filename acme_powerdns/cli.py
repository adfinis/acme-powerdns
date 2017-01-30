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

import logging
import sys
from OpenSSL import crypto
from acme_powerdns import cert_handling
from acme_powerdns import acme_client
from acme_powerdns import dns
from acme_powerdns import settings


def main():
    logging.basicConfig(level=logging.INFO)

    ac = acme_client.Account(
        logging,
        settings.DIRECTORY_URL,
    )
    nsupdate = dns.NSUpdate(
        logging,
        settings.TSIG_KEYID,
        settings.TSIG_KEY,
        settings.TSIG_ALGO,
    )

    # create an ACME account
    regr, acme, account_key = ac.create_account(
        settings.ACCOUNT_KEY,
    )

    # load CSRs
    csr = cert_handling.CertHandling(
        settings.CSR,
        settings.CRT,
    )

    fqdn = csr.get_alternative_names()

    logging.info('Certificate {} expires in {} days'.format(
        settings.CRT,
        csr.enddate(),
    ))
    if csr.enddate() < settings.DAYS:
        # create certificate request
        cr = acme_client.CertRequest(
            ac,
            acme,
            regr,
            account_key,
        )
        tokens = cr.request_tokens(
            fqdn,
            'dns01',
        )

        for token in tokens:
            # create dns record
            nsupdate.create(
                settings.SERVER,
                settings.ZONE,
                '_acme-challenge.{}'.format(token['domain']),
                token['validation'],
            )
        cert, chain = cr.answer_challenges(
            csr._csr,
        )
        with open(settings.CRT, 'wb') as f:
            for crt in cert:
                f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, crt))
        with open(settings.CHAIN, 'wb') as f:
            for crt in chain:
                f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, crt))

        for token in tokens:
            # delete dns record
            nsupdate.delete(
                settings.SERVER,
                settings.ZONE,
                '_acme-challenge.{}'.format(token['domain']),
                token['validation'],
            )

    sys.exit(0)


if __name__ == '__main__':
    main()
