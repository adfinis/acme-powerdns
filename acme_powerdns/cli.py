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
from acme import challenges
from acme_powerdns import acme_client
from acme_powerdns import dns
from acme_powerdns import settings


def main():
    logging.basicConfig(level=logging.INFO)

    ac = acme_client.Client(
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
    account_key = ac.create_account(
        settings.ACCOUNT_KEY,
    )

    authzrs = list()
    for domain in settings.FQDN:
        # request a challenge
        authzr, challb = ac.request_domain_challenges(
            domain,
            challenges.DNS01,
        )
        authzrs.append(authzr)

        chall_response, chall_validation = challb.response_and_validation(
            account_key
        )

        # create dns record
        nsupdate.create(
            settings.SERVER,
            settings.ZONE,
            '_acme-challenge.{}'.format(domain),
            chall_validation,
        )

        try:
            ac.answer_challenge(challb, chall_response)
        except BaseException as e:
            logging.error(e)

        # delete dns record
        nsupdate.delete(
            settings.SERVER,
            settings.ZONE,
            '_acme-challenge.{}'.format(domain),
            chall_validation,
        )

    (cert, chain) = ac.request_cert(settings.CSR, authzrs)
    with open(settings.CRT, 'wb') as f:
        for crt in cert:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, crt))

    sys.exit(0)


if __name__ == '__main__':
    main()
