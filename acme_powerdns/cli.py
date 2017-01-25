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
    regr, account_key = ac.create_account(
        settings.ACCOUNT_KEY,
    )

    # create certificate request
    cr = acme_client.CertRequest(
        ac,
        account_key,
    )
    tokens = cr.request_tokens(
        settings.FQDN,
    )

    for token in tokens:
        # create dns record
        nsupdate.create(
            settings.SERVER,
            settings.ZONE,
            '_acme-challenge.{}'.format(token['domain']),
            token['validation'],
        )

    cr.answer_challenges(
        settings.CSR,
        settings.CRT,
        settings.CHAIN,
    )

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
