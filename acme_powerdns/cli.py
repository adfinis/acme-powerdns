#!/usr/bin/env python

import logging
import sys
from acme_powerdns import acme_client
from acme_powerdns import dns
from acme_powerdns import settings


logging.basicConfig(level=logging.INFO)


def main():
    logging.basicConfig(level=logging.DEBUG)
    ac = acme_client.Client(logging)
    nsupdate = dns.NSUpdate(
        logging,
        settings.TSIG_KEYID,
        settings.TSIG_KEY,
        settings.TSIG_ALGO,
    )

    # create an ACME account
    ac.create_account(settings.ACCOUNT_KEY)

    # request a challenge
    authzr, authzr_response = ac.request_challenges(settings.FQDN)
    token = ac.filter_challenges(authzr, authzr_response)

    # create dns record
    nsupdate.create(
        settings.SERVER,
        settings.ZONE,
        settings.FQDN,
        token,
    )

    # delete dns record
    nsupdate.delete(
        settings.SERVER,
        settings.ZONE,
        settings.FQDN,
        token,
    )

    sys.exit(0)


if __name__ == '__main__':
    main()
