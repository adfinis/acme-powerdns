#!/usr/bin/env python

import logging
import sys
from time import sleep
from acme_powerdns import acme_client
from acme_powerdns import dns
from acme_powerdns import settings


logging.basicConfig(level=logging.INFO)


def main():
    logging.basicConfig(level=logging.DEBUG)

    ac = acme_client.Client(logging)
    ac.create_account(settings.BITS)
    authzr, authzr_response = ac.request_challenges(settings.FQDN)
    token = ac.filter_challenges(authzr, authzr_response)
    logging.info(token)

    nsupdate = dns.NSUpdate(
        logging,
        settings.TSIG_KEYID,
        settings.TSIG_KEY,
        settings.TSIG_ALGO,
    )
    nsupdate.create(
        settings.SERVER,
        settings.ZONE,
        settings.FQDN,
        token,
    )
    sleep(5)
    nsupdate.delete(
        settings.SERVER,
        settings.ZONE,
        settings.FQDN,
        token,
    )

    sys.exit(0)


if __name__ == '__main__':
    main()
