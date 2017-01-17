#!/usr/bin/env python

import logging
import sys
from acme_powerdns import acme_client
from acme_powerdns import settings


logging.basicConfig(level=logging.INFO)


def main():
    logging.basicConfig(level=logging.INFO)
    ac = acme_client.Client(logging)
    ac.create_account(settings.BITS)
    authzr, authzr_response = ac.request_challenges(settings.DOMAIN)
    token = ac.filter_challenges(authzr, authzr_response)
    logging.info(token)
    sys.exit(0)


if __name__ == '__main__':
    main()
