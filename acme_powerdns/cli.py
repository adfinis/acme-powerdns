#!/usr/bin/env python

import logging
import sys
from OpenSSL import crypto
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
    account_key = ac.create_account(settings.ACCOUNT_KEY)

    authzrs = list()
    for domain in settings.FQDN:
        # request a challenge
        authzr, authzr_response = ac.request_challenges(domain)
        authzrs.append(authzr)

        challb = ac.filter_challenges(authzr, authzr_response)
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
