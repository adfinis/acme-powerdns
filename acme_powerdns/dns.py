#!/usr/bin/env python

from dns import query
from dns import tsigkeyring
from dns import update
from dns import tsig


class NSUpdate:

    def __init__(self, logging, keyid, key, algo):
        self._logging = logging
        self._algo = algo
        self._keyid = keyid
        self._key = key
        self._keyring = tsigkeyring.from_text({
            keyid: key
        })

    def create(self, server, zone, record, rdata):
        self._logging.info(
            'add record [{}] in zone [{}] on [{}] with rdata [{}]'.format(
                record,
                zone,
                server,
                rdata,
            )
        )
        data = update.Update(
            zone,
            keyname = self._keyid,
            keyring = self._keyring,
            keyalgorithm = getattr(tsig, self._algo),
        )
        data.add(
            '{}.'.format(record),
            60,
            'TXT',
            rdata,
        )
        response = query.udp(
            data,
            server,
        )
        return response

    def delete(self, server, zone, record, rdata):
        self._logging.info(
            'delete record [{}] in zone [{}] on [{}]'.format(
                record,
                zone,
                server,
            )
        )
        data = update.Update(
            zone,
            keyname = self._keyid,
            keyring = self._keyring,
            keyalgorithm = getattr(tsig, self._algo),
        )
        data.delete(
            '{}.'.format(record),
            'TXT',
            rdata,
        )
        response = query.udp(
            data,
            server,
        )
        return response
