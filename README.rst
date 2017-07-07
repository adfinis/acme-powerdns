=============
ACME PowerDNS
=============

ACME PowerDNS is a `Let's Encrypt`_ client which makes the `ACME`_ challenge
response with PowerDNS. The big benefit of doing the ACME challenge response
over DNS is, that a central server can validate each certificate signing
request without access to the web-servers. There is also no modification
needed on the web-server.


REQUIREMENTS
============

* Python > 3.4


INSTALLATION
============
Clone the git repository to a local directory and install it inside a
virtualenv.

.. code-block:: bash

  mkdir -p /opt/acme-powerdns
  git clone https://github.com/adfinis-sygroup/acme-powerdns.git \
          /opt/acme-powerdns/acme-powerdns
  python3 -m venv --without-pip /opt/acme-powerdns/venv
  . /opt/acme-powerdns/venv/bin/activate
  python /opt/acme-powerdns/acme-powerdns/.testdata/get-pip.py

Create your certificate signing request directories and your directories for
the certificates.

.. code-block:: bash

  mkdir -p /etc/acme-powerdns/{csr,live}

Create your configuration file ``/etc/acme-powerdns/settings.yml``:

.. code-block:: yaml

  ---

  directory_url: 'https://acme-staging.api.letsencrypt.org/directory'
  days: 30
  updater: powerdns

  powerdns:
    server: 'https://api.example.com/'
    username: '<user>'
    password: '<password>'

  directories:
    - account_key: /etc/acme-powerdns/account.key
      csr:         /etc/acme-powerdns/csr
      cert:        /etc/acme-powerdns/live

  # vim: set ft=yaml sw=2 ts=2 et wrap tw=76:

Multiple accounts are possible with multiple directories. Each directory is
linked to one account.


USAGE
=====
The command ``acme-powerdns`` will do the following:

1. Search for files inside the csr directories (setting ``directories`` ->
   ``csr``).
#. Read those files as certificate signing request (be aware, no other
   files are allowed inside the csr directories).
#. Validate the dns entries of each csr.
#. Get certificates from acme directory (e.g. `Let's Encrypt`_).
#. Store certificates to cert directories (setting ``directories`` ->
   ``cert``).


LICENSE
=======

GNU GENERAL PUBLIC LICENSE Version 3

See the `LICENSE`_ file.

.. _Let's Encrypt: https://letsencrypt.org/
.. _ACME: https://tools.ietf.org/html/draft-ietf-acme-acme-05
.. _LICENSE: LICENSE


.. vim: set ft=rst sw=2 ts=2 et wrap tw=76:
