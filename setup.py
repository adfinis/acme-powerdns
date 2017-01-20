from codecs import open as codecs_open
from setuptools import setup, find_packages


# Get the long description from the relevant file
with codecs_open('README.rst', encoding='utf-8') as f:
    LONG_DESCRIPTION = f.read()


setup(
    name='acme_powerdns',
    version='0.1',
    description='ACME client with DNS challenge response with PowerDNS',
    long_description=LONG_DESCRIPTION,
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6'
    ],
    keywords='acme letsencrypt powerdns',
    author='Adfinis SyGroup AG',
    author_email='https://adfinis-sygroup.ch/',
    url='https://github.com/adfinis-sygroup/acme-powerdns',
    license='GPLv3',
    packages=find_packages(),
    install_requires=[
        'acme',
        'dnspython',
    ],
    extras_require={
        'test': ['pytest'],
    },
    entry_points="""
    [console_scripts]
    acme-powerdns=acme_powerdns.cli:main
    """
)
