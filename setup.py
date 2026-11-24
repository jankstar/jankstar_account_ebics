#!/usr/bin/env python3
# This file is part of the account_ebics module for Tryton.
# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
# rebuild: 'python setup.py sdist bdist_wheel'
import io
import os
import re
from configparser import ConfigParser

from setuptools import find_packages, setup  # type: ignore

MODULE2PREFIX = {}


def read(fname):
    content = io.open(
        os.path.join(os.path.dirname(__file__), fname),
        'r', encoding='utf-8').read()
    content = re.sub(
        r'(?m)^\.\. toctree::\r?\n((^$|^\s.*$)\r?\n)*', '', content)
    return content


def get_require_version(name):
    require = '%s >= %s.%s, < %s.%s'
    require %= (name, major_version, minor_version,
        major_version, minor_version + 1)
    return require


config = ConfigParser()
config.read_file(open(os.path.join(os.path.dirname(__file__), 'tryton.cfg')))
info = dict(config.items('tryton'))
for key in ('depends', 'extras_depend', 'xml'):
    if key in info:
        info[key] = info[key].strip().splitlines()
version = info.get('version', '0.0.1')
major_version, minor_version, _ = version.split('.', 2)
major_version = int(major_version)
minor_version = int(minor_version)
name = 'jankstar_account_ebics'

requires = []
for dep in info.get('depends', []):
    if not re.match(r'(ir|res)(\W|$)', dep):
        prefix = MODULE2PREFIX.get(dep, 'trytond')
        requires.append(get_require_version('%s_%s' % (prefix, dep)))
requires.append(get_require_version('trytond'))
# Protocol layer: keys, signatures, encryption (installed: 50.0.2)
requires.append('cryptography >= 50.0')

tests_require = []

setup(name=name,
    version=version,
    description='EBICS 3.0 (H005) bank interface for Tryton',
    long_description=read('README.rst'),
    author='jankstar',
    author_email='jankstar.berlin@gmail.com',
    url='www.jankstar.de',
    project_urls={
        'Source': 'https://github.com/jankstar/jankstar_account_ebics',
        'Documentation':
            'https://github.com/jankstar/jankstar_account_ebics/tree/main/doc',
        },
    keywords='Tryton EBICS bank statement',
    package_dir={'trytond.modules.account_ebics': '.'},
    packages=(
        ['trytond.modules.account_ebics']
        + ['trytond.modules.account_ebics.%s' % p
            for p in find_packages()]
        ),
    package_data={
        'trytond.modules.account_ebics': (info.get('xml', [])
            + ['tryton.cfg', 'view/*/*.xml', 'locale/*.po',
                'report/*.fodt', 'report/*.odt', 'icons/*.svg',
                'tests/*.rst', 'tests/*.xml', 'tests/*.json',
                'tests/data/*']),
        },
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Environment :: Plugins',
        'Framework :: Tryton',
        'Intended Audience :: Developers',
        'Intended Audience :: Financial and Insurance Industry',
        'License :: OSI Approved :: '
        'GNU General Public License v3 or later (GPLv3+)',
        'Natural Language :: English',
        'Natural Language :: German',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3.13',
        'Programming Language :: Python :: Implementation :: CPython',
        'Topic :: Office/Business',
        'Topic :: Office/Business :: Financial :: Accounting',
        ],
    license='GPL-3',
    python_requires='>=3.10',
    install_requires=requires,
    extras_require={
        'test': tests_require,
        },
    zip_safe=False,
    entry_points="""
    [trytond.modules]
    account_ebics = trytond.modules.account_ebics
    """,  # noqa: E501
    )
