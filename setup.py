#!/usr/bin/env python3

from setuptools import setup, find_packages  # Always prefer setuptools over distutils
from src.ndn import __version__

requirements = ['cryptography >= 2.7', 'pycryptodomex >= 3.8.2']
setup(
    name='ndn-python',
    version=__version__,
    description='An NDN client library with AsyncIO support in Python 3',
    url='https://github.com/zjkmxy/python-ndn',
    maintainer='Xinyu Ma',
    maintainer_email='xinyu.ma@cs.ucla.edu',
    license='LGPLv3',
    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'Development Status :: 3 - Alpha',

        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries',

        'License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)',

        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8'
    ],

    keywords='NDN',

    packages=find_packages('src'),
    package_dir={'': 'src'},

    install_requires=requirements
)
