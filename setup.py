#!/usr/bin/env python3

import io
import re
from setuptools import setup, find_packages  # Always prefer setuptools over distutils


with io.open("src/ndn/__init__.py", "rt", encoding="utf8") as f:
    version = re.search(r'__version__ = "(.*?)"', f.read()).group(1)


requirements = ['pycryptodomex >= 3.10.1', 'pygtrie >= 2.4.2']
setup(
    name='python-ndn',
    version=version,
    description='An NDN client library with AsyncIO support in Python 3',
    url='https://github.com/named-data/python-ndn',
    author='Xinyu Ma',
    author_email='ma.xinyu.26a@kyoto-u.jp',
    download_url='https://pypi.python.org/pypi/python-ndn',
    project_urls={
        "Bug Tracker": "https://github.com/named-data/python-ndn/issues",
        "Documentation": "https://python-ndn.readthedocs.io/",
        "Source Code": "https://github.com/named-data/python-ndn",
    },
    license='Apache License 2.0',
    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'Development Status :: 4 - Beta',

        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries',
        'Topic :: Internet',
        'Topic :: System :: Networking',

        'License :: OSI Approved :: Apache Software License',

        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],

    keywords='NDN',

    packages=find_packages('src'),
    package_dir={'': 'src'},

    install_requires=requirements,
    python_requires=">=3.7",
    extras_require={
        "dev":  ["pytest>=5.3.5", "pytest-cov>=2.8.1", "flake8>=3.7.9"],
    }
)
