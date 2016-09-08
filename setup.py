#!/usr/bin/env python
# -*- coding: utf-8 -*-


try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = history_file.read()

requirements = [
    # TODO: put package requirements here
]

test_requirements = [
    # TODO: put package test requirements here
]

setup(
    name='parsec',
    version='0.1.0',
    description="Secure cloud framework",
    long_description=readme + '\n\n' + history,
    author="Scille SAS.",
    author_email='emmanuel.leblond@gmail.com',
    url='https://github.com/Scille/parsec',
    packages=[
        'parsec',
    ],
    package_dir={'parsec':
                 'parsec'},
    include_package_data=True,
    install_requires=requirements,
    license="GPLv3",
    zip_safe=False,
    keywords='parsec',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],
    test_suite='tests',
    tests_require=test_requirements
)
