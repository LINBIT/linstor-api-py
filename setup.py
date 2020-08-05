#!/usr/bin/env python3
"""
    linstor - management of distributed DRBD9 resources
    Copyright (C) 2013 - 2018  LINBIT HA-Solutions GmbH
    Author: Robert Altnoeder, Philipp Reisner

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import os
import sys
import re
from setuptools import setup, Command


def get_version():
    """
    Function to parse the version string from the linstor/__init__.py.
    This was done to not rely on a working build, e.g. sometimes files were
    not yet generated and this made problems with importing.

    :return: semantic version string
    :rtype: str
    """
    with open('linstor/version.py') as linstor_init:
        for line in linstor_init:
            if line.startswith('VERSION'):
                m = re.search(r'"(.*)"', line)
                if m:
                    return m.group(1)
                else:
                    raise RuntimeError("Unable to parse version: " + line)
    raise RuntimeError("Unable to find version string.")


# used to overwrite version tag by internal build tools
# keep it, even if you don't understand it.
def get_setup_version():
    return get_version()


class CheckUpToDate(Command):
    description = "Check if version strings are up to date"
    user_options = []

    def initialize_options(self):
        self.cwd = None

    def finalize_options(self):
        self.cwd = os.getcwd()

    def run(self):
        version = get_version()
        try:
            with open("debian/changelog") as f:
                firstline = f.readline()
                if version not in firstline:
                    # returning false is not promoted
                    sys.exit(1)
        except IOError:
            # probably a release tarball without the debian directory but with Makefile
            return True


setup(
    name="python-linstor",
    version=get_version(),
    description="Linstor python api",
    long_description="Python linstor api interface",
    url='https://www.linbit.com',
    author="Robert Altnoeder <robert.altnoeder@linbit.com>, Roland Kammerer <roland.kammerer@linbit.com>" +
           ", Rene Peinthor <rene.peinthor@linbit.com>",
    author_email="roland.kammerer@linbit.com",
    maintainer="LINBIT HA-Solutions GmbH",
    maintainer_email="drbd-user@lists.linbit.com",
    license="GPLv3",
    extras_require={
        ":python_version<'3'": ['enum34'],
    },
    packages=[
        'linstor'
    ],
    # package_data={},
    cmdclass={
        "versionup2date": CheckUpToDate
    },
    test_suite="linstor_tests"
)
