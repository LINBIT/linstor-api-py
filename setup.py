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
import subprocess
import codecs
from setuptools import setup, Command
from setuptools.command.build_py import build_py


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
            with codecs.open("debian/changelog", encoding='utf8', errors='ignore') as f:
                firstline = f.readline()
                if version not in firstline:
                    # returning false is not promoted
                    sys.exit(1)
        except IOError:
            # probably a release tarball without the debian directory but with Makefile
            return True


class BuildPyCommand(build_py):
    """
    Run make gensrc before doing build.
    """
    def run(self):
        subprocess.check_call(["make", "gensrc"])
        build_py.run(self)


with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="python-linstor",
    version=get_version(),
    description="Linstor python api",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://www.linbit.com',
    project_urls={
        "Source Code": "https://github.com/LINBIT/linstor-api-py",
        "Documentation": "https://linbit.github.io/linstor-api-py",
    },
    author="Robert Altnoeder <robert.altnoeder@linbit.com>, Roland Kammerer <roland.kammerer@linbit.com>" +
           ", Rene Peinthor <rene.peinthor@linbit.com>, Moritz Wanzenboeck <moritz.wanzenboeck@linbit.com>",
    author_email="rene.peinthor@linbit.com",
    maintainer="LINBIT HA-Solutions GmbH",
    maintainer_email="drbd-user@lists.linbit.com",
    license="LGPLv3",
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],
    extras_require={
        ":python_version<'3'": ['enum34'],
    },
    packages=[
        'linstor'
    ],
    # package_data={},
    cmdclass={
        "versionup2date": CheckUpToDate,
        "build_py": BuildPyCommand
    },
    test_suite="linstor_tests"
)
