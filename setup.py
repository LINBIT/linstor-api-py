#!/usr/bin/env python2
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
import subprocess
from setuptools import setup, Command
from setuptools.command import build_py


def get_version():
    from linstor import VERSION
    return VERSION


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


class GenerateProtoSourcesCommand(build_py.build_py):
    """Generates python protobuf messages"""

    def run(self):
        subprocess.check_call(["make", "gensrc"])
        build_py.build_py.run(self)


setup(
    name="linstor",
    version='0.2.0',
    description="Linstor python api",
    long_description="Python linstor api interface",
    url='https://www.linbit.com',
    author="Robert Altnoeder <robert.altnoeder@linbit.com>, Roland Kammerer <roland.kammerer@linbit.com>" +
           ", Rene Peinthor <rene.peinthor@linbit.com>",
    author_email="roland.kammerer@linbit.com",
    maintainer="LINBIT HA-Solutions GmbH",
    maintainer_email="drbd-user@lists.linbit.com",
    license="GPLv3",
    install_requires=['protobuf'],
    packages=['linstor', 'linstor/proto', 'linstor/proto/eventdata', 'linstor/protobuf_to_dict'],
    # package_data={},
    cmdclass={
        "build_py": GenerateProtoSourcesCommand,
        "versionup2date": CheckUpToDate
    },
    test_suite="tests"
)
