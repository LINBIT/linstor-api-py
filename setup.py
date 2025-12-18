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

import re
import subprocess
from setuptools import setup
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
    packages=['linstor'],
    # package_data={},
    cmdclass={
        "build_py": BuildPyCommand
    },
)
