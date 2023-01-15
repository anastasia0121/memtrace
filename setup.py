#! /usr/bin/env python3

import os
import re
import sys
import sysconfig
import platform
import subprocess

from setuptools import setup, Extension, find_packages
from setuptools.command.build_ext import build_ext
from setuptools.dist import Distribution


class BinaryDistribution(Distribution):
    def is_pure(self):
        return False


class CMakeExtension(Extension):
    def __init__(self, name, sourcedir=""):
        Extension.__init__(self, name, sources=[])
        self.sourcedir = os.path.abspath(sourcedir)


class CMakeBuild(build_ext):
    def run(self):
        try:
            subprocess.check_call(["cmake", "--version"])
        except OSError:
            raise RuntimeError(
                "cmake does not install. Extentions: ".join(e.name for e in self.extensions))

        for ext in self.extensions:
            self.build_extension(ext)

    def build_extension(self, ext):
        # 'build_temp': 'build/temp.linux-x86_64-3.10', 
        # 'inplace': 1, 
        # 'package': None,

        cfg = "Debug" if self.debug else "Release"
        cmake_args = ["-DPYTHON_EXECUTABLE=" + sys.executable, '-DCMAKE_BUILD_TYPE=' + cfg]
        build_args = ['--config', cfg, '--', '-j2']

        if not os.path.exists(self.build_temp):
            os.makedirs(self.build_temp)

        subprocess.check_call(['cmake', ext.sourcedir] + cmake_args,
                              cwd=self.build_temp, env=os.environ)
        subprocess.check_call(['cmake', '--build', '.'] + build_args,
                              cwd=self.build_temp)
        print()

setup(
    name="memtrace",
    version="1.0",
    author="Anastasia Kondrateva",
    author_email="anastasia012120@gmail.com",
    description="Tool to trace allocated memory in c++ applications.",
    url="https://github.com/anastasia0121",
    install_requires=open(os.path.dirname(os.path.realpath(__file__)) + "/requirements.txt").read(),
    long_description=open(os.path.dirname(os.path.realpath(__file__)) + "/README.md").read(),
    long_description_content_type="markdown",
    packages=find_packages(),
    package_dir={"":"."},
    ext_modules=[CMakeExtension("libmemtrace")],
    license="MIT",
    platforms="linux-x86_64",
    cmdclass=dict(build_ext=CMakeBuild),
    zip_safe=False,
    include_package_data=True,
    distclass=BinaryDistribution,
)
