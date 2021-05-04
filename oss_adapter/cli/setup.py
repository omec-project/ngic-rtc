from setuptools import setup
import os

VERSION = '0.0.0'


setup(
    name='c3pocli',
    packages=['c3pocli'],
    entry_points={
        'console_scripts': [
            'c3pocli = c3pocli.c3pocli:c3pocli'
        ]
    },
    install_requires=['Click', 'requests'],
    description='c3pocli util',
    version=VERSION,
    author='GSLab',
    author_email='javier.conde@gslab.com',
    keywords=['c3po', 'cli', 'gslab']
    )
