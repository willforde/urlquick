from setuptools import setup
from codecs import open
from os import path
import re

try:
    import configparser
except ImportError:
    # noinspection PyUnresolvedReferences, PyPep8Naming
    import ConfigParser as configparser

# Path to local directory
here = path.abspath(path.dirname(__file__))


def readfile(filename):  # type: (str) -> str
    """Get the long description from the README file"""
    readme_file = path.join(here, filename)
    with open(readme_file, "r", encoding="utf-8") as stream:
        return stream.read()


def extract_variable(filename, variable):  # type: (str, str) -> str
    """Extract the version number from a python file that contains the '__version__' variable."""
    with open(filename, "r", encoding="utf8") as stream:
        search_refind = r'{} = ["\'](\d+\.\d+\.\d+)["\']'.format(variable)
        verdata = re.search(search_refind, stream.read())
        if verdata:
            return verdata.group(1)
        else:
            raise RuntimeError("Unable to extract version number")


def extract_config_value(filename, section):
    """Extract values from a ini config file."""
    config = configparser.ConfigParser()
    config.read(filename)
    return config.options(section) if config.has_section(section) else []


setup(
    name='urlquick',
    version=extract_variable('urlquick.py', '__version__'),
    description="Requests wrapper that add's support for HTTP caching. It act's just "
                "like requests but with a few extra parameters and features.",
    long_description=readfile('README.md'),
    long_description_content_type='text/markdown',
    python_requires='>=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*, !=3.5.*',
    install_requires=extract_config_value("Pipfile", "packages"),
    extras_require={"dev": extract_config_value("Pipfile", "dev-packages")},
    keywords='python http caching requests',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: Implementation :: CPython',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
    url='https://github.com/willforde/urlquick',
    platforms=['OS Independent'],
    author='William Forde',
    author_email='willforde@gmail.com',
    license='MIT',
    py_modules=['urlquick'],
    zip_safe=False,
    project_urls={
        'Documentation': 'http://urlquick.readthedocs.io/en/stable/?badge=stable',
        'Source': 'https://github.com/willforde/urlquick',
    },
)
