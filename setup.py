from setuptools import setup
from codecs import open as _open
from os import path


def readme():
    # Get the long description from the README file
    readme_file = path.join(path.abspath(path.dirname(__file__)), "README.rst")
    with _open(readme_file, "rb", encoding='utf-8') as opened_file:
        return opened_file.read()


setup(name='urlquick',
      version='0.1.1',
      description='A light-weight http client with requests like interface. Featuring persistent connections and caching support.',
      long_description=readme(),
      keywords='url lightweight caching http-client requests',
      classifiers=['Development Status :: 4 - Beta',
                   'Intended Audience :: Developers',
                   'License :: OSI Approved :: MIT License',
                   'Natural Language :: English',
                   'Operating System :: OS Independent',
                   'Programming Language :: Python :: 2',
                   'Programming Language :: Python :: 2.7',
                   'Programming Language :: Python :: 3',
                   'Programming Language :: Python :: 3.3',
                   'Programming Language :: Python :: 3.4',
                   'Programming Language :: Python :: 3.5',
                   'Programming Language :: Python :: 3.6',
                   'Topic :: Internet :: WWW/HTTP',
                   'Topic :: Software Development :: Libraries :: Python Modules'],
      url='https://github.com/willforde/urlquick',
      platforms=['OS Independent'],
      author='William Forde',
      author_email='willforde@gmail.com',
      license='MIT License',
      py_modules=['urlquick'])
