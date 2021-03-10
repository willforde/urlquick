# Urlquick II: Requests, but with caching

[![PyPI](https://img.shields.io/pypi/v/urlquick)](https://pypi.org/project/urlquick/)
[![Documentation Status](https://readthedocs.org/projects/urlquick/badge/?version=stable)](https://urlquick.readthedocs.io/en/stable/)
[![Build Status](https://www.travis-ci.com/willforde/urlquick.svg?branch=master)](https://www.travis-ci.com/willforde/urlquick)
[![Coverage Status](https://coveralls.io/repos/github/willforde/urlquick/badge.svg?branch=master)](https://coveralls.io/github/willforde/urlquick?branch=master)
[![Maintainability](https://api.codeclimate.com/v1/badges/4f622589a4b8e24ac996/maintainability)](https://codeclimate.com/github/willforde/urlquick/maintainability)


## Urlquick II
Urlquick 2 is a wrapper for requests that add's support for http caching.
It acts just like requests but with a few extra parameters and features.
'Requests' itself is left untouched.

All GET, HEAD and POST requests are cached locally for a period of 4 hours, this can be changed. When the cache expires,
conditional headers are added to any new request e.g. "Etag" and "Last-modified". Then if the server
returns a 304 Not-Modified response, the cache is used, saving having to re-download the content body.

All of Requests `get`, `head`, `post` and `request` functions/methods all get 2 extra optional parameters.
Both these 2 parameters can also be set on a session object too.
* `max_age`: Age the 'cache' can be before it’s considered stale.
* `raise_for_status`: Boolean that when set to `True` will call `resp.raise_for_status()` for you automatically.

The Requests response objects also gets too new methods.
* `parse()`: Parse’s “HTML” document into a element tree using HTMLement.
* `xml()`: Parse’s XML document into a element tree.

## Usage

```python
>>> import urlquick

# Make a simple request to check ip address.
>>> r = urlquick.get('https://httpbin.org/ip')
>>> r.json()
{'ip': '172.69.48.124'}

# Take note of the elapsed time.
>>> r.elapsed
0:00:00.556889

# Now make the same request but notice the much lower elapsed time.
>>> r = urlquick.get('https://httpbin.org/ip')
>>> r.elapsed
0:00:00.000184

# To change the max age for the cache to 1 hour.
>>> r = urlquick.get('https://httpbin.org/ip', max_age=60*60)
# max_age of -1 will disable the caching system.
# max_age of 0 will send conditional headers to check if content needs to be redownloaded.
```


## Install
Urlquick 2 officially supports Python 2.7 & 3.6+.
```console
$ pip install urlquick
```

## Full Documentation over at [Read the Docs](https://urlquick.readthedocs.io)

* [Requests Docs](https://requests.readthedocs.io/en/master/)
* [HTMLement Docs](https://python-htmlement.readthedocs.io/en/stable/?badge=stable)
* [Elementtree Docs](https://docs.python.org/3/library/xml.etree.elementtree.html)
