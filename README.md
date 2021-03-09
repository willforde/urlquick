# Urlquick II: Requests, but with caching

[![PyPI](https://img.shields.io/pypi/v/urlquick)](https://pypi.org/project/urlquick/)
[![Documentation Status](https://readthedocs.org/projects/urlquick/badge/?version=stable)](https://urlquick.readthedocs.io/en/stable/?badge=stable)
[![Build Status](https://www.travis-ci.com/willforde/urlquick.svg?branch=master)](https://www.travis-ci.com/willforde/urlquick)
[![Coverage Status](https://coveralls.io/repos/github/willforde/urlquick/badge.svg?branch=master)](https://coveralls.io/github/willforde/urlquick?branch=master)
[![Maintainability](https://api.codeclimate.com/v1/badges/4f622589a4b8e24ac996/maintainability)](https://codeclimate.com/github/willforde/urlquick/maintainability)


## Urlquick II
Urlquick2 is a wrapper for requests that add's support for http caching.
It act's just like requests but with a few extra parameters and features.
'Requests' itself is left untouched.

All GET, HEAD and POST requests are cached locally for a period of 4 hours, this can be changed. When the cache expires,
conditional headers are added to any new request e.g. "Etag" and "Last-modified". Then if the server
returns a 304 Not-Modified response, the cache is used, saving having to re-download the content body.


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
Stable
```console
$ pip install urlquick
```

## Full Documentation over at [Read the Docs](https://urlquick.readthedocs.io)
