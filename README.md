Urlquick II: Requests, but with caching.
========================================

Urlquick II
-----------
Urlquick2 is a wrapper for requests that add's support for http caching.
It act's just like requests but with a few extra parameters and features.
'Requests' itself is left untouched.

All GET, HEAD and POST requests are cached locally for a period of 4 hours, this can be changed. When the cache expires,
conditional headers are added to any new request e.g. "Etag" and "Last-modified". Then if the server
returns a 304 Not-Modified response, the cache is used, saving having to re-download the content body.


Usage
-----

```pycon
>>> import urlquick

# Make a request.
>>> r = urlquick.get('https://httpbin.org/ip')

# View response data.
>>> r.status_code
200
>>> r.json()
{'ip': '172.69.48.124'}
```


Install
-------
Stable
```bash
pip install urlquick
```

Unstable
```bash
pip install git+https://github.com/willforde/urlquick.git
```
