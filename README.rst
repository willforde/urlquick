========
Urlquick
========
A light-weight http client with requests like interface. Featuring persistent connections and caching support.

This project was originally created for use by Kodi add-ons, but has grown into something more.
I found that while requests has a very nice interface, there was a noticeable lag when importing the library.
The other option available is to use urllib2 but then you loose the benefit of persistent
connections that requests have. Hence the reason for this project.

All GET, HEAD and POST requests are cached locally for a period of 4 hours. When the cache expires, conditional headers
are added to a new request e.g. 'Etag' and 'Last-modified'. Then if the response returns a 304 Not-Modified response,
the cache is reused, saving having to re-download the content body.

------------

TODO:
-----

- Create tests
- Create a mock of httplib for offline testing
- Create documentation
