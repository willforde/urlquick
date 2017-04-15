.. urlquick documentation master file, created by
   sphinx-quickstart on Fri Apr  7 17:02:08 2017.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to urlquick's documentation!
====================================

.. include::
    ../README.rst

API
===

.. autodata:: urlquick.MAX_AGE
.. data:: urlquick.CACHE_LOCATION

    Location to store the cache files. Defaults to current working directory. Will create a ".cache" subdirectory.

.. autofunction:: urlquick.request
.. autofunction:: urlquick.get
.. autofunction:: urlquick.head
.. autofunction:: urlquick.post
.. autofunction:: urlquick.put
.. autofunction:: urlquick.patch
.. autofunction:: urlquick.delete
.. autofunction:: urlquick.cache_cleanup

.. autoexception:: urlquick.UrlError
.. autoexception:: urlquick.Timeout
.. autoexception:: urlquick.MaxRedirects
.. autoexception:: urlquick.ContentError
.. autoexception:: urlquick.ConnError
.. autoexception:: urlquick.SSLError
.. autoexception:: urlquick.HTTPError

Session Class
-------------

.. autoclass:: urlquick.Session
    :members:

Response Object
---------------

.. autoclass:: urlquick.Response
    :members:

    .. autoattribute:: urlquick.Response.content
    .. autoattribute:: urlquick.Response.cookies
    .. autoattribute:: urlquick.Response.encoding
    .. autoattribute:: urlquick.Response.links
    .. autoattribute:: urlquick.Response.text

Request Object
--------------
.. autoclass:: urlquick.Request
    :members:

External Links
==============
Requests Quickstart: http://docs.python-requests.org/en/master/user/quickstart/

Bug Tracker: https://github.com/willforde/urlquick/issues