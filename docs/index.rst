.. urlquick documentation master file, created by
   sphinx-quickstart on Fri Apr  7 17:02:08 2017.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to urlquick's documentation!
====================================

.. include::
    ../README.rst

.. seealso::
    More examples can be found in `examples.py`_.

API
===

.. autodata:: urlquick.MAX_AGE

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

.. _examples.py: https://github.com/willforde/python-htmlement/blob/master/examples.py