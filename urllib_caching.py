# Standard Library Imports
from functools import partial
import urllib2
import io

# Package imports
from urlquick import CacheAdapter as BaseCacheAdapter, py3

if py3:
    # noinspection PyUnresolvedReferences
    from http.client import HTTPMessage
else:
    # noinspection PyUnresolvedReferences
    from httplib import HTTPMessage


def register_opener():
    """Register the CacheAdapter as a global urllib2 opener"""
    cache_adapter = CacheAdapter()
    opener = urllib2.build_opener(cache_adapter)
    urllib2.install_opener(opener)


# noinspection PyClassHasNoInit
class CacheAdapter(urllib2.BaseHandler, BaseCacheAdapter):
    @staticmethod
    def callback(response):
        return response.info(), response.read(), response.code, response.msg

    @staticmethod
    def prepare_response(response, url):
        """ Prepare the cached response so that urllib can handle it """
        response.pop("strict")
        response.pop("version")
        return HTTPResponse(url=url, **response)

    def default_open(self, request):
        """
        Use the request information to check if it exists in the cache
        and return cached response if so. Else forward on the said request
        """
        url = request.get_full_url()
        cache_resp = self.cache_check(request.get_method(), url, request.data, request.headers)
        if cache_resp:
            return self.prepare_response(cache_resp, url)

    def http_response(self, request, response):
        """ Cache the response and return cached response """
        callback = partial(self.callback, response)
        cache_resp = self.handle_response(request.get_method(), response.code, callback)
        if cache_resp:
            response = self.prepare_response(cache_resp, request.get_full_url())

        return response

    # Redirect HTTPS Requests and Responses to HTTP
    https_request = http_request
    https_response = http_response


class HTTPResponse(urllib2.addinfourl):
    def __init__(self, body=None, headers=None, url=None, status=None, reason=None):
        # Convert headers to a httplib.HTTPMessage instance
        msg_headers = HTTPMessage(io.BytesIO(""))
        for key, value in headers.items():
            msg_headers.addheader(key.capitalize(), value)

        # Setup msg_headers
        msg_headers.encodingheader = msg_headers.getheader("Content-transfer-encoding")
        msg_headers.typeheader = msg_headers.getheader("Content-type")
        msg_headers.parsetype()
        msg_headers.parseplist()

        # Farward on the the source class
        urllib2.addinfourl.__init__(self, io.BytesIO(body), msg_headers, url, status)
        self.msg = reason
