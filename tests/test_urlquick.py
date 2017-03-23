import unittest
import urlquick


class TestFromResponse(unittest.TestCase):
    start_time = urlquick.datetime.utcnow()
    class Request(object):
        def __init__(self):
            self.url = "https://httpbin.org/get"

    class Response(object):
        def __init__(self):
            self.status = 200
            self.reason = "OK"

        @staticmethod
        def getheaders():
            return {"conection": "close"}

        @staticmethod
        def read():
            return "data"

        def close(self):
            pass

    def test_from_cache(self):
        org_request = self.Request()
        response_data = {u"body": "data", u"headers": {"conection": "close"}, u"status": 200, u"reason": "OK"}
        resp = urlquick.Response.from_cache(response_data, org_request, self.start_time, [])
        self.assertTrue(resp.ok)

    def test_from_httplib(self):
        org_request = self.Request()
        response_data = self.Response()
        resp = urlquick.Response.from_httplib(response_data, org_request, self.start_time, [])
        self.assertTrue(resp.ok)


class TestResponse(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        urlquick.cache_cleanup(0)
        cls.resp = urlquick.request("GET", "https://httpbin.org/redirect/1", allow_redirects=False)

    def test_ok(self):
        self.assertTrue(self.resp.ok)

    def test_content(self):
        data = self.resp.content
        self.assertTrue(data)

    def test_text(self):
        data = self.resp.text
        self.assertTrue(data)

    def test_json(self):
        data = self.resp.json()
        self.assertTrue(isinstance(data, dict))

    def test_cookies(self):
        is_dict = isinstance(self.resp.cookies, dict)
        self.assertTrue(is_dict)

    def test_headers(self):
        is_dict = isinstance(self.resp.headers, urlquick.CaseInsensitiveDict)
        print(self.resp.headers)
        self.assertTrue(is_dict)

    def test_is_redirect(self):
        self.assertTrue(self.resp.is_redirect)



class TestMethods(unittest.TestCase):
    def setUp(self):
        urlquick.cache_cleanup(0)

    def tearDown(self):
        self.setUp()

    def test_request(self):
        resp = urlquick.request("GET", "https://httpbin.org/get")
        self.assertTrue(resp.ok)

    def test_get(self):
        resp = urlquick.get("https://httpbin.org/get")
        self.assertTrue(resp.ok)

    def test_head(self):
        resp = urlquick.head("https://httpbin.org/get")
        self.assertTrue(resp.ok)




#def test_urlquick():
#    _url = u"https://en.wikipedia.org/wiki/\u0278"
#    ret = urlquick.get(_url, allow_redirects=True)
#    print("Status =", ret.status_code)
#    print("Reason =", ret.reason)
#    print("Encoding =", ret.encoding)
#    print("Elapsed =", ret.elapsed)
#    print("Data =", repr(ret.text[:200]))
#    print("Data Len", len(ret.text))
#    print("Cookie =", ret.cookies)
#    print("===")
#
#    for i in ret.headers.items():
#        print(i)
