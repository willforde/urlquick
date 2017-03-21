import urlquick

def test_urlquick():
    _url = u"https://en.wikipedia.org/wiki/\u0278"
    ret = urlquick.get(_url, allow_redirects=True)
    print("Status =", ret.status_code)
    print("Reason =", ret.reason)
    print("Encoding =", ret.encoding)
    print("Elapsed =", ret.elapsed)
    print("Data =", repr(ret.text[:200]))
    print("Data Len", len(ret.text))
    print("Cookie =", ret.cookies)
    print("===")

    for i in ret.headers.items():
        print(i)
