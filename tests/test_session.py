import urlquick


def test_get(requests_mock):
    requests_mock.get('https://www.test.com', text="data")
    ret = urlquick.get('https://www.test.com')
    print(type(ret.content), ret.content)
    assert ret.content == "data"
