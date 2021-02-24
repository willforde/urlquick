import urlquick
import pytest
import shutil


@pytest.fixture(autouse=True, scope="module")
def clear_cache():
    shutil.rmtree(urlquick.CACHE_LOCATION, ignore_errors=True)


def test_xml(requests_mock):
    xml = b"""
    <note>
        <to>Tove</to>
        <from secure="true">Jani</from>
    </note>
    """
    requests_mock.get('https://www.test.com/cache/1', body=xml)
    ret = urlquick.get('https://www.test.com/cache/1')
    assert ret.content == xml
    tree = ret.xml()

    assert tree.find("to").text == "Tove"
    assert tree.find("from").text == "Jani"
    assert tree.find("from").get("secure") == "true"


def test_parse(requests_mock):
    html = b"""
    <html>
        <head>
            <title>Test title</title>
        </head>
        <body>
            <a href="https://google.ie">google</a>
        </body>
    </html>
    """
    requests_mock.get('https://www.test.com/cache/2', body=html)
    ret = urlquick.get('https://www.test.com/cache/2')
    assert ret.content == html
    tree = ret.parse()

    assert tree.find(".//title").text == "Test title"
    assert tree.find(".//a").text == "google"
    assert tree.find(".//a").get("href") == "https://google.ie"
