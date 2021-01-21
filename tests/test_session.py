import urlquick
import pytest


@pytest.mark.parametrize("strings", [b"test.string.bytes", "test.string.str", u"test.string.unicode"])
def test_to_bytes_string(strings):
    value = urlquick.to_bytes_string(strings)
    assert isinstance(value, bytes)
