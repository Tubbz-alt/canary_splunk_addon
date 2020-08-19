import operator
import sys
import six
from six.moves import zip


try:
    from collections import MutableMapping, Sequence  # noqa
except ImportError:
    from collections.abc import MutableMapping, Sequence  # noqa

PY3 = sys.version_info[0] >= 3
PY26 = sys.version_info[:2] == (2, 6)

if PY3:
    zip = zip
    from functools import lru_cache
    from io import StringIO
    from urllib.parse import (
        unquote, urljoin, urlunsplit, SplitResult, urlsplit as _urlsplit
    )
    from urllib.request import urlopen
    str_types = str,
    int_types = int,
    iteritems = operator.methodcaller("items")
else:
      # noqa
    from StringIO import StringIO
    from six.moves.urllib.parse import (
        urljoin, urlunsplit, SplitResult, urlsplit as _urlsplit # noqa
    )
    from six.moves.urllib.parse import unquote  # noqa
    from six.moves.urllib.request import urlopen  # noqa
    str_types = six.string_types
    int_types = int, long
    iteritems = operator.methodcaller("iteritems")

    if PY26:
        from repoze.lru import lru_cache
    else:
        from functools32 import lru_cache


# On python < 3.3 fragments are not handled properly with unknown schemes
def urlsplit(url):
    scheme, netloc, path, query, fragment = _urlsplit(url)
    if "#" in path:
        path, fragment = path.split("#", 1)
    return SplitResult(scheme, netloc, path, query, fragment)


def urldefrag(url):
    if "#" in url:
        s, n, p, q, frag = urlsplit(url)
        defrag = urlunsplit((s, n, p, q, ''))
    else:
        defrag = url
        frag = ''
    return defrag, frag


# flake8: noqa
