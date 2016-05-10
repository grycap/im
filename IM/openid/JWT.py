import json
import base64
import re

_b64_re = re.compile(b"^[A-Za-z0-9_-]*$")

def add_padding(b):
    # add padding chars
    m = len(b) % 4
    if m == 1:
        # NOTE: for some reason b64decode raises *TypeError* if the
        # padding is incorrect.
        raise Exception(b, "incorrect padding")
    elif m == 2:
        b += b"=="
    elif m == 3:
        b += b"="
    return b

def b64d(b):
    """Decode some base64-encoded bytes.

    Raises BadSyntax if the string contains invalid characters or padding.

    :param b: bytes
    """

    cb = b.rstrip(b"=")  # shouldn't but there you are

    # Python's base64 functions ignore invalid characters, so we need to
    # check for them explicitly.
    if not _b64_re.match(cb):
        raise Exception(cb, "base64-encoded data contains illegal characters")

    if cb == b:
        b = add_padding(b)

    return base64.urlsafe_b64decode(b)

class JWT(object):
    def __init__(self):
        self.headers = {'alg': None}
        self.b64part = ['eyJhbGciOm51bGx9']
        self.part = ['{"alg":null}']

    def unpack(self, token):
        """
        Unpacks a JWT into its parts and base64 decodes the parts
        individually

        :param token: The JWT
        """
        try:
            token = token.encode("utf-8")
        except UnicodeDecodeError:
            pass

        part = tuple(token.split(b"."))
        self.b64part = part
        self.part = [b64d(p) for p in part]
        self.headers = json.loads(self.part[0].decode())
        return self

    def get_info(self, token):
        """
        Unpacks a JWT into its parts and base64 decodes the parts
        individually, returning the part 1 json decoded.

        :param token: The JWT
        """
        self.unpack(token)
        return json.loads(self.part[1])
