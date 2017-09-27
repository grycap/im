# IM - Infrastructure Manager
# Copyright (C) 2011 - GRyCAP - Universitat Politecnica de Valencia
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public Licenslast_updatee for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
Class to unpack the JWT IAM tokens
"""
import json
import base64
import re


class JWT(object):

    @staticmethod
    def b64d(b):
        """Decode some base64-encoded bytes.

        Raises Exception if the string contains invalid characters or padding.

        :param b: bytes
        """

        cb = b.rstrip(b"=")  # shouldn't but there you are

        # Python's base64 functions ignore invalid characters, so we need to
        # check for them explicitly.
        b64_re = re.compile(b"^[A-Za-z0-9_-]*$")
        if not b64_re.match(cb):
            raise Exception(cb, "base64-encoded data contains illegal characters")

        if cb == b:
            b = JWT.add_padding(b)

        return base64.urlsafe_b64decode(b)

    @staticmethod
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

    @staticmethod
    def get_info(token):
        """
        Unpacks a JWT into its parts and base64 decodes the parts
        individually, returning the part 1 json decoded, where the
        token info is stored.

        :param token: The JWT token
        """
        part = tuple(token.encode("utf-8").split(b"."))
        part = [JWT.b64d(p) for p in part]
        return json.loads(part[1].decode("utf-8"))
