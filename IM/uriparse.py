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
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


def uriparse(url, scheme='', allow_fragments=1):
    """Parse a URL into 6 components:
    <scheme>://<netloc>/<path>;<params>?<query>#<fragment>
    Return a 6-tuple: (scheme, netloc, path, params, query, fragment).
    Note that we don't break the components up in smaller bits
    (e.g. netloc is a single string) and we don't expand % escapes."""
    tuple = urisplit(url, scheme, allow_fragments)
    scheme, netloc, url, query, fragment = tuple
    if ';' in url:
        url, params = _splitparams(url)
    else:
        params = ''
    return scheme, netloc, url, params, query, fragment


def _splitparams(url):
    if '/' in url:
        i = url.find(';', url.rfind('/'))
        if i < 0:
            return url, ''
    else:
        i = url.find(';')
    return url[:i], url[i + 1:]


def urisplit(url, scheme='', allow_fragments=1):
    """Parse a URL into 5 components:
    <scheme>://<netloc>/<path>?<query>#<fragment>
    Return a 5-tuple: (scheme, netloc, path, query, fragment).
    Note that we don't break the components up in smaller bits
    (e.g. netloc is a single string) and we don't expand % escapes."""
    netloc = query = fragment = ''
    i = url.find(':')
    if i > 0:
        scheme = url[:i].lower()
        url = url[i + 1:]
        if url[:2] == '//':
            netloc, url = _splitnetloc(url, 2)
        if allow_fragments and '#' in url:
            url, fragment = url.split('#', 1)
        if '?' in url:
            url, query = url.split('?', 1)
        tuple = scheme, netloc, url, query, fragment
        return tuple

    if url[:2] == '//':
        netloc, url = _splitnetloc(url, 2)
    if allow_fragments and '#' in url:
        url, fragment = url.split('#', 1)
    if '?' in url:
        url, query = url.split('?', 1)
    tuple = scheme, netloc, url, query, fragment

    return tuple


def _splitnetloc(url, start=0):
    for char in '/?#':  # the order is important!
        delim = url.find(char, start)
        if delim >= 0:
            break
    else:
        delim = len(url)
    return url[start:delim], url[delim:]
