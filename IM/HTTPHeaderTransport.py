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

from SOAPpy.version import __version__
from SOAPpy import *


class HTTPHeaderTransport(HTTPTransport):
    headers = {}

    # Need a Timeout someday?
    def call(self, addr, data, namespace, soapaction=None, encoding=None,
             http_proxy=None, config=Config):

        import httplib

        if not isinstance(addr, SOAPAddress):
            addr = SOAPAddress(addr, config)

        # Build a request
        if http_proxy:
            real_addr = http_proxy
            real_path = addr.proto + "://" + addr.host + addr.path
        else:
            real_addr = addr.host
            real_path = addr.path

        if addr.proto == 'httpg':
            from pyGlobus.io import GSIHTTP
            r = GSIHTTP(real_addr, tcpAttr=config.tcpAttr)
        elif addr.proto == 'https':
            r = httplib.HTTPS(real_addr)
        else:
            r = httplib.HTTP(real_addr)

        r.putrequest("POST", real_path)

        r.putheader("Host", addr.host)
        r.putheader("User-agent", SOAPUserAgent())
        t = 'text/xml'
        if encoding is not None:
            t += '; charset="%s"' % encoding
        r.putheader("Content-type", t)
        r.putheader("Content-length", str(len(data)))

        # if user is not a user:passwd format
        #    we'll receive a failure from the server. . .I guess (??)
        if addr.user is not None:
            val = base64.encodestring(addr.user)
            r.putheader('Authorization', 'Basic ' + val.replace('\012', ''))

        # This fixes sending either "" or "None"
        if soapaction is None or len(soapaction) == 0:
            r.putheader("SOAPAction", "")
        else:
            r.putheader("SOAPAction", '"%s"' % soapaction)

        for k, v in self.headers.iteritems():
            r.putheader(k, v)

        if config.dumpHeadersOut:
            s = 'Outgoing HTTP headers'
            debugHeader(s)
            print "POST %s %s" % (real_path, r._http_vsn_str)
            print "Host:", addr.host
            print "User-agent: SOAPpy " + __version__ + " (http://pywebsvcs.sf.net)"
            print "Content-type:", t
            print "Content-length:", len(data)
            print 'SOAPAction: "%s"' % soapaction
            for k, v in self.headers.iteritems():
                print k + ": " + v
            debugFooter(s)

        r.endheaders()

        if config.dumpSOAPOut:
            s = 'Outgoing SOAP'
            debugHeader(s)
            print data,
            if data[-1] != '\n':
                print
            debugFooter(s)

        # send the payload
        r.send(data)

        # read response line
        code, msg, headers = r.getreply()

        content_type = headers.get("content-type", "text/xml")
        content_length = headers.get("Content-length")
        if content_length is None:
            # No Content-Length provided; just read the whole socket
            # This won't work with HTTP/1.1 chunked encoding
            data = r.getfile().read()
            message_len = len(data)
        else:
            message_len = int(content_length)
            data = r.getfile().read(message_len)

        if(config.debug):
            print "code=", code
            print "msg=", msg
            print "headers=", headers
            print "content-type=", content_type
            print "data=", data

        if config.dumpHeadersIn:
            s = 'Incoming HTTP headers'
            debugHeader(s)
            if headers.headers:
                print "HTTP/1.? %d %s" % (code, msg)
                print "\n".join(map(lambda x: x.strip(), headers.headers))
            else:
                print "HTTP/0.9 %d %s" % (code, msg)
            debugFooter(s)

        def startswith(string, val):
            return string[0:len(val)] == val

        if code == 500 and not \
                (startswith(content_type, "text/xml") and message_len > 0):
            raise HTTPError(code, msg)

        if config.dumpSOAPIn:
            s = 'Incoming SOAP'
            debugHeader(s)
            print data,
            if (len(data) > 0) and (data[-1] != '\n'):
                print
            debugFooter(s)

        if code not in (200, 500):
            raise HTTPError(code, msg)

        # get the new namespace
        if namespace is None:
            new_ns = None
        else:
            new_ns = self.getNS(namespace, data)

        # return response payload
        return data, new_ns
