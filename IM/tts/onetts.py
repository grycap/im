'''
Created on 16 de jun. de 2016

@author: micafer
'''

try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse
from IM.tts.tts import TTSClient


class ONETTSClient():
    """
    Class to interact get user/password credentials to OpenNebula using the TTS
    """

    @staticmethod
    def get_auth_from_tts(tts_url, one_server, token, verify_ssl=False):
        """
        Get username and password from the TTS service
        """
        tts_uri = urlparse(tts_url)
        scheme = tts_uri[0]
        host = tts_uri[1]
        port = None
        if host.find(":") != -1:
            parts = host.split(":")
            host = parts[0]
            port = int(parts[1])

        ttsc = TTSClient(token, host, port, scheme, verify_ssl)

        success, svc = ttsc.find_service(one_server)
        if not success:
            raise Exception("Error getting credentials from TTS: %s" % svc)
        succes, cred = ttsc.request_credential(svc["id"])
        if succes:
            username = password = None
            for elem in cred['credential']['entries']:
                if elem['name'] == 'Username':
                    username = elem['value']
                elif elem['name'] == 'Password':
                    password = elem['value']
            return username, password
        else:
            raise Exception("Error getting credentials from TTS: %s" % cred)
