#! /usr/bin/env python
import time
import os
import argparse
import sys
import json
import requests
import logging
from logging.handlers import RotatingFileHandler

try:
    # To avoid annoying InsecureRequestWarning messages in some Connectors
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except Exception:
    pass


def read_file_as_string(file_name):
    tests_path = os.path.dirname(os.path.abspath(__file__))
    abs_file_path = os.path.join(tests_path, file_name)
    return open(abs_file_path, 'r').read()


class ResponseIM:

    def __init__(self, statuscode, info):
        self.statuscode = statuscode
        self.info = info


class IM:

    @staticmethod
    def update_imheaders(tokenstring=None):

        vlines = read_file_as_string('./conf/authorizationHeader.txt')

        authoriz = ''
        i = 0

        for line in vlines.split("\n"):
            i += 1
            line = line.strip()
            if line:
                if tokenstring:
                    authoriz += line + " token = " + tokenstring + ";"
                else:
                    authoriz += line + " username = mon_user; password = mon_test_1X;"

                if len(vlines) > i:
                    authoriz += "\\n"

        UPD_HEADERS = {
            "Content-Type": "text/plain",
            "Accept": "application/json",
            "Authorization": authoriz
        }

        return UPD_HEADERS

    @staticmethod
    def requestIM(method, url, data, headers, verify):
        try:
            logging.debug(method, url, data, headers)
            r = requests.request(method, url, data=data, headers=headers, verify=verify)
            rq = ResponseIM(r.status_code, r.text)
        except requests.ConnectionError as e:
            logging.error("* ConnectionError exception at method " + method + ": " + str(e))
            rq = ResponseIM(111, e)
        except requests.exceptions.InvalidHeader as e:
            logging.error("* InvalidHeader exception: ---> " + str(e) + " <--")
            rq = ResponseIM(111, e)

        return rq

    @staticmethod
    def list_infrastructure(url, imheaders):

        r = IM.requestIM('GET', url + "/infrastructures", {}, imheaders, False)

        if r.statuscode == 200:
            ret = ResponseIM(r.statuscode, 'list method OK')
        elif r.statuscode == 111:
            ret = ResponseIM(r.statuscode, r.info)
        else:
            try:
                json_data = json.loads(r.info)
                ret = ResponseIM(r.statuscode, json_data['message'])
            except ValueError as e:
                ret = ResponseIM(111, e)
                logging.error("list_infrastructure" + str(e))

        return ret

    @staticmethod
    def create_infrastructure(url, imheaders):
        # hold on a little bit for the IM to get ready
        time.sleep(3)
        radl = read_file_as_string('./conf/test.radl')
        r = IM.requestIM('POST', url + "/infrastructures", radl, imheaders, False)

        if r.statuscode == 200:
            try:
                json_data = json.loads(r.info)
                ret = ResponseIM(r.statuscode, json_data['uri'])
            except ValueError as e:
                ret = ResponseIM(111, e)
                logging.error(e)

        elif r.statuscode == 111:
            ret = ResponseIM(r.statuscode, r.info)
        else:
            try:
                json_data = json.loads(r.info)
                ret = ResponseIM(r.statuscode, json_data['message'])
            except ValueError as e:
                ret = ResponseIM(111, e)
                logging.error("create_infrastructure" + str(e))
        return ret

    @staticmethod
    def start_infrastructure(imheaders, uri_inf_id):

        time.sleep(3)
        r = IM.requestIM('PUT', uri_inf_id + '/start', {}, imheaders, False)

        if r.statuscode == 200:
            ret = ResponseIM(r.statuscode, 'start method OK')
        elif r.statuscode == 111:
            ret = ResponseIM(r.statuscode, r.info)
        else:
            try:
                json_data = json.loads(r.info)
                ret = ResponseIM(r.statuscode, json_data['message'])
            except ValueError as e:
                ret = ResponseIM(111, e)
                logging.error("start_infrastructure" + str(e))

        return ret

    @staticmethod
    def create_vm(IMHEADERS, uri_inf_id):

        time.sleep(3)
        radl = read_file_as_string('./conf/test.radl')
        r = IM.requestIM('POST', uri_inf_id, radl, IMHEADERS, False)

        if r.statuscode == 200:
            ret = ResponseIM(r.statuscode, 'Creation of VM is OK')
        elif r.statuscode == 111:
            ret = ResponseIM(r.statuscode, r.info)
        else:
            try:
                json_data = json.loads(r.info)
                ret = ResponseIM(r.statuscode, json_data['message'])
            except ValueError as e:
                ret = ResponseIM(111, e)
                logging.error("create_vm" + str(e))

        return ret

    @staticmethod
    def delete_infrastructure(imheaders, uri_inf_id):

        time.sleep(3)
        r = IM.requestIM('DELETE', uri_inf_id, {}, imheaders, False)

        if r.statuscode == 200:
            ret = ResponseIM(r.statuscode, 'delete_infrastructure is OK')
        elif r.statuscode == 111:
            ret = ResponseIM(r.statuscode, r.info)
        else:
            try:
                json_data = json.loads(r.info)
                ret = ResponseIM(r.statuscode, json_data['message'])
            except ValueError as e:
                ret = ResponseIM(111, e)
                logging.error("delete_infrastructure" + str(e))

        return ret


def log_setup(loglevel):
    tests_path = os.path.dirname(os.path.abspath(__file__))
    log_handler = RotatingFileHandler(tests_path + '/log/probeim.log', maxBytes=1048576, backupCount=5)

    formatter = logging.Formatter('%(asctime)s - %(levelname)s: %(message)s -- %(filename)s::%(funcName)s'
                                  ' line     %(lineno)d', '%b %d %H:%M:%S')
    formatter.converter = time.gmtime
    log_handler.setFormatter(formatter)
    logger = logging.getLogger()
    logger.addHandler(log_handler)

    if loglevel == 'ERROR':
        lvl = 40
    elif loglevel == 'WARNING':
        lvl = 30
    elif loglevel == 'INFO':
        lvl = 20
    elif loglevel == 'DEBUG':
        lvl = 10
    else:
        lvl = 30

    logger.setLevel(lvl)


def main(url, token):

    imheaders = IM.update_imheaders(token)

    # CREATE INFRASTRUCTURE
    ci = IM.create_infrastructure(url, imheaders)
    url_infr = ci.info

    if ci.statuscode == 401:
        return False, "Authentication Error"

    elif ci.statuscode == 111:
        logging.error("Could NOT start CREATION INFRASTRUCTURE process: %s" % ci.info)
        return False, str(ci.info)

    elif ci.statuscode == 200:
        # START INFRASTRUCTUREWARNING
        si = IM.start_infrastructure(imheaders, url_infr)

        if si.statuscode == 200:

            time.sleep(1)
            # LIST INFRASTRUCTURE
            li = IM.list_infrastructure(url, imheaders)

            if li.statuscode == 200:
                # CREATE VM
                cv = IM.create_vm(imheaders, url_infr)

                if cv.statuscode == 200:
                    # DELETE INFRASTRUCTURE
                    di = IM.delete_infrastructure(imheaders, url_infr)

                    if di.statuscode == 200:
                        logging.info("All operations have been completed successfully.")
                        return True, "All operations have been completed successfully."
                    else:
                        logging.error("Infrastructure could NOT be DELETED")
                        return False, str(di.info)

                else:
                    logging.error("VM could NOT be CREATED")
                    return False, str(cv.info)
            else:
                logging.error("Infrastructure could NOT be LISTED")
                return False, str(li.info)
        else:
            logging.error("Infrastructure could NOT be STARTED")
            return False, str(si.info)
    else:
        logging.error("Infrastructure could NOT be CREATED")
        return False, str(ci.info)

# ----- RUN -----------------------------------------------------------------


if __name__ == '__main__':

    log_setup('INFO')

    logging.info("Initializing --------------")

    # Parse input arguments
    parser = argparse.ArgumentParser(description='Monitorize IM operations.')
    parser.add_argument('-u', '--url', help='URL of the IM REST API endpoint', default="http://localhost:8800")
    parser.add_argument('-t', '--token', help='STRING of access token', default=None)
    args = parser.parse_args()

    logging.info("Initializing --------------")

    succcess, msg = main(args.url, args.token)
    if succcess:
        print("All operations have been completed successfully.")
        sys.exit(0)
    else:
        print(msg)
        sys.exit(2)
