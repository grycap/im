import time
import json
import requests
import logging
import os


class ResponseIM:

    def __init__(self, statuscode, info):
        self.statuscode = statuscode
        self.info = info


def read_file_as_string(file_name):
    tests_path = os.path.dirname(os.path.abspath(__file__))
    abs_file_path = os.path.join(tests_path, file_name)
    return open(abs_file_path, 'r').read()


def update_imheaders(tokenstring):

    vlines = read_file_as_string('./conf/authorizationHeader.txt')
    authoriz = ''
    i = 0

    for line in vlines.split("\n"):
        i += 1
        line = line.rstrip()
        if tokenstring:
            authoriz += line + " token = " + tokenstring
        else:
            authoriz += line + " username = mon_user; password = mon_test_1X"

        if len(vlines) > i:
            authoriz += "\\n  "

    authoriz += " ;"

    UPD_HEADERS = {
        "Content-Type": "text/plain",
        "Accept": "application/json",
        "Authorization": authoriz
    }

    return UPD_HEADERS


def requestIM(method, url, data, headers, verify):

    if method == 'POST':
        try:
            r = requests.post(url, data=data, headers=headers, verify=verify)
            rq = ResponseIM(r.status_code, r.text)
        except requests.ConnectionError as e:
            logging.error("* ConnectionError exception at method " + method + ": " + str(e))
            rq = ResponseIM(111, e)

    elif method == 'GET':
        try:
            r = requests.get(url, data=data, headers=headers, verify=verify)
            rq = ResponseIM(r.status_code, r.text)
        except requests.ConnectionError as e:
            logging.error("* ConnectionError exception at method " + method + ": " + str(e))
            rq = ResponseIM(111, e)
        except requests.exceptions.InvalidHeader as e:
            logging.error("* InvalidHeader exception: ---> " + str(e) + " <--")
            rq = ResponseIM(111, e)

    elif method == 'PUT':
        try:
            r = requests.put(url, data=data, headers=headers, verify=verify)
            rq = ResponseIM(r.status_code, r.text)
        except requests.ConnectionError as e:
            logging.error("* ConnectionError exception at method " + method + ": " + str(e))
            rq = ResponseIM(111, e)
        except requests.exceptions.InvalidHeader as e:
            logging.error("* InvalidHeader exception: ---> " + str(e) + " <--")
            rq = ResponseIM(111, e)

    elif method == 'DELETE':
        try:
            r = requests.delete(url, data=data, headers=headers, verify=verify)
            rq = ResponseIM(r.status_code, r.text)
        except requests.ConnectionError as e:
            logging.error("* ConnectionError exception at method " + method + ": " + str(e))
            rq = ResponseIM(111, e)
        except requests.exceptions.InvalidHeader as e:
            logging.error("* InvalidHeader exception: ---> " + str(e) + " <--")
            rq = ResponseIM(111, e)

    return rq


def list_infrastructure(url, imheaders):

    r = requestIM('GET', url + "/infrastructures", {}, imheaders, False)

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


def create_infrastructure(url, imheaders):
    # hold on a little bit for the IM to get ready
    time.sleep(3)
    radl = read_file_as_string('./conf/test.radl')
    r = requestIM('POST', url + "/infrastructures", radl, imheaders, False)

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


def start_infrastructure(imheaders, uri_inf_id):

    time.sleep(3)
    r = requestIM('PUT', uri_inf_id + '/start', {}, imheaders, False)

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


def create_vm(IMHEADERS, uri_inf_id):

    time.sleep(3)
    radl = read_file_as_string('./conf/test.radl')
    r = requestIM('POST', uri_inf_id, radl, IMHEADERS, False)

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


def delete_infrastructure(imheaders, uri_inf_id):

    time.sleep(3)
    r = requestIM('DELETE', uri_inf_id, {}, imheaders, False)

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
