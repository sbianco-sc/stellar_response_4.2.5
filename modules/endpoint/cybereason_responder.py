#!/usr/bin/env python

import argparse
import logging
import logging.handlers
import sys
import requests
import json
from cybereason_connector import CybereasonConnector
import firewall.common as common

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import utils


class CybereasonResponder():
    def __init__(self, username, password, server, port, lgr=None, **kwargs):
        self._username = username
        self._password = utils.aella_decode(utils.COLLECTOR_SECRET, password)
        self._server = server
        self._port = port
        self._logger = lgr
        self._connector = CybereasonConnector(username=self._username, password=self._password, server=self._server, port=self._port, logger=self._logger)

    def prepare(self, action_name, settings, source):
        return common.prepare(action_name, settings, source)

    def isolate_machine(self, sensor_id, malop_id = None, **kwargs):
        try:
            session = self._connector.login()
            results = self._connector.isolate(session, sensor_id, malop_id)
            if results.status_code == 200:
                res = results.json()
                self._logger.info("isolate_machine: " + str(res))
                return {"result_msg": "isolate_machine: " + str(res)}
            else:
                self._logger.error("Fail to isolate machine: {0}, status code {1}".format(str(res), results.status_code))
                raise Exception("Fail to isolate machine: {0}, status code {1}".format(str(res), results.status_code))
        except Exception as e:
            self._logger.error("Exception in isolate_machine: {}".format(str(e)))
            raise Exception("Exception in isolate_machine: {}".format(str(e)))

    def unisolate_machine(self, sensor_id, malop_id = None, **kwargs):
        try:
            session = self._connector.login()
            results = self._connector.unisolate(session, sensor_id, malop_id)
            if results.status_code == 200:
                res = results.json()
                self._logger.info("unisolate_machine: " + str(res))
                return {"result_msg": "unisolate_machine: " + str(res)}
            else:
                self._logger.error("Fail to unisolate machine: {0}, status code {1}".format(str(res), results.status_code))
                raise Exception("Fail to unisolate machine: {0}, status code {1}".format(str(res), results.status_code))
        except Exception as e:
            self._logger.error("Exception in unisolate_machine: {}".format(str(e)))
            raise Exception("Exception in unisolate_machine: {}".format(str(e)))

    def test_connection(self, **kwargs):
        try:
            session = self._connector.login()
            results = self._connector.test_connection(session)
            if results.status_code == 200:
                your_response = results.json()
                if your_response["status"] == "SUCCESS":
                    return utils.create_response("Cybereason", 200, "")
                else:
                    return utils.create_response("Cybereason", 400, "Cannot get json from cybereason api")
            else:
                return utils.create_response("Cybereason", results.status_code, str(results.content))
        except Exception as e:
            return utils.create_response("Cybereason", 400, str(e))

if __name__ == '__main__':
    LOG_FILENAME = 'logs/cybereason_collector.log'
    MODULE = 'cybereason_collector'
    FORMAT = '%(asctime)-15s|%(name)s|%(levelname)s|%(message)s'
    logger = logging.getLogger(MODULE)
    logger.setLevel(logging.INFO)

    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--action', action='store', dest='action', required=True,
        help='The action to take, can be isolate_machine or unisolate_machine')
    parser.add_argument('-p', '--password', action='store', dest='password', required=True,
        help='The password to login Cybereason API')
    parser.add_argument('-s', '--server', action='store', dest='server', required=True,
        help='The server of Cybereason API')
    parser.add_argument('-t', '--port', action='store', dest='port', required=True,
        help='The port of Cybereason API')
    parser.add_argument('-u', '--username', action='store', dest='username', required=True,
        help='The username to login Cybereason API')
    parser.add_argument('-r', '--sensor_id', action='store', dest='sensor_id', required=False,
        help='The sensor_id as input of action')
    parser.add_argument('-r', '--malop_id', action='store', dest='malop_id', required=False,
        help='The malop_id as input of action')

    results = parser.parse_args()

    responder = CybereasonResponder(results.username, results.password, results.server, results.port, lgr=logger)

    if results.action == "isolate_machine":
        try:
            res = responder.isolate_machine(results.sensor_id, results.malop_id)
        except Exception as e:
            sys.stderr.write("Failed to isolate_machine: {} \n".format(e))
            sys.exit(1)
    elif results.action == "unisolate_machine":
        try:
            res = responder.unisolate_machine(results.sensor_id, results.malop_id)
        except Exception as e:
            sys.stderr.write("Failed to unisolate_machine: {}\n".format(e))
            sys.exit(1)
    if res != "Succeeded":
        sys.stderr.write("Failed to perform {}: {}\n".format(results.action, res))
        sys.exit(1)
