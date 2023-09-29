#!/usr/bin/env python

import argparse
import logging
import logging.handlers
import sys
import requests
import json
from deep_instinct_connector import DeepInstinctConnector

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import utils

VALID_ACTIONS = ["isolate_machine", "unisolate_machine"]

class DeepInstinctResponder():
    def __init__(self, host, api_token, lgr=None, **kwargs):
        self._host = host
        self._api_token = utils.aella_decode(utils.COLLECTOR_SECRET, api_token)
        if lgr is None:
            self._logger = utils.action_agent_logger
        else:
            self._logger = lgr
        self._connector = DeepInstinctConnector(host_name=self._host, api_token=self._api_token, logger=self._logger)

    def prepare(self, action_name, settings, source):
        """
        Function used by Stellar Cyber for threat hunting integration
        :param action_name: str: function to call
        :param settings: obj: additional info that may be needed
        :param source: obj: threat hunting results
        :return: list of obj: list of parameters to call <action_name> with.
            Each object in the list represents one function call, so a list
            of length n will result in n separate calls
        """
        params = []
        return params

    def isolate_machine(self, device_id, **kwargs):
        try:
            results = self._connector.isolate(device_id)
            if results.status_code == 200:
                if not self._logger is None:
                    self._logger.info("isolate_machine: " + str(device_id))
                return {"result_msg": "isolate_machine: " + str(device_id) + " successfully " + results.text}
            else:
                if self._logger:
                    self._logger.error("Fail to isolate machine: {0}, status code {1}".format(results.text, results.status_code))
                raise Exception("Fail to isolate machine: {0}, status code {1}".format(str(device_id), results.status_code))
        except Exception as e:
            if self._logger:
                self._logger.error("Exception in isolate_machine: {}".format(str(e)))
            raise Exception("Exception in isolate_machine: {}".format(str(e)))

    def unisolate_machine(self, device_id, **kwargs):
        try:
            results = self._connector.unisolate(device_id)
            if results.status_code == 200:
                if not self._logger is None:
                    self._logger.info("unisolate_machine: " + str(device_id))
                return {"result_msg": "unisolate_machine: " + str(device_id) + " successfully " + results.text}
            else:
                if self._logger:
                    self._logger.error("Fail to unisolate machine: {0}, status code {1}".format(results.text, results.status_code))
                raise Exception("Fail to unisolate machine: {0}, status code {1}".format(str(device_id), results.status_code))
        except Exception as e:
            if self._logger:
                self._logger.error("Exception in unisolate_machine: {}".format(str(e)))
            raise Exception("Exception in unisolate_machine: {}".format(str(e)))

    def test_connection(self, **kwargs):
        try:
            results = self._connector.test_connection()
            if results.status_code == 200:
                return utils.create_response("Cybereason", 200, "")
            else:
                return utils.create_response("Cybereason", results.status_code, "Fail to authenticate Deep Instinct")
        except Exception as e:
            return utils.create_response("Cybereason", 400, str(e))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--host', action='store', dest='host', required=True,
        help="Host")    
    parser.add_argument('-t', '--token', action='store', dest='token', required=True,
        help="API Token")
    parser.add_argument('-a', '--action', action='store', dest='action', required=True,
        choices=VALID_ACTIONS,
        help="The action to take: {}".format(", ".join(VALID_ACTIONS)))
    parser.add_argument('-d', '--device_id', action='store', dest='device_id', required=True,
        help="The Device ID")

    results = parser.parse_args()
    responder = DeepInstinctResponder(results.host, results.token)

    if results.action == "isolate_machine":
        action_fn = responder.isolate_machine
    elif results.action == "unisolate_machine": 
        action_fn = responder.unisolate_machine

    result = action_fn(results.device_id)
    print(str(result))