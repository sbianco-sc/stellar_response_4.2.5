import argparse
import logging
import logging.handlers
import json
import requests
from bitdefender_connector import BitdefenderConnector

from requests.packages.urllib3.exceptions import InsecureRequestWarning
import utils

VALID_ACTIONS = ["isolate_machine", "unisolate_machine"]

class BitdefenderResponder():
    def __init__(self, access_url, api_key, lgr=None, **kwargs):
        self._access_url = access_url
        self._api_key = utils.aella_decode(utils.COLLECTOR_SECRET, api_key)
        if lgr is None:
            self._logger = utils.action_agent_logger
        else:
            self._logger = lgr
        self._connector = BitdefenderConnector(self._access_url, self._api_key, logger=self._logger)

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

    def isolate_machine(self, endpoint_id, **kwargs):
        try:
            results = self._connector.isolate_endpoint(endpoint_id)
            if results.status_code == 200:
                if not self._logger is None:
                    self._logger.info("isolate_machine: " + str(endpoint_id))
                if results.json().get("result", ""):
                    """
                    successful response example
                    {"id": "1","jsonrpc": "2.0","result": true}  
                    """
                    if self._logger:
                        self._logger.info("isolate_machine: {} {}".format(endpoint_id, results.json()["result"]))
                    return {"result_msg": "isolate_machine: " + str(endpoint_id) + " successfully "}
                elif not results.json().get("error") is None:
                    """
                    failed response example with 200 status code
                    {'id': '1', 'error': {'code': -32602, 'data': {'details': 'This endpoint cannot be restored from isolation. It is either not isolated, cannot be isolated or a isolation task is already in progress.'}, 'message': 'Invalid params'}, 'jsonrpc': '2.0'}
                    """
                    if self._logger:
                        self._logger.info("isolate_machine: {} {}".format(endpoint_id, results.json()["error"]["data"]["details"]))
                    try:
                        raise Exception("Failed to isolate_machine: {} {}".format(endpoint_id, results.json()["error"]["data"]["details"]))
                    except KeyError:
                        self._logger.error("isolate_machine has unsupported json data")
            else:
                if self._logger:
                    self._logger.error("Fail to isolate_machine: {0}, status code {1}".format(results.text, results.status_code))
                raise Exception("Fail to isolate_machine: {0}, status code {1}".format(str(endpoint_id), results.status_code))
        except Exception as e:
            self._logger.error("Exception in isolate_machine: {}".format(str(e)))
            raise Exception("Exception in isolate_machine: {}".format(str(e)))

    def unisolate_machine(self, endpoint_id, **kwargs):
        try:
            results = self._connector.unisolate_endpoint(endpoint_id)
            if results.status_code == 200:
                if not self._logger is None:
                    self._logger.info("unisolate_machine: " + str(endpoint_id))
                if results.json().get("result", ""):
                    if self._logger:
                        self._logger.info("unisolate_machine: {} {}".format(endpoint_id, results.json()["result"]))
                    return {"result_msg": "unisolate_machine: " + str(endpoint_id) + " successfully "}
                elif not results.json().get("error") is None:
                    if self._logger:
                        self._logger.info("unisolate_machine: {} {}".format(endpoint_id, results.json()["error"]["data"]["details"]))
                    try:
                        raise Exception("Failed to unisolate_machine: {} {}".format(endpoint_id, results.json()["error"]["data"]["details"]))
                    except KeyError:
                        self._logger.error("unisolate_machine has unsupported json data")
            else:
                if self._logger:
                    self._logger.error("Fail to unisolate_machine: {0}, status code {1}".format(results.text, results.status_code))
                raise Exception("Fail to unisolate_machine: {0}, status code {1}".format(str(endpoint_id), results.status_code))
        except Exception as e:
            self._logger.error("Exception in unisolate_machine: {}".format(str(e)))
            raise Exception("Exception in unisolate_machine: {}".format(str(e)))

    def test_connection(self, **kwargs):
        try:
            results = self._connector.test_connection()
            if self._logger:
                self._logger.info("resp {}".format(results.content))
            if results:
                return utils.create_response("Bitdefender", 200, "")
            else:
                return utils.create_response("Bitdefender", results.status_code, "Fail to authenticate Bitdefender")
        except Exception as e:
            return utils.create_response("Bitdefender", 400, str(e))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--access_url', action='store', dest='access_url', required=True,
        help="Access URL")    
    parser.add_argument('-t', '--api_key', action='store', dest='api_key', required=True,
        help="API Key")
    parser.add_argument('-a', '--action', action='store', dest='action', required=True,
        choices=VALID_ACTIONS,
        help="The action to take: {}".format(", ".join(VALID_ACTIONS)))
    parser.add_argument('-d', '--endpoint_id', action='store', dest='endpoint_id', required=True,
        help="Endpoint ID")

    results = parser.parse_args()
    responder = BitdefenderResponder(results.access_url, results.api_key)

    if results.action == "isolate_machine":
        action_fn = responder.isolate_machine
    elif results.action == "unisolate_machine": 
        action_fn = responder.unisolate_machine

    result = action_fn(results.endpoint_id)
    print(str(result))