#!/usr/bin/env python

import argparse
import requests
import json
import logging
import logging.handlers
import sys

import utils
import firewall.common as common

class HanDreamnetSwitchConnector():

    def __init__(self, device, token, lgr=None, **kwargs):
        self._token = utils.aella_decode(utils.COLLECTOR_SECRET, token)
        self._device = device
        self._url = "https://{}/vnm/restapi/solutionlink/ip_block".format(self._device)
        self._headers = {"Content-Type": "application/json"}
        self._logger = lgr

    def prepare(self, action_name, settings, source):
        return common.prepare(action_name, settings, source)

    def block_ip(self, cidr, direction=None, **kwargs):
        return common.block_ip_wrapper(self, cidr, None, block_subnet=False, **kwargs)

    def unblock_ip(self, cidr, direction=None, **kwargs):
        return common.unblock_ip_wrapper(self, cidr, None, block_subnet=False, **kwargs)

    def _block_ip(self, cidr, egress=None):
        payload = {
            "authorization": {
                "token": self._token
            },
            "data": {
                "ip": cidr,
                "action": "drop"
            }
        }
        try:
            raw_response = requests.post(self._url, headers=self._headers, json=payload, verify=False)
            response = raw_response.json()
            data = response.get("data", {})
            result = data.get("result", "")
            if result == "suss":
                self._logger.info("Successfully blocked IP {0}".format(cidr))
                return common.SUCCESS
            else:
                reason = data.get("reason", "")
                self._logger.info("Failed to block IP {0}. Received {1}: {2}".format(cidr, result, reason))
                return "Failed to block IP {0}. Received {1}: {2}".format(cidr, result, reason)
        except Exception as e:
            self._logger.info("Failed to block IP {0} on HanDreamnet Switch: {1}".format(cidr, str(e)))
            if "Invalid control character" in str(e):
                return "Unknown IP information"
            return str(e)
 
    def _unblock_ip(self, cidr, egress=None):
        payload = {
            "authorization": {
                "token": self._token
            },
            "data": {
                "ip": cidr,
                "action": "free"
            }
        }
        try:
            raw_response = requests.post(self._url, headers=self._headers, json=payload, verify=False)
            response = raw_response.json()
            data = response.get("data", {})
            result = data.get("result", "")
            if result == "suss":
                self._logger.info("Successfully unblocked IP {0}".format(cidr))
                return common.SUCCESS
            else:
                reason = data.get("reason", "")
                self._logger.info("Failed to unblock IP {0}. Received {1}: {2}".format(cidr, result, reason))
                return "Failed to unblock IP {0}. Received {1}: {2}".format(cidr, result, reason)
        except Exception as e:
            self._logger.info("Failed to unblock IP {0} on HanDreamnet Switch: {1}".format(cidr, str(e)))
            return str(e)

    def _test_connection(self, **kwargs):
        try:
            run_on = kwargs.get("run_on", "dp")
            if run_on != "" and run_on != "dp":
                return self.notify_ds_to_test_connection(run_on)
            
            error_msg = ""
            if not self._token:
                error_msg += "Missing token info. "
            if not self._device:
                error_msg += "Missing device info. "
            if not self._token or not self._device:
                return utils.create_response("HanDreamnet", 400, error_msg)
            
            payload = {
                "authorization": {
                    "token": self._token
                },
                "data": {
                    "ip": "",
                    "action": "drop"
                }
            }
            raw_response = requests.post(self._url, headers=self._headers, json=payload, verify=False)
            self._logger.info("Response: {0}".format(raw_response.text))
            if raw_response.status_code == 200:
                if "Unknown" in raw_response.text:
                    return utils.create_response("HanDreamnet", 200, common.SUCCESS)
                elif "suss" in raw_response.text:
                    return utils.create_response("HanDreamnet", 200, common.SUCCESS)
                elif "Invalid token" in raw_response.text:
                    error_msg = "Invalid token"
                    return utils.create_response("HanDreamnet", 400, error_msg)
            
            error_msg = "Invalid credentials"
            return utils.create_response("HanDreamnet", 400, error_msg)             
    
        except Exception as e:
            self._logger.error("Failed to connect to HanDreamnet: %s", str(e))
            return utils.create_response("HanDreamnet", 0, str(e))

    def notify_ds_to_test_connection(self, run_on):
        """
        Notify DS to perform the connection test
        :param run_on: str: the engid of sensor to run the test
        :return: str: the test results
        """
        script_path = "/opt/aelladata/connector/modules/security_switch/handreamnet.py"
        token = utils.aella_encode(utils.COLLECTOR_SECRET, self._token)
        command = "export PYTHONPATH={}; python {} -a test -v {} -k \"{}\"".format(
                  utils.PYTHONPATH, script_path, self._device, token)
        status_code, error_msg = utils.execute_action_on_ds(run_on, command, retry_count=1)
        if status_code > 0:
            return utils.error_msg_process("HanDreamnet Switch", error_msg)
        return  utils.create_response("HanDreamnet Switch", 200, common.SUCCESS)

    def test_connection_on_ds(self):
        """
        This function will only be called on DS
        """
        kwargs = {}
        res = self._test_connection(**kwargs)
        if utils.test_response_success(res):
            return common.SUCCESS
        raise Exception(res)

    def _run_action_on_ds(self, action, cidr, egress, run_on):
        script_path = "/opt/aelladata/connector/modules/security_switch/handreamnet.py"
        token = utils.aella_encode(utils.COLLECTOR_SECRET, self._token)
        command = "export PYTHONPATH={}; python {} -a {} -v {} -k \"{}\" -c {}".format(
                  utils.PYTHONPATH, script_path, action, self._device, token, cidr)
        status_code, error_msg = utils.execute_action_on_ds(run_on, command)
        if status_code > 0:
            return "Security switch action on sensor fail with status code {}: {}".format(status_code, error_msg)
        return common.SUCCESS


if __name__ == '__main__':
    LOG_FILENAME = "/var/log/aella/firewall_action.log"
    FORMAT = "%(asctime)-15s|%(name)s|%(levelname)s|%(message)s"
    logger = logging.getLogger("handreamnetswitch_fw")
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter(FORMAT)
    handler = logging.handlers.WatchedFileHandler(LOG_FILENAME)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--action', action='store', dest='action', required=True,
        help='The action to take, can be block or unblock ip')
    parser.add_argument('-v', '--device', action='store', dest='device', required=True,
        help='The host address of the security switch')
    parser.add_argument('-k', '--key', action='store', dest='token', required=True,
        help='The token to authenticate security switch')
    parser.add_argument('-c', '--cidr', action='store', dest='cidr', required=False,
        help='The CIDR as input of action')

    results = parser.parse_args()

    switch_connector = HanDreamnetSwitchConnector(results.device, results.token, lgr=logger)

    if results.action == "test":
        try:
            res = switch_connector.test_connection_on_ds()
        except Exception as e:
            sys.stderr.write(utils.ERROR_HEAD + str(e) + utils.ERROR_END)
            sys.exit(1)
        print res
        sys.exit()

    if results.action == "block_ip":
        try:
            res = switch_connector._block_ip(results.cidr)
        except Exception as e:
            if "Invalid control character" in str(e):
                sys.stderr.write("Failed to block ip: Unknown IP information\n")
            else:
                sys.stderr.write("Failed to block ip: {} \n".format(e))
            sys.exit(1)
    elif results.action == "unblock_ip":
        try:
            res = switch_connector._unblock_ip(results.cidr)
        except Exception as e:
            sys.stderr.write("Failed to unblock ip: {}\n".format(e))
            sys.exit(1)
    if res != "Success":
        sys.stderr.write("Failed to perform {}: {}\n".format(results.action, res))
        sys.exit(1)
