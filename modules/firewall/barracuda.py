#!/usr/bin/env python

import argparse
import base64
import logging
import logging.handlers
import random
import sys
import os
import requests
import re
import time
import json

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import pdb

import firewall.common as common

import utils


STELLAR_COMMENTS = "StellarCyber Automation"

class BarracudaConnector():
    def __init__(self, api_token, device, port, src_object, dst_object, lgr=None, **kwargs):
        self._api_token = utils.aella_decode(utils.COLLECTOR_SECRET, api_token)
        self._device = device
        self._port = port
        self._src_object = src_object
        self._dst_object = dst_object
        self._logger = lgr
        self._base_url = "https://{}:{}/rest/config/v1/forwarding-firewall/objects/networks".format(device, port)
        self._token = None
        self._headers = {"Content-Type": "application/json",
                         "x-api-token": self._api_token}

    def prepare(self, action_name, settings, source):
        return common.prepare(action_name, settings, source)


    def block_ip(self, cidr, direction, **kwargs):
        return common.block_ip_wrapper(self, cidr, direction, **kwargs)

    def _block_ip(self, cidr, egress):
        if egress:
            network_obj = self._dst_object
        else:
            network_obj = self._src_object
        payload = {
            "entry": {
                "comment": "Stellar-blocked address",
                "ip": cidr
            }
        }
        url = "{}/{}/included".format(self._base_url, network_obj)
        try:
            response = requests.post(
                url,
                data=json.dumps(payload),
                headers=self._headers,
                params=None, timeout=120,
                verify=False)
            if response.status_code > 299:
                if response.content:
                    res = json.loads(response.content)
                    msg = res.get("message")
                    if "already exists" not in msg:
                        return msg
                else:
                    return "API call returns {}".format(response.status_code)
        except Exception as e:
            return str(e)
        return common.SUCCESS

    def unblock_ip(self, cidr, direction, **kwargs):
        return common.unblock_ip_wrapper(self, cidr, direction, **kwargs)

    def _unblock_ip(self, cidr, egress):
        if egress:
            network_obj = self._dst_object
        else:
            network_obj = self._src_object
        addr = cidr.split('/')[0]
        url = "{}/{}/included/{}".format(self._base_url, network_obj, addr)
        try:
            response = requests.delete(
                url, headers=self._headers, timeout=120, verify=False)
            if response.status_code > 299:
                if response.content:
                    res = json.loads(response.content)
                    msg = res.get("message")
                    if msg != "Entry not found in network object":
                        return msg
                else:
                    return "API call returns {}".format(response.status_code)
            else:
                if response.content:
                    res = json.loads(response.content)
                    code = res.get("code", 200)
                    if code > 299:
                        return "API call returns {}: {}".format(code, res.get("message", ""))
        except Exception as e:
            return str(e)
        return common.SUCCESS

    def _test_get_url(self, url):
        try:
            response = requests.get(
                url, headers=self._headers, timeout=120,
                params=None, data=None, verify=False)
            if response.status_code > 299:
                if response.content:
                    res = json.loads(response.content)
                    msg = res.get("message")
                    return response.status_code, msg
                else:
                    return response.status_code, "API call returns {}".format(response.status_code)
            return 200, common.SUCCESS
        except Exception as e:
            self._logger.error("Failed to test url: %s", e)
            return 500, str(e)

    def _test_connection(self, **kwargs):
        try:
            run_on = kwargs.get("run_on", "dp")
            if run_on != "" and run_on != "dp":
                return self.notify_ds_to_test_connection(run_on)
            # Test basic connection
            test_url = self._base_url
            res, msg = self._test_get_url(test_url)
            if res != 200:
                return utils.create_response("Barracuda", res, msg)
            # Test src object
            test_url = "{}/{}".format(self._base_url, self._src_object)
            res, msg = self._test_get_url(test_url)
            if res != 200:
                return utils.create_response("Barracuda", res, "Source object test failed: {}".format(msg))
            # Test dst object
            test_url = "{}/{}".format(self._base_url, self._dst_object)
            res, msg = self._test_get_url(test_url)
            if res != 200:
                return utils.create_response("Barracuda", res, "Destination object test failed: {}".format(msg))
        except Exception as e:
            self._logger.error("Failed to connect to firewall: %s", e)
            return utils.create_response("Barracuda", 0, str(e))
        return utils.create_response("Barracuda", 200, common.SUCCESS)

    def notify_ds_to_test_connection(self, run_on):
        """
        Notify DS to perform the connection test
        :param run_on: str: the engid of sensor to run the test
        :return: str: the test results
        """
        script_path = "/opt/aelladata/connector/modules/firewall/barracuda.py"
        api_token = utils.aella_encode(utils.COLLECTOR_SECRET, self._api_token)
        command = "export PYTHONPATH={}; python {} -a test -v {} -p {} -k \"{}\" -s \"{}\" -d \"{}\"".format(
                  utils.PYTHONPATH, script_path, self._device, self._port, api_token,
                  self._src_object, self._dst_object)
        status_code, error_msg = utils.execute_action_on_ds(run_on, command, retry_count=1)
        if status_code > 0:
            return utils.error_msg_process("Barracuda", error_msg)
        return  utils.create_response("Barracuda", 200, common.SUCCESS)

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
        script_path = "/opt/aelladata/connector/modules/firewall/barracuda.py"
        api_token = utils.aella_encode(utils.COLLECTOR_SECRET, self._api_token)
        command = "export PYTHONPATH={}; python {} -a {} -v {} -p {} -k \"{}\" -s \"{}\" -d \"{}\" -c {} -e {}".format(
                  utils.PYTHONPATH, script_path, action, self._device, self._port, api_token,
                  self._src_object, self._dst_object, cidr, egress)
        status_code, error_msg = utils.execute_action_on_ds(run_on, command)
        if status_code > 0:
            return "Firewall action on sensor fail with status code {}: {}".format(status_code, error_msg)
        return common.SUCCESS

if __name__ == '__main__':
    LOG_FILENAME = "/var/log/aella/firewall_action.log"
    FORMAT = "%(asctime)-15s|%(name)s|%(levelname)s|%(message)s"
    logger = logging.getLogger("barracuda_fw")
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter(FORMAT)
    handler = logging.handlers.WatchedFileHandler(LOG_FILENAME)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--action', action='store', dest='action', required=True,
        help='The action to take, can be block or unblock ip')
    parser.add_argument('-v', '--device', action='store', dest='device', required=True,
        help='The host address of the firewall')
    parser.add_argument('-k', '--key', action='store', dest='api_token', required=True,
        help='The username to login firewall')
    parser.add_argument('-p', '--port', action='store', dest='port', required=True,
        help='The port of firewall API')
    parser.add_argument('-s', '--src_object', action='store', dest='src_object', required=True,
        help='The name for source IP group')
    parser.add_argument('-d', '--dst_object', action='store', dest='dst_object', required=True,
        help='The name for destination IP group')
    parser.add_argument('-c', '--cidr', action='store', dest='cidr', required=False,
        help='The CIDR as input of action')
    parser.add_argument('-e', '--egress', action='store', dest='egress', required=False,
        help='True if direction is egress')

    results = parser.parse_args()

    firewall_connector = BarracudaConnector(results.api_token, results.device,
                                            results.port, results.src_object,
                                            results.dst_object,
                                            lgr=logger)

    if results.action == "test":
        try:
            res = firewall_connector.test_connection_on_ds()
        except Exception as e:
            sys.stderr.write(utils.ERROR_HEAD + str(e) + utils.ERROR_END)
            sys.exit(1)
        print res
        sys.exit()

    egress = False
    if str(results.egress).lower() == "true":
        egress = True

    if results.action == "block_ip":
        try:
            res = firewall_connector._block_ip(results.cidr, egress)
        except Exception as e:
            sys.stderr.write("Failed to block ip: {} \n".format(e))
            sys.exit(1)
    elif results.action == "unblock_ip":
        try:
            res = firewall_connector._unblock_ip(results.cidr, egress)
        except Exception as e:
            sys.stderr.write("Failed to unblock ip: {}\n".format(e))
            sys.exit(1)
    if res != "Success":
        sys.stderr.write("Failed to perform {}: {}\n".format(results.action, res))
        sys.exit(1)
