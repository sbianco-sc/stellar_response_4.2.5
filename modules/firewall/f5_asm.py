#!/usr/bin/env python

import argparse
import copy
import logging
import logging.handlers
import random
import sys
import os
import requests
import xmltodict
import re
import time
import json

import socket
import struct

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import firewall.common as common

import utils


class F5ASMConnector():
    def __init__(self, username, password, device, port, policy_name, lgr=None, **kwargs):
        self._api_username = username
        self._api_password = utils.aella_decode(utils.COLLECTOR_SECRET, password)
        self._device = device
        self._port = port
        self._policy_name = policy_name
        self._policy_id = None
        self._policy_full_path = None
        self._logger = lgr
        self._policy_url = "https://{}:{}/mgmt/tm/asm/policies".format(device, port)
        self._headers = {"Content-Type": "application/json"}
        self._auth_info = (self._api_username, self._api_password)


    def prepare(self, action_name, settings, source):
        return common.prepare(action_name, settings, source)


    def _get_request(self, url, params=None):
        try:
            response = requests.get(
                url, headers=self._headers,
                auth=self._auth_info,
                params=params, verify=False)
        except requests.RequestException as e:
            self._logger.error("Get F5 ASM request %s failed: %s", url, e)
            return None, "F5 ASM requests error: {}".format(e)
        if response.status_code == 200:
            res = response.content
            try:
                return json.loads(res), "Success"
            except Exception as e:
                self._logger.error("Failed to parse F5 ASM response %s", e)
                return None, "Cannot parse response from {}: {}".format(url, e)
        else:
            self._logger.error("Get request of url %s returned status %s, %s",
                url, response.status_code, response.content)
            return None, "Request of {} returned status {}: {}".format(
                url, response.status_code, response.content)

    def _post_request(self, url, payload):
        try:
            response = requests.post(
                url,
                data=json.dumps(payload),
                headers=self._headers,
                auth=self._auth_info,
                params=None, timeout=120,
                verify=False)
            if response.status_code > 299:
                if response.content:
                    try:
                        res = json.loads(response.content)
                        msg = res.get("message")
                        return msg
                    except:
                        return "API call of {} returns {}".format(url, response.status_code)
                else:
                    return "API call of {} returns {}".format(url, response.status_code)
        except Exception as e:
            return "Post request for {} gets exception: {}".format(url, str(e))
        return common.SUCCESS


    def _delete_request(self, url):
        try:
            response = requests.delete(
                url,
                headers=self._headers,
                auth=self._auth_info,
                params=None, timeout=120,
                verify=False)
            if response.status_code > 299:
                if response.content:
                    try:
                        res = json.loads(response.content)
                        msg = res.get("message")
                        return msg
                    except:
                        return "Delete API call returns {}".format(response.status_code)
                else:
                    return "Delete API call returns {}".format(response.status_code)
        except Exception as e:
            return "Delete API exception: {}".format(e)
        return common.SUCCESS

    def _get_policy_id(self):
        msg = ""
        policy_id = None
        res, msg = self._get_request(self._policy_url)
        if res != None:
            items = res.get("items", [])
            for item in items:
                name = item.get("name", "")
                if name == self._policy_name:
                    policy_id = item.get("id", "")
                    if policy_id and not self._policy_id:
                        self._logger.info("Found item matching: {}".format(json.dumps(item)))
                        self._policy_id = policy_id
                        self._policy_full_path = item.get("fullPath", "")
                    break
            if not policy_id:
                msg = "Cannot find the policy with specified name: {}".format(self._policy_name)
        return policy_id, msg

    def _apply_policy(self):
        url = "https://{}:{}/mgmt/tm/asm/tasks/apply-policy/".format(self._device, self._port)
        payload = {"policy":{"fullPath": self._policy_full_path}}
        self._logger.info("Paylod is: {}".format(json.dumps(payload)))
        return  self._post_request(url, payload)

    def unblock_ip(self, cidr, direction, **kwargs):
        return common.unblock_ip_wrapper(self, cidr, direction, **kwargs)

    def _unblock_ip(self, cidr, egress):
        address = cidr.split('/')[0]

        if not self._policy_id:
            policy_id, msg = self._get_policy_id()
            if not policy_id:
                return msg

        whitelist_url = "{}/{}/whitelist-ips".format(self._policy_url, self._policy_id)

        res, msg = self._get_request(whitelist_url)
        if not res:
            return msg

        items = res.get("items", [])
        object_id = None
        for item in items:
            ip_address = item.get("ipAddress", "")
            ip_mask = item.get("ipMask", "")
            if ip_address == address and ip_mask == "255.255.255.255":
                object_id = item.get("id", "")
                break
        if not object_id:
            return "Cannot find the address {} in policy".format(cidr)

        delete_url = "{}/{}".format(whitelist_url, object_id)
        res = self._delete_request(delete_url)

        if res != common.SUCCESS:
            return res

        return self._apply_policy()

    def block_ip(self, cidr, direction, **kwargs):
        return common.block_ip_wrapper(self, cidr, direction, **kwargs)

    def _block_ip(self, cidr, egress):
        address = cidr.split('/')[0]
        config_json = {
            "ipAddress": address,
            "ipMask": "255.255.255.255",
            "description": "always block only",
            "blockRequests": "always",
            "neverLearnRequests": False
        }

        if not self._policy_id:
            policy_id, msg = self._get_policy_id()
            if not policy_id:
                return msg

        whitelist_url = "{}/{}/whitelist-ips".format(self._policy_url, self._policy_id)
        res = self._post_request(whitelist_url, config_json)
        if res != common.SUCCESS:
            return res
        return self._apply_policy()

    def _test_connection(self, **kwargs):
        run_on = kwargs.get("run_on", "dp")
        if run_on != "" and run_on != "dp":
            return self.notify_ds_to_test_connection(run_on)
        # First login, then query both address groups

        res, msg = self._get_policy_id()
        if res is None:
            return utils.create_response("F5 ASM", 400, msg)
        return utils.create_response("F5 ASM", 200, common.SUCCESS)

    def notify_ds_to_test_connection(self, run_on):
        """
        Notify DS to perform the connection test
        :param run_on: str: the engid of sensor to run the test
        :return: str: the test results
        """
        script_path = "/opt/aelladata/connector/modules/firewall/f5_asm.py"
        password = utils.aella_encode(utils.COLLECTOR_SECRET, self._api_password)
        command = "export PYTHONPATH={}; python {} -a test -v {} -t {} -u \"{}\" -p \"{}\" -l \"{}\"".format(
                  utils.PYTHONPATH, script_path, self._device, self._port, self._api_username,
                  password, self._policy_name)
        status_code, error_msg = utils.execute_action_on_ds(run_on, command, retry_count=1)
        if status_code > 0:
            return utils.error_msg_process("F5 ASM", error_msg)
        return utils.create_response("F5 ASM", 200, common.SUCCESS)

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
        script_path = "/opt/aelladata/connector/modules/firewall/f5_asm.py"
        password = utils.aella_encode(utils.COLLECTOR_SECRET, self._api_password)
        command = "export PYTHONPATH={}; python {} -a {} -v {} -t {} -u \"{}\" -p \"{}\" -l \"{}\" -c {} -e {}".format(
                  utils.PYTHONPATH, script_path, action, self._device, self._port, self._api_username,
                  password, self._policy_name,
                  cidr, egress)
        status_code, error_msg = utils.execute_action_on_ds(run_on, command)
        if status_code > 0:
            return "Firewall action on sensor fail with status code {}: {}".format(status_code, error_msg)
        return common.SUCCESS

if __name__ == '__main__':
    LOG_FILENAME = "/var/log/aella/firewall_action.log"
    FORMAT = "%(asctime)-15s|%(name)s|%(levelname)s|%(message)s"
    logger = logging.getLogger("f5_asm_firewall")
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
    parser.add_argument('-t', '--port', action='store', dest='port', required=True,
        help='The port of firewall')
    parser.add_argument('-u', '--username', action='store', dest='username', required=True,
        help='The username to login firewall')
    parser.add_argument('-p', '--password', action='store', dest='password', required=True,
        help='The password to login firewall')
    parser.add_argument('-l', '--policy_name', action='store', dest='policy_name', required=True,
        help='The name of the policy')
    parser.add_argument('-c', '--cidr', action='store', dest='cidr', required=False,
        help='The CIDR as input of action')
    parser.add_argument('-e', '--egress', action='store', dest='egress', required=False,
        help='True if direction is egress')

    results = parser.parse_args()

    firewall_connector = F5ASMConnector(results.username, results.password,
                                     results.device, results.port,
                                     results.policy_name,
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
