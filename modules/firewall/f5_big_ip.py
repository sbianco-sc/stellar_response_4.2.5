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


class F5Connector():
    def __init__(self, username, password, device, port, src_ip_grp_name, dst_ip_grp_name, lgr=None, **kwargs):
        self._api_username = username
        self._api_password = utils.aella_decode(utils.COLLECTOR_SECRET, password)
        self._device = device
        self._port = port
        self._src_address_grp = src_ip_grp_name
        self._dst_address_grp = dst_ip_grp_name
        self._logger = lgr
        self._address_list_url = "https://{}:{}/mgmt/tm/security/firewall/address-list".format(device, port)
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
            self._logger.error("Get request failed: %s", e)
            return None, str(e)
        if response.status_code == 200:
            res = response.content
            try:
                return json.loads(res), "Success"
            except Exception as e:
                self._logger.error("Failed to parse response %s", e)
                return None, str(e)
        else:
            self._logger.error("Get request returned status %s, %s",
                response.status_code, response.content)
            return None, "Request returned status {}: {}".format(
                response.status_code, response.content)

    def _put_request(self, url, payload):
        try:
            response = requests.put(
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
                        return "API call returns {}".format(response.status_code)
                else:
                    return "API call returns {}".format(response.status_code)
        except Exception as e:
            return str(e)
        return common.SUCCESS


    def _add_address(self, address_group, address):
        """
        Add address to address list
        """
        try:
            success, group_info, msg = self._get_address_group(address_group)
            if not success:
                return False, msg
            addr_exists = False
            address_list = group_info.get("addresses", [])
            for item in address_list:
                value = item.get("name", "")
                if value == address:
                    addr_exists = True
            if not addr_exists:
                address_list.append({"name": address})
            payload = {"addresses": address_list}
            url = "{}/{}".format(self._address_list_url, address_group)
            res = self._put_request(url, payload)
            if res != common.SUCCESS:
                return False, ""
            return True, ""
        except Exception as e:
            self._logger.error("Failed to add address to list for %s: %s", address, e)
            return False, "Failed to add address to address list"

    def _remove_address(self, address_group, address):
        """
        Remove the IP from address group
        """
        try:
            success, group_info, msg = self._get_address_group(address_group)
            if not success:
                return False, msg
            addr_exists = False
            address_list = group_info.get("addresses", [])
            new_list = []
            for item in address_list:
                value = item.get("name", "")
                if value == address:
                    addr_exists = True
                else:
                    new_list.append(item)
            if not addr_exists:
                return False, "Address not found in address list"
            payload = {"addresses": new_list}
            url = "{}/{}".format(self._address_list_url, address_group)
            res = self._put_request(url, payload)
            if res != common.SUCCESS:
                return False, ""
            return True, ""
        except Exception as e:
            self._logger.error("Failed to remove address frome list for %s: %s", address, e)
            return False, "Failed to remove address from address list"

    def _get_address_group(self, address_group):
        msg = ""
        success = True
        url = "{}/{}".format(self._address_list_url, address_group)
        res, msg = self._get_request(url)
        if res is None:
            success = False
        else:
            code = int(res.get("code", 200))
            if code != 200:
                success = False
                msg = res.get("message", "connection error")
        return success, res, msg

    def unblock_ip(self, cidr, direction, **kwargs):
        return common.unblock_ip_wrapper(self, cidr, direction, **kwargs)

    def _unblock_ip(self, cidr, egress):
        address = cidr.split('/')[0]

        if egress:
            addrgrp_name = self._dst_address_grp
        else:
            addrgrp_name = self._src_address_grp

        res, msg = self._remove_address(addrgrp_name, address)

        if not res:
            return msg

        return common.SUCCESS

    def block_ip(self, cidr, direction, **kwargs):
        return common.block_ip_wrapper(self, cidr, direction, **kwargs)

    def _block_ip(self, cidr, egress):
        address = cidr.split('/')[0]

        if egress:
            addrgrp_name = self._dst_address_grp
        else:
            addrgrp_name = self._src_address_grp

        res, msg = self._add_address(addrgrp_name, address)
        if not res:
            return msg

        return common.SUCCESS

    def _test_connection(self, **kwargs):
        run_on = kwargs.get("run_on", "dp")
        if run_on != "" and run_on != "dp":
            return self.notify_ds_to_test_connection(run_on)
        # First login, then query both address groups

        res, msg = self._get_request(self._address_list_url)
        if res is None:
            return utils.create_response("F5 BIG-IP", 400, msg)
        try:
            code = int(res.get("code", 200))
            if code != 200:
                return utils.create_response("F5 BIG-IP", 400, res.get("message", "connection error"))
        except:
            return utils.create_response("F5 BIG-IP", 400, "Error parsing connection response")

        error = ""
        success, res, msg = self._get_address_group(self._src_address_grp)
        if not success:
            error += "Error getting group {}: {}".format(self._src_address_grp, msg)

        success, res, msg = self._get_address_group(self._dst_address_grp)
        if not success:
            error += "Error getting group {}: {}".format(self._dst_address_grp, msg)

        if error:
            return utils.create_response("F5 BIG-IP", 400, error)
        return utils.create_response("F5 BIG-IP", 200, common.SUCCESS)

    def notify_ds_to_test_connection(self, run_on):
        """
        Notify DS to perform the connection test
        :param run_on: str: the engid of sensor to run the test
        :return: str: the test results
        """
        script_path = "/opt/aelladata/connector/modules/firewall/f5_big_ip.py"
        password = utils.aella_encode(utils.COLLECTOR_SECRET, self._api_password)
        command = "export PYTHONPATH={}; python {} -a test -v {} -t {} -u \"{}\" -p \"{}\" -s \"{}\" -d \"{}\"".format(
                  utils.PYTHONPATH, script_path, self._device, self._port, self._api_username,
                  password, self._src_address_grp, self._dst_address_grp)
        status_code, error_msg = utils.execute_action_on_ds(run_on, command, retry_count=1)
        if status_code > 0:
            return utils.error_msg_process("F5 BIG-IP", error_msg)
        return utils.create_response("F5 BIG-IP", 200, common.SUCCESS)

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
        script_path = "/opt/aelladata/connector/modules/firewall/f5_big_ip.py"
        password = utils.aella_encode(utils.COLLECTOR_SECRET, self._api_password)
        command = "export PYTHONPATH={}; python {} -a {} -v {} -t {} -u \"{}\" -p \"{}\" -s \"{}\" -d \"{}\" -c {} -e {}".format(
                  utils.PYTHONPATH, script_path, action, self._device, self._port, self._api_username,
                  password, self._src_address_grp, self._dst_address_grp,
                  cidr, egress)
        status_code, error_msg = utils.execute_action_on_ds(run_on, command)
        if status_code > 0:
            return "Firewall action on sensor fail with status code {}: {}".format(status_code, error_msg)
        return common.SUCCESS

if __name__ == '__main__':
    LOG_FILENAME = "/var/log/aella/firewall_action.log"
    FORMAT = "%(asctime)-15s|%(name)s|%(levelname)s|%(message)s"
    logger = logging.getLogger("f5_big_ip_firewall")
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
    parser.add_argument('-s', '--src_ip_grp_name', action='store', dest='src_ip_grp_name', required=True,
        help='The name for source IP group')
    parser.add_argument('-d', '--dst_ip_grp_name', action='store', dest='dst_ip_grp_name', required=True,
        help='The name for destination IP group')
    parser.add_argument('-c', '--cidr', action='store', dest='cidr', required=False,
        help='The CIDR as input of action')
    parser.add_argument('-e', '--egress', action='store', dest='egress', required=False,
        help='True if direction is egress')

    results = parser.parse_args()

    firewall_connector = F5Connector(results.username, results.password,
                                     results.device, results.port,
                                     results.src_ip_grp_name,
                                     results.dst_ip_grp_name,
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
