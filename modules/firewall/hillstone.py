#!/usr/bin/env python

import argparse
import logging
import logging.handlers
import random
import sys
import os
import requests
import re
import time
import json

import base64

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


import pdb

import firewall.common as common

import utils

class HillstoneConnector():
    def __init__(self, username, encode_uname, password, device, src_ip_grp_name, dst_ip_grp_name, port=443, lgr=None, **kwargs):
        if encode_uname:
            self._api_username = base64.encodestring(username)
        else:
            self._api_username = username
        password = utils.aella_decode(utils.COLLECTOR_SECRET, password)
        self._api_password = base64.encodestring(password)
        self._device = device
        self._port = int(port)
        self._src_address_grp = src_ip_grp_name
        self._dst_address_grp = dst_ip_grp_name
        self._logger = lgr
        self._dev_url = "https://{}/rest/doc".format(device)
        if port != 443:
            self._dev_url = "https://{}:{}/rest/doc".format(device, port)
        self._cookie = None
        self._action_result = {}

    def prepare(self, action_name, settings, source):
        return common.prepare(action_name, settings, source)

    def _login(self):
        data = { 'userName': self._api_username,
            'password': self._api_password}
        try:
            response = requests.post(self._dev_url + '/login', data=json.dumps(data), verify=False)
        except Exception as e:
            if self._logger:
                self._logger.info("Cannot login {}".format(e))
            return "Cannot login {}".format(e)
        try:
            res_json = json.loads(response.content)
        except Exception as e:
            if self._logger:
                self._logger.info("Cannot parse response {}".format(e))
            return "Cannot parse response {}".format(e)

        if not res_json.get("success", False):
            if self._logger:
                self._logger.info("Login failed {}".format(res_json))
            return "Login failed"

        try:
            result = res_json.get("result")
            result = result[0]
        except Exception as e:
            if self._logger:
                self._logger.info("Cannot parse response result{}".format(e))
            return "Cannot parse response result {}".format(e)

        self._cookie = {'username':self._api_username}
        for key in ['token','role','vsysId', 'fromrootvsys']:
            self._cookie[key] = result[key]

        return common.SUCCESS

    def block_ip(self, cidr, direction, **kwargs):
        return common.block_ip_wrapper(self, cidr, direction, **kwargs)

    def _block_ip(self, cidr, egress):
        if self._logger:
            self._logger.info("Trying to block ip {} egress {}".format(cidr, egress))

        ret_val = self._login()
        if ret_val != common.SUCCESS:
            if self._logger:
                self._logger.info("Login {} failed. status {}".format(self._device, ret_val))
            return "Login {} failed. status {}".format(self._device, ret_val)

        if egress:
            block_ip_grp = self._dst_address_grp
        else:
            block_ip_grp = self._src_address_grp

        # Get the address book
        addr_book_url = self._dev_url + "/addrbook?query={\"conditions\":[{\"field\":\"name\",\"value\":\"" + block_ip_grp + "\"}]}"
        try:
            res = requests.get(addr_book_url, cookies=self._cookie, verify=False)
            res_json = json.loads(res.content)
        except Exception as e:
            if self._logger:
                self._logger.info("Cannot query address book {}".format(e))
            return "Cannot query address book {}".format(e)

        if not res_json.get("success", False):
            if self._logger:
                self._logger.info("Query address book failed {}".format(res_json))
            return "Query address book failed"

        if '/' in cidr:
            ip, net_size = cidr.split('/')
        else:
            ip = cidr
            net_size = '32'

        try:
            result = res_json.get("result")
            res_ip = result[0].get("ip", [])
            for item in res_ip:
                ip_addr = item["ip_addr"]
                netmask = item["netmask"]
                if ip_addr == ip and netmask == net_size:
                    if self._logger:
                        self._logger.info("Address {} is already in the address book {}".format(cidr, block_ip_grp))
                    return "Address {} is already in the address book {}".format(cidr, block_ip_grp)
        except Exception as e:
            if self._logger:
                self._logger.info("Cannot parse address list {}".format(e))
            return "Cannot parse address list {}".format(e)

        try:
            res_ip.append({'netmask':net_size, 'ip_addr':ip, 'flag': '0'})
            result[0]["ip"] = res_ip
            # We changed the content in result
            data = result
            put_url = self._dev_url + '/addrbook'
            res = requests.put(put_url, cookies=self._cookie, data=json.dumps(data), verify=False)
            res_json = json.loads(res.content)
        except Exception as e:
            if self._logger:
                self._logger.info("Cannot modify address group {}".format(e))
            return "Cannot modify address group {}".format(e)

        if not res_json.get("success", False):
            if self._logger:
                self._logger.info("Modify address book failed {}".format(res_json))
            return "Modify address book for blocking ip {} failed".format(cidr)

        if self._logger:
            self._logger.info("Success block ip {} for address book {}".format(cidr, block_ip_grp))
        return common.SUCCESS

    def unblock_ip(self, cidr, direction, **kwargs):
        return common.unblock_ip_wrapper(self, cidr, direction, **kwargs)

    def _unblock_ip(self, cidr, egress):
        if self._logger:
            self._logger.info("Trying to unblock ip {} egress {}".format(cidr, egress))

        ret_val = self._login()
        if ret_val != common.SUCCESS:
            if self._logger:
                self._logger.info("Login {} failed. status {}".format(self._device, ret_val))
            return "Login {} failed. status {}".format(self._device, ret_val)

        if egress:
            block_ip_grp = self._dst_address_grp
        else:
            block_ip_grp = self._src_address_grp

        # Get the address book
        addr_book_url = self._dev_url + "/addrbook?query={\"conditions\":[{\"field\":\"name\",\"value\":\"" + block_ip_grp + "\"}]}"
        try:
            res = requests.get(addr_book_url, cookies=self._cookie, verify=False)
            res_json = json.loads(res.content)
        except Exception as e:
            if self._logger:
                self._logger.info("Cannot query address book {}".format(e))
            return "Cannot query address book {}".format(e)

        if not res_json.get("success", False):
            if self._logger:
                self._logger.info("Query address book failed {}".format(res_json))
            return "Query address book failed"

        if '/' in cidr:
            ip, net_size = cidr.split('/')
        else:
            ip = cidr
            net_size = '32'

        try:
            found_ip = False
            result = res_json.get("result")
            res_ip = result[0].get("ip", [])
            for item in res_ip:
                ip_addr = item["ip_addr"]
                netmask = item["netmask"]
                if ip_addr == ip and netmask == net_size:
                    found_ip = True
                    res_ip.remove(item)
            if not found_ip:
                if self._logger:
                    self._logger.info("Address {} is not found in the address book {}".format(cidr, block_ip_grp))
                return "Address {} is not found in the address book {}".format(cidr, block_ip_grp)
        except Exception as e:
            if self._logger:
                self._logger.info("Cannot parse address list {}".format(e))
            return "Cannot parse address list {}".format(e)

        try:
            # We changed the content in result
            data = result
            put_url = self._dev_url + '/addrbook'
            res = requests.put(put_url, cookies=self._cookie, data=json.dumps(data), verify=False)
            res_json = json.loads(res.content)
        except Exception as e:
            if self._logger:
                self._logger.info("Cannot modify address group {}".format(e))
            return "Cannot modify address group {}".format(e)

        if not res_json.get("success", False):
            if self._logger:
                self._logger.info("Modify address book for unblocking ip failed {}".format(res_json))
            return "Modify address book for unblocking ip {} failed".format(cidr)

        if self._logger:
            self._logger.info("Success unblock ip {} for address book {}".format(cidr, block_ip_grp))
        return common.SUCCESS

    def _test_connection(self, **kwargs):
        run_on = kwargs.get("run_on", "dp")
        if run_on != "" and run_on != "dp":
            return self.notify_ds_to_test_connection(run_on)
        ret_val = self._login()
        if ret_val != common.SUCCESS:
            if self._logger:
                self._logger.info("Login {} failed. status {}".format(self._device, ret_val))
            return utils.create_response("Hillstone", 400, "Login {} failed. status {}".format(self._device, ret_val))

        address_book_url = self._dev_url + '/addrbook'
        try:
            res = requests.get(address_book_url, cookies=self._cookie, verify=False)
            res_json = json.loads(res.content)
        except Exception as e:
            if self._logger:
                self._logger.info("Cannot list address book {}".format(e))
            return utils.create_response("Hillstone", 400, "Cannot list address book {}".format(e))

        if not res_json.get("success", False):
            if self._logger:
                self._logger.info("List address book failed {}".format(res_json))
            return utils.create_response("Hillstone", 400, "List address booki failed")

        try:
            result = res_json.get("result")
            src_grp_found = False
            dst_grp_found = False
            for item in result:
                name = item['name']
                if name == self._src_address_grp:
                    src_grp_found = True
                elif name == self._dst_address_grp:
                    dst_grp_found = True
        except Exception as e:
            if self._logger:
                self._logger.info("Cannot iterate through address book {}".format(e))
            return utils.create_response("Hillstone", 400, "Cannot iterate through address book {}".format(e))

        if not src_grp_found:
            return utils.create_response("Hillstone", 400, "Cannot find address group {}".format(self._src_address_grp))
        if not dst_grp_found:
            return utils.create_response("Hillstone", 400, "Cannot find address group {}".format(self._dst_address_grp))
        return utils.create_response("Hillstone", 200, common.SUCCESS)

    def notify_ds_to_test_connection(self, run_on):
        """
        Notify DS to perform the connection test
        :param run_on: str: the engid of sensor to run the test
        :return: str: the test results
        """
        script_path = "/opt/aelladata/connector/modules/firewall/hillstone.py"
        password = utils.aella_encode(utils.COLLECTOR_SECRET, self._api_password)
        command = "export PYTHONPATH={}; python {} -a test -v {} -t {} -u \"{}\" -p {} -s \"{}\" -d \"{}\"".format(
                  utils.PYTHONPATH, script_path, self._device, self._port, self._api_username,
                  password, self._src_address_grp, self._dst_address_grp)
        status_code, error_msg = utils.execute_action_on_ds(run_on, command, retry_count=1)
        if status_code > 0:
            return utils.error_msg_process("Hillstone", error_msg)
        return utils.create_response("Hillstone", 200, common.SUCCESS)

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
        script_path = "/opt/aelladata/connector/modules/firewall/hillstone.py"
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
    logger = logging.getLogger("hillstone_firewall")
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
    parser.add_argument('-t', '--port', action='store', dest='port', required=False,
        help='The port to reach firewall')
    parser.add_argument('-u', '--username', action='store', dest='username', required=True,
        help='The username to login firewall')
    parser.add_argument('-m', '--encode_username', action='store', dest='encode_username', required=False,
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

    encode_username = False
    if str(results.encode_username).lower() == "true":
        encode_username = True

    firewall_connector = HillstoneConnector(results.username, encode_username,
                                            results.password, results.device,
                                            results.src_ip_grp_name,
                                            results.dst_ip_grp_name,
                                            port=results.port,
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
