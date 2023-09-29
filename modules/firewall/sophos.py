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


class SophosConnector():
    def __init__(self, username, password, device, port, src_ip_grp_name, dst_ip_grp_name, lgr=None, **kwargs):
        self._api_username = username
        self._api_password = utils.aella_decode(utils.COLLECTOR_SECRET, password)
        self._device = device
        self._port = port
        self._src_address_grp = src_ip_grp_name
        self._dst_address_grp = dst_ip_grp_name
        self._logger = lgr
        self._url = "https://{}:{}/webconsole/APIController".format(device, port)
        self._request_param = {
            "Request": {
                "Login": {
                    "Username": self._api_username,
                    "Password": self._api_password
                }
            }
        }

    def prepare(self, action_name, settings, source):
        return common.prepare(action_name, settings, source)


    def _get_request(self, url, xml_contents):
        headers = {"Content-Type": "application/xml"}
        xml_str = xmltodict.unparse(xml_contents)
        params = {"reqxml": xml_str}
        self._logger.info("Running get request with url {}, headers {}, body {}".format(url, headers, xml_contents))
        try:
            response = requests.get(
                url, headers=headers,
                params=params, verify=False)
        except requests.RequestException as e:
            self._logger.error("Get request failed", exc_info=1)
            return None
        if response.status_code == 200:
            res = response.content
            try:
                parsed_res = xmltodict.parse(res)
                self._logger.info("Get request response {}".format(parsed_res))
                return parsed_res
            except Exception as e:
                self._logger.error("Failed to parse xml response %s", response.content, exc_info=1)
                return None
        else:
            self._logger.error("Get request returned status %s, %s", response.status_code, response.content)
            return None

    def _get_stellar_object_name(self, address):
        return "Stellar_{}".format(address)

    def _create_address_object(self, address):
        """
        Create address object if not existing. The name will
        be stellar specific for ease of recognition.
        """
        try:
            xml_contents = copy.deepcopy(self._request_param)
            obj_name = self._get_stellar_object_name(address)
            xml_contents["Request"]["Set"] = {
                "IPHost": {
                    "Name": obj_name,
                    "IPFamily": "IPv4",
                    "HostType": "IP",
                    "IPAddress": address
               }
            }
            response = self._get_request(self._url, xml_contents)
            if response is None:
                return False, "Failed to create address object"

            status = int(response.get("Response", {}).get("IPHost", {}).get("Status", {}).get("@code", 0))
            if status != 200:
                if status == 0:
                    return False, "Fail to access firewall"
                else:
                    return False, "Failed to create address object: {}".format(
                            response.get("Response", {}).get("IPHost", {}).get("Status", {}).get("#text", 0))
            return True, ""
        except Exception as e:
            self._logger.error("Failed to create address object for %s: %s", cidr, e)
            return False, "Failed to create address object"

    def _get_address_groups(self):
        xml_contents = copy.deepcopy(self._request_param)
        xml_contents["Request"]["Get"] = {
            "IPHostGroup": None
        }
        response = self._get_request(self._url, xml_contents)
        if response is None:
            return None, "Failed to access firewall"
        login_res = response.get("Response", {}).get("Login", {}).get("status", "")
        if login_res != "Authentication Successful":
            self._logger.info("Failed to login firewall: {0}".format(response))
            return None, "Failed to login firewall: {0}".format(response)
        address_groups = response.get("Response", {}).get("IPHostGroup", [])
        if not isinstance(address_groups, list):
            self._logger.info("Retrieving address groups encountered an error: {0}".format(response))
            return None, "Received: {0}".format(response)
        return address_groups, "Success"

    def _update_address_group(self, group_name, host_list):
        xml_contents = copy.deepcopy(self._request_param)
        xml_contents["Request"]["Set"] = {
            "IPHostGroup": {
                "Name": group_name,
                "HostList": {
                    "Host": host_list
                }
            }
        }
        response = self._get_request(self._url, xml_contents)
        if response is None:
            return None, "Failed to access firewall"
        status = int(response.get("Response", {}).get("IPHostGroup", {}).get("Status", {}).get("@code", 0))
        if status != 200:
            if status == 0:
                return False, "Fail to access firewall"
            else:
                return False, "Failed to create address object: {}".format(
                    response.get("Response", {}).get("IPHost", {}).get("Status", {}).get("#text", 0))
        return True, ""

    def _remove_ip_host(self, host_name, host_ip):
        xml_contents = copy.deepcopy(self._request_param)
        xml_contents["Request"]["Remove"] = {
            "IPHost": {
                "Name": host_name,
                "IPFamily": "IPv4",
                "HostType": "IP",
                "IPAddress": host_ip
            }
        }
        headers = {"Content-Type": "application/xml"}
        xml_str = xmltodict.unparse(xml_contents)
        params = {"reqxml": xml_str}
        self._logger.info("Running remove request with url {}, headers {}, body {}".format(self._url, headers, xml_contents))
        try:
            response = requests.post(
                self._url, headers=headers,
                params=params, verify=False)
        except requests.RequestException as e:
            self._logger.error("Delete request failed", exc_info=1)
            return None
        if response.status_code == 200:
            res = response.content
            try:
                parsed_res = xmltodict.parse(res)
                self._logger.info("Delete request response {}".format(parsed_res))
                return parsed_res
            except Exception as e:
                self._logger.error("Failed to parse xml response %s", response.content, exc_info=1)
                return None
        else:
            self._logger.error("Delete request returned status %s, %s", response.status_code, response.content)
            return None

    def unblock_ip(self, cidr, direction, **kwargs):
        return common.unblock_ip_wrapper(self, cidr, direction, **kwargs)

    def _unblock_ip(self, cidr, egress):
        address = cidr.split('/')[0]

        if egress:
            addrgrp_name = self._dst_address_grp
        else:
            addrgrp_name = self._src_address_grp

        address_groups, msg = self._get_address_groups()
        if address_groups is None:
            return msg

        object_name = self._get_stellar_object_name(address)
        group_found = False
        for group in address_groups:
            name = group.get("Name")
            if name == addrgrp_name:
                host_info = group.get("HostList", {}).get("Host", [])
                if not host_info:
                    host_list = []
                elif not isinstance(host_info, list):
                    host_list = [host_info]
                else:
                    host_list = host_info
                if not object_name in host_list:
                    return "Address object associated with {} not found in group {}".format(address, addrgrp_name)
                host_list.remove(object_name)
                res, msg = self._update_address_group(addrgrp_name, host_list)
                if not res:
                    return msg
                group_found = True
                break
        if not group_found:
            return "Address group not found"
        res = self._remove_ip_host(object_name, address)
        if not res:
            self._logger.error("Unable to remove IP Host {} with IP address {}".format(object_name, address))
        return common.SUCCESS

    def block_ip(self, cidr, direction, **kwargs):
        return common.block_ip_wrapper(self, cidr, direction, **kwargs)

    def _block_ip(self, cidr, egress):
        address = cidr.split('/')[0]

        if egress:
            addrgrp_name = self._dst_address_grp
        else:
            addrgrp_name = self._src_address_grp

        res, msg = self._create_address_object(address)
        if not res:
            return msg

        # Sophos XG does not support single address group query,
        # so we have to get all of them
        address_groups, msg = self._get_address_groups()
        if address_groups is None:
            return msg

        object_name = self._get_stellar_object_name(address)
        group_found = False
        for group in address_groups:
            name = group.get("Name")
            if name == addrgrp_name:
                host_info = group.get("HostList", {}).get("Host", [])
                if not host_info:
                    host_list = []
                elif not isinstance(host_info, list):
                    host_list = [host_info]
                else:
                    host_list = host_info
                if not object_name in host_list:
                    host_list.append(object_name)
                res, msg = self._update_address_group(addrgrp_name, host_list)
                if not res:
                    return msg
                group_found = True
                break
        if not group_found:
            return "Address group not found"
        return common.SUCCESS

    def _test_connection(self, **kwargs):
        run_on = kwargs.get("run_on", "dp")
        if run_on != "" and run_on != "dp":
            return self.notify_ds_to_test_connection(run_on)
        # First login, then query both address groups
        src_group_found = False
        dst_group_found = False
        address_groups, msg = self._get_address_groups()
        if address_groups is None:
            return utils.create_response("Sophos", 400, msg)

        for group in address_groups:
            name = group.get("Name")
            if name == self._dst_address_grp:
                dst_group_found = True
            if name == self._src_address_grp:
                src_group_found = True
        msg = ""
        if not dst_group_found:
            msg += "Group {} is not found. ".format(self._dst_address_grp)
        if not src_group_found:
            msg += "Group {} is not found. ".format(self._src_address_grp)
        if not src_group_found or not dst_group_found:
            return utils.create_response("Sophos", 400, msg)
        return utils.create_response("Sophos", 200, common.SUCCESS)

    def notify_ds_to_test_connection(self, run_on):
        """
        Notify DS to perform the connection test
        :param run_on: str: the engid of sensor to run the test
        :return: str: the test results
        """
        script_path = "/opt/aelladata/connector/modules/firewall/sophos.py"
        password = utils.aella_encode(utils.COLLECTOR_SECRET, self._api_password)
        command = "export PYTHONPATH={}; python {} -a test -v {} -t {} -u \"{}\" -p \"{}\" -s \"{}\" -d \"{}\"".format(
                  utils.PYTHONPATH, script_path, self._device, self._port, self._api_username,
                  password, self._src_address_grp, self._dst_address_grp)
        status_code, error_msg = utils.execute_action_on_ds(run_on, command, retry_count=1)
        if status_code > 0:
            return utils.error_msg_process("Sophos", error_msg)
        return utils.create_response("Sophos", 200, common.SUCCESS)

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
        script_path = "/opt/aelladata/connector/modules/firewall/sophos.py"
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
    logger = logging.getLogger("sophos_firewall")
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

    firewall_connector = SophosConnector(results.username, results.password,
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
