#!/usr/bin/env python
import argparse
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

FORTIGATE_LOGIN = '/logincheck'
FORTIGATE_BASE_URL = '/api/v2'

FORTIGATE_JSON_IP = 'ip'
FORTIGATE_JSON_POLICY = 'policy'
FORTIGATE_JSON_NAME = 'name'
FORTIGATE_JSON_TYPE = 'type'
FORTIGATE_JSON_IP_MASK = 'ipmask'
FORTIGATE_JSON_SUBNET = 'subnet'

FORTIGATE_REST_RESP_BAD_REQUEST = 400
FORTIGATE_REST_RESP_BAD_REQUEST_MSG = 'Request cannot be processed by the API'
FORTIGATE_REST_RESP_NOT_AUTH = 401
FORTIGATE_REST_RESP_NOT_AUTH_MSG = 'Request without successful login session'
FORTIGATE_REST_RESP_FORBIDDEN = 403
FORTIGATE_REST_RESP_FORBIDDEN_MSG = 'Request is missing CSRF token or administrator is missing access profile permissions'
FORTIGATE_REST_RESP_RESOURCE_NOT_FOUND = 404
FORTIGATE_REST_RESP_RESOURCE_NOT_FOUND_MSG = 'Resource not available'
FORTIGATE_REST_RESP_NOT_ALLOWED = 405
FORTIGATE_REST_RESP_NOT_ALLOWED_MSG = 'Specified HTTP method is not allowed for this resource'
FORTIGATE_REST_RESP_ENTITY_LARGE = 413
FORTIGATE_REST_RESP_ENTITY_LARGE_MSG = 'Request cannot be processed due to large entity'
FORTIGATE_REST_RESP_FAIL_DEPENDENCY = 424
FORTIGATE_REST_RESP_FAIL_DEPENDENCY_MSG = 'Fail dependency can be duplicate resource, missing required parameter, missing required attribute, invalid attribute value'
FORTIGATE_REST_RESP_INTERNAL_ERROR = 500
FORTIGATE_REST_RESP_INTERNAL_ERROR_MSG = 'Internal error when processing the request'
FORTIGATE_REST_RESP_SUCCESS = 200
FORTIGATE_ERR_API_UNSUPPORTED_METHOD = 'Unsupported method {}'
FORTIGATE_ERR_SERVER_CONNECTION = 'Connection failed'
FORTIGATE_ERR_JSON_PARSE = 'Unable to parse the fields parameter into a dictionary. \nResponse text - {raw_text}'
FORTIGATE_ERR_FROM_SERVER = 'API failed\nStatus code: {status}\nDetail: {detail}'
FORTIGATE_REST_RESP_OTHER_ERROR_MSG = 'Unknown error'

FORTIGATE_ADD_ADDRESS = '/cmdb/firewall/address'
FORTIGATE_GET_ADDRESSES = '/cmdb/firewall/address/{ip}?key=name&pattern={ip}'

FORTIGATE_GET_ADDRGRP = '/cmdb/firewall/addrgrp/{addrgrp}?key=name'
FORTIGATE_SET_ADDRGRP = '/cmdb/firewall/addrgrp/{}/'

FORTIGATE_IP_BLOCKED = 'IP blocked successfully'
FORTIGATE_IP_UNBLOCKED = 'IP unblocked successfully'

class FortigateConnector():
    def __init__(self, username, password, device, vdom, src_ip_grp_name, dst_ip_grp_name, port=443, lgr=None, **kwargs):
        self._api_username = username
        self._api_password = utils.aella_decode(utils.COLLECTOR_SECRET, password)
        self._device = device
        self._vdom = vdom
        self._src_address_grp = src_ip_grp_name
        self._dst_address_grp = dst_ip_grp_name
        self._port = int(port)
        self._logger = lgr
        self._sess_obj = None
        self._verify_server_cert = False
        self._error_resp_dict = {FORTIGATE_REST_RESP_BAD_REQUEST: FORTIGATE_REST_RESP_BAD_REQUEST_MSG,
            FORTIGATE_REST_RESP_NOT_AUTH: FORTIGATE_REST_RESP_NOT_AUTH_MSG,
            FORTIGATE_REST_RESP_FORBIDDEN: FORTIGATE_REST_RESP_FORBIDDEN_MSG,
            FORTIGATE_REST_RESP_NOT_ALLOWED: FORTIGATE_REST_RESP_NOT_ALLOWED_MSG,
            FORTIGATE_REST_RESP_ENTITY_LARGE: FORTIGATE_REST_RESP_ENTITY_LARGE_MSG,
            FORTIGATE_REST_RESP_FAIL_DEPENDENCY: FORTIGATE_REST_RESP_FAIL_DEPENDENCY_MSG,
            FORTIGATE_REST_RESP_INTERNAL_ERROR: FORTIGATE_REST_RESP_INTERNAL_ERROR_MSG}

    def prepare(self, action_name, settings, source):
        return common.prepare(action_name, settings, source)

    def _make_rest_call(self, endpoint, data = None, method = 'get'):
        host = "https://{}".format(self._device)
        if self._port != 443:
            host = "https://{}:{}".format(self._device, self._port)
        rest_res = None
        try:
            request_func = getattr(self._sess_obj, method)
        except Exception as e:
            status = FORTIGATE_ERR_API_UNSUPPORTED_METHOD.format(method)
            if self._logger:
                self._logger.info("Rest call exception {}, status {}".format(e, status))
            return (status, rest_res)

        url = host + FORTIGATE_BASE_URL + endpoint
        if endpoint == FORTIGATE_LOGIN:
            url = host + endpoint
        try:
            response = request_func(url, data=data, params={'vdom':self._vdom}, verify=self._verify_server_cert, timeout=(15, 27))
        except Exception as e:
            status = FORTIGATE_ERR_SERVER_CONNECTION
            if self._logger:
                self._logger.info("Rest call exception {}, status {}".format(e, status))
            return (status, rest_res)

        if response.status_code in self._error_resp_dict.keys():
            status = self._error_resp_dict[response.status_code]
            if self._logger:
                self._logger.info("Rest call failed, status {}".format(status))
            return (status, rest_res)

        if response.status_code == FORTIGATE_REST_RESP_RESOURCE_NOT_FOUND:
            status = 'resource_not_available'
            if self._logger:
                self._logger.debug("Rest call succeeded with status {}".format(status))
            return (common.SUCCESS, {'resource_not_available': True})
        if response.status_code == FORTIGATE_REST_RESP_SUCCESS:
            content_type = response.headers['content-type']
            if content_type.find('json') != -1:
                try:
                    rest_res = response.json()
                except Exception as e:
                    msg_string = FORTIGATE_ERR_JSON_PARSE.format(raw_text=response.text)
                    if self._logger:
                        self._logger.info("Rest call exception {}, status {}".format(e, msg_string))
                    return (msg_string, rest_res)
            return (common.SUCCESS, rest_res)
        status = FORTIGATE_ERR_FROM_SERVER.format(status=response.status_code, detail=FORTIGATE_REST_RESP_OTHER_ERROR_MSG)
        if self._logger:
            self._logger.info("Rest call with status {}".format(status))
        return (status, rest_res)

    def _login(self):
        credential_data = {'username': self._api_username,
         'secretkey': self._api_password}
        self._sess_obj = requests.session()
        status, response = self._make_rest_call(FORTIGATE_LOGIN, data=credential_data, method='post')
        if status != common.SUCCESS:
            return status
        self._sess_obj.headers.update({'X-CSRFTOKEN': self._sess_obj.cookies['ccsrftoken'][1:-1]})
        return status

    def _get_net_size(self, net_mask):
        net_mask = net_mask.split('.')
        binary_str = ''
        for octet in net_mask:
            binary_str += bin(int(octet))[2:].zfill(8)

        return str(len(binary_str.rstrip('0')))

    def _get_net_mask(self, net_size):
        host_bits = 32 - int(net_size)
        net_mask = socket.inet_ntoa(struct.pack('!I', 4294967296 - (1 << host_bits)))
        return net_mask

    def _break_ip_addr(self, ip_addr):
        ip = None
        net_size = None
        net_mask = None
        if '/' in ip_addr:
            ip, net_size = ip_addr.split('/')
            net_mask = self._get_net_mask(net_size)
        elif ' ' in ip_addr:
            ip, net_mask = ip_addr.split()
            net_size = self._get_net_size(net_mask)
        else:
            ip = ip_addr
            net_size = '32'
            net_mask = '255.255.255.255'
        return (ip, net_size, net_mask)

    def _is_address_available(self, ip_addr_obj_name):
        ret_code, json_resp = self._make_rest_call(FORTIGATE_GET_ADDRESSES.format(ip=ip_addr_obj_name))
        if ret_code != common.SUCCESS:
            return (ret_code, None)
        if json_resp.get('resource_not_available'):
            return (common.SUCCESS, False)
        return (common.SUCCESS, True)

    # Remove the address object, which can fail if the address object is still referenced by address groups
    def _delete_address(self, ip_addr_obj_name):
        ret_code, json_resp = self._make_rest_call(FORTIGATE_GET_ADDRESSES.format(ip=ip_addr_obj_name), method='delete')
        if self._logger:
            self._logger.info("_delete_address {} {}".format(ret_code, json_resp))
        if ret_code != common.SUCCESS:
            return (ret_code, None)
        if json_resp.get('resource_not_available'):
            return (common.SUCCESS, False)
        return (common.SUCCESS, True)

    def unblock_ip(self, cidr, direction, **kwargs):
        return common.unblock_ip_wrapper(self, cidr, direction, **kwargs)

    def _unblock_ip(self, cidr, egress):
        ret_val = self._login()
        if ret_val != common.SUCCESS:
            if self._logger:
                self._logger.info("Login {} failed. status {}".format(self._device, ret_val))
            return "Login {} failed. status {}".format(self._device, ret_val)

        ip, net_size, net_mask = self._break_ip_addr(cidr)
        ip_addr_obj_name = 'Stellar_Cyber_Addr_{0}_{1}'.format(ip, net_size)
        ip_addr_obj_old_name = 'Stellar Cyber Addr {0}_{1}'.format(ip, net_size)

        addr_status, addr_exists = self._is_address_available(ip_addr_obj_name)
        old_addr_status, old_addr_exists = self._is_address_available(ip_addr_obj_old_name)
        if addr_status != common.SUCCESS or old_addr_status != common.SUCCESS:
            if self._logger:
                self._logger.info("Lookup address {} failed. status {}".format(ip_addr_obj_name, addr_status))
            return "Lookup address {} failed. status {}".format(ip_addr_obj_name, addr_status)

        if not (addr_exists or old_addr_exists):
            if self._logger:
                self._logger.info("Address {} does not exist".format(ip_addr_obj_name))
            return "Address {} does not exist".format(ip_addr_obj_name)

        if egress:
            addrgrp_name = self._dst_address_grp
        else:
            addrgrp_name = self._src_address_grp

        grp_status, addrgrp = self._make_rest_call(FORTIGATE_GET_ADDRGRP.format(addrgrp=addrgrp_name),
             method='get')
        if grp_status != common.SUCCESS or addrgrp.get('resource_not_available'):
            if self._logger:
                self._logger.info("Not able to find the addrgrp {}".format(addrgrp_name))
            return "Not able to find the addrgrp {}".format(addrgrp_name)

        mem_list = addrgrp['results'][0]['member']
        member = []
        addr_found = False
        old_addr_found = False
        for item in mem_list:
            if str(item["name"]) == ip_addr_obj_name:
                addr_found = True
                continue
            elif str(item["name"]) == ip_addr_obj_old_name:
                old_addr_found = True
                continue
            else:
                member.append({"name":str(item["name"])})

        if not (addr_found or old_addr_found):
            if self._logger:
                self._logger.info("Address {} not found in addrgrp {}".format(
                    ip_addr_obj_name, addrgrp_name))
            return common.SUCCESS

        payload = {"json":{'member':member}}
        remove_addr_status, aa_response = self._make_rest_call(FORTIGATE_SET_ADDRGRP.format(addrgrp_name),
             data=repr(payload), method='put')
        if remove_addr_status != common.SUCCESS:
            if self._logger:
                self._logger.info("Not able to remove address {} from the addrgrp {}".format(
                    ip_addr_obj_name, addrgrp_name))
            return "Not able to remove address {} from the addrgrp {}".format(ip_addr_obj_name, addrgrp_name)

        # Try to remove the address object after unbind from address group
        if addr_found:
            self._delete_address(ip_addr_obj_name)
        if old_addr_found:
            self._delete_address(ip_addr_obj_old_name)

        return remove_addr_status

    def block_ip(self, cidr, direction, **kwargs):
        return common.block_ip_wrapper(self, cidr, direction, **kwargs)

    def _block_ip(self, cidr, egress):
        ret_val = self._login()
        if ret_val != common.SUCCESS:
            if self._logger:
                self._logger.info("Login {} failed. status {}".format(self._device, ret_val))
            return "Login {} failed. status {}".format(self._device, ret_val)

        ip, net_size, net_mask = self._break_ip_addr(cidr)
        ip_addr_obj_name = 'Stellar_Cyber_Addr_{0}_{1}'.format(ip, net_size)
        ip_addr_obj_old_name = 'Stellar Cyber Addr {0}_{1}'.format(ip, net_size)

        addr_status, addr_exists = self._is_address_available(ip_addr_obj_name)
        old_addr_status, old_addr_exists = self._is_address_available(ip_addr_obj_old_name)
        if addr_status != common.SUCCESS or old_addr_status != common.SUCCESS:
            if self._logger:
                self._logger.info("Lookup address {} failed. status {}".format(ip_addr_obj_name, addr_status))
            return "Lookup address {} failed. status {}".format(ip_addr_obj_name, addr_status)

        if not addr_exists:
            address_create_params = {FORTIGATE_JSON_NAME: ip_addr_obj_name,
                FORTIGATE_JSON_TYPE: FORTIGATE_JSON_IP_MASK,
                FORTIGATE_JSON_SUBNET: '{0} {1}'.format(ip, net_mask)}
            add_addr_status, add_addr_response = self._make_rest_call(FORTIGATE_ADD_ADDRESS,
                 data=repr(address_create_params), method='post')
            if add_addr_status != common.SUCCESS:
                if self._logger:
                    self._logger.info("Create address object {} failed. status {}".format(
                        ip_addr_obj_name, add_addr_status))
                return "Create address object {} failed. status {}".format(ip_addr_obj_name, add_addr_status)

        if egress:
            addrgrp_name = self._dst_address_grp
        else:
            addrgrp_name = self._src_address_grp

        grp_status, addrgrp = self._make_rest_call(FORTIGATE_GET_ADDRGRP.format(addrgrp=addrgrp_name),
             method='get')
        if grp_status != common.SUCCESS or addrgrp.get('resource_not_available'):
            if self._logger:
                self._logger.info("Not able to find the addrgrp {}".format(addrgrp_name))
            return "Not able to find the addrgrp {}".format(addrgrp_name)

        mem_list = addrgrp['results'][0]['member']
        member = []
        old_addr_found = False
        for item in mem_list:
            if str(item["name"]) == ip_addr_obj_name:
                if self._logger:
                    self._logger.info("Address {} is already in addrgrp {}".format(
                        ip_addr_obj_name, addrgrp_name))
                return common.SUCCESS
            elif str(item["name"]) == ip_addr_obj_old_name:
                old_addr_found = True
                if self._logger:
                    self._logger.info("Address {} is already in addrgrp {} and the policy will be updated with new name {}".format(
                        ip_addr_obj_old_name, addrgrp_name, ip_addr_obj_name))
                continue
            member.append({"name":str(item["name"])})
        member.append({"name":ip_addr_obj_name})
        payload = {"json":{'member':member}}
        add_addr_status, aa_response = self._make_rest_call(FORTIGATE_SET_ADDRGRP.format(addrgrp_name),
             data=repr(payload), method='put')
        if add_addr_status != common.SUCCESS:
            if self._logger:
                self._logger.info("Not able to add address {} to the addrgrp {}".format(
                    ip_addr_obj_name, addrgrp_name))
            return "Not able to add address {} to the addrgrp {}".format(ip_addr_obj_name, addrgrp_name)
        
        if old_addr_found:
            self._delete_address(ip_addr_obj_old_name)
        
        return add_addr_status

    def _test_connection(self, **kwargs):
        run_on = kwargs.get("run_on", "dp")
        if run_on != "" and run_on != "dp":
            return self.notify_ds_to_test_connection(run_on)
        # First login, then query both address groups
        ret_val = self._login()
        if ret_val != common.SUCCESS:
            if self._logger:
                self._logger.info("Login {} failed. status {}".format(self._device, ret_val))
            return utils.create_response("Fortigate", 400, "Login {} failed. status {}".format(self._device, ret_val))

        for group_name in [self._src_address_grp, self._dst_address_grp]:
            ret_val, addrgrp = self._make_rest_call(FORTIGATE_GET_ADDRGRP.format(
                addrgrp=group_name), method='get')

            if ret_val != common.SUCCESS:
                if self._logger:
                    self._logger.info("Query addrgrp {} failed. status {}".format(group_name, ret_val))
                return utils.create_response("Fortigate", 400, "Query addrgrp {} failed. status {}".format(group_name, ret_val))

            if addrgrp.get('resource_not_available'):
                if self._logger:
                    self._logger.info("Address group {} does not exist".format(group_name))
                return utils.create_response("Fortigate", 400, "Address group {} does not exist".format(group_name))
        return utils.create_response("Fortigate", 200, common.SUCCESS)

    def notify_ds_to_test_connection(self, run_on):
        """
        Notify DS to perform the connection test
        :param run_on: str: the engid of sensor to run the test
        :return: str: the test results
        """
        script_path = "/opt/aelladata/connector/modules/firewall/fortigate.py"
        password = utils.aella_encode(utils.COLLECTOR_SECRET, self._api_password)
        command = "export PYTHONPATH={}; python {} -a test -v {} -u \"{}\" -p \"{}\" -s \"{}\" -d \"{}\" -n \"{}\" -t {}".format(
                  utils.PYTHONPATH, script_path, self._device, self._api_username,
                  password, self._src_address_grp, self._dst_address_grp,
                  self._vdom, self._port)
        status_code, error_msg = utils.execute_action_on_ds(run_on, command, retry_count=1)
        if status_code > 0:
            return utils.error_msg_process("Fortigate", error_msg)
        return utils.create_response("Fortigate", 200, common.SUCCESS)

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
        script_path = "/opt/aelladata/connector/modules/firewall/fortigate.py"
        password = utils.aella_encode(utils.COLLECTOR_SECRET, self._api_password)
        command = "export PYTHONPATH={}; python {} -a {} -v {} -u \"{}\" -p \"{}\" -s \"{}\" -d \"{}\" -n \"{}\" -t {} -c {} -e {}".format(
                  utils.PYTHONPATH, script_path, action, self._device, self._api_username,
                  password, self._src_address_grp, self._dst_address_grp,
                  self._vdom, self._port, cidr, egress)
        status_code, error_msg = utils.execute_action_on_ds(run_on, command)
        if status_code > 0:
            return "Firewall action on sensor fail with status code {}: {}".format(status_code, error_msg)
        return common.SUCCESS

if __name__ == '__main__':
    LOG_FILENAME = "/var/log/aella/firewall_action.log"
    FORMAT = "%(asctime)-15s|%(name)s|%(levelname)s|%(message)s"
    logger = logging.getLogger("fortigate_firewall")
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
    parser.add_argument('-u', '--username', action='store', dest='username', required=True,
        help='The username to login firewall')
    parser.add_argument('-p', '--password', action='store', dest='password', required=True,
        help='The password to login firewall')
    parser.add_argument('-s', '--src_ip_grp_name', action='store', dest='src_ip_grp_name', required=True,
        help='The name for source IP group')
    parser.add_argument('-d', '--dst_ip_grp_name', action='store', dest='dst_ip_grp_name', required=True,
        help='The name for destination IP group')
    parser.add_argument('-t', '--port', action='store', dest='port', required=False,
        help='The port to reach firewall')
    parser.add_argument('-n', '--domain', action='store', dest='vdom', required=False,
        help='The domain name')
    parser.add_argument('-c', '--cidr', action='store', dest='cidr', required=False,
        help='The CIDR as input of action')
    parser.add_argument('-e', '--egress', action='store', dest='egress', required=False,
        help='True if direction is egress')

    results = parser.parse_args()

    firewall_connector = FortigateConnector(results.username, results.password,
                                            results.device, results.vdom,
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
