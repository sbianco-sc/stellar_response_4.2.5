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

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import pdb

import firewall.common as common

import utils

PAN_JSON_VSYS = 'vsys'
BLOCK_IP_GROUP_NAME = 'Stellar Cyber Network List'
BLOCK_IP_GROUP_NAME_SRC = 'Stellar Cyber Network List Source'
TAG_XPATH = "/config/devices/entry/vsys/entry[@name='{vsys}']/tag"
TAG_ELEM = "<entry name='{tag}'><color>{tag_color}</color><comments>{tag_comment}</comments></entry>"
TAG_COLOR = 'color7'
AELLA_ADDRESS_NAME = 'Added By Stellar Cyber'
IP_ADDR_XPATH = "/config/devices/entry/vsys/entry[@name='{vsys}']/address/entry[@name='{ip_addr_name}']"
IP_ADDR_ELEM = '<{type}>{ip}</{type}><tag><member>{tag}</member></tag>'

ADDR_GRP_XPATH = "/config/devices/entry/vsys/entry[@name='{vsys}']/address-group/entry[@name='{ip_group_name}']"
ADDR_GRP_ELEM = '<static><member>{addr_name}</member></static>'
IP_GRP_SEC_POL_ELEM = '<destination><member>{ip_group_name}</member></destination>'
IP_GRP_SEC_POL_ELEM_SRC = '<source><member>{ip_group_name}</member></source>'
DEL_ADDR_GRP_XPATH = "/static/member[text()='{addr_name}']"

PAN_TIMEOUT = int(os.getenv("PAN_TIMEOUT", "600"))
PAN_RETRY = int(os.getenv("PAN_RETRY", "3"))
PAN_DELTA = int(os.getenv("PAN_DELTA", "120"))

class PanConnector():
    def __init__(self, username, password, device, vsys, src_ip_grp_name, dst_ip_grp_name, port=443, lgr=None, **kwargs):
        self._api_username = username
        self._api_password = utils.aella_decode(utils.COLLECTOR_SECRET, password)
        self._device = device
        self._port = int(port)
        self._vsys = vsys
        self._src_address_grp = src_ip_grp_name
        self._dst_address_grp = dst_ip_grp_name
        self._logger = lgr
        self._dev_url = "https://{}/api".format(device)
        if port != 443:
            self._dev_url = "https://{}:{}/api".format(device, port)
        self._dev_key = None
        self._action_result = {}

    def prepare(self, action_name, settings, source):
        return common.prepare(action_name, settings, source)

    def batch_process(self, action):
        common.batch_process(action)

    def _get_key(self):
        data = {'type': 'keygen',
         'user': self._api_username,
         'password': self._api_password}
        try:
            response = requests.post(self._dev_url, data=data, verify=False)
        except Exception as e:
            if self._logger:
                self._logger.info("Cannot get key {}".format(e))
            return "Cannot get key {}".format(e)

        xml = response.text
        try:
            response_dict = xmltodict.parse(xml)
        except Exception as e:
            if self._logger:
                self._logger.info("Cannot parse key {}".format(e))
            return "Cannot parse key {}".format(e)

        response = response_dict.get('response')
        if response is None:
            if self._logger:
                self._logger.info("Key response is missing")
            return "Key response is missing"

        status = response.get('@status')
        if status is None:
            if self._logger:
                self._logger.info("Key status is missing")
            return "Key status is missing"

        if status != 'success':
            json_resp = json.dumps(response).replace('{', ':')
            json_resp = json_resp.replace('}', '')
            message = 'Response from server: {0}'.format(json_resp)
            if self._logger:
                self._logger.info(message)
            return message

        result = response.get('result')
        if result is None:
            if self._logger:
                self._logger.info("Key result is missing")
            return "Key result is missing"

        self._dev_key = result.get('key')
        if self._dev_key is None:
            if self._logger:
                self._logger.info("Key is missing")
            return "Key is missing"

        return common.SUCCESS

    def _parse_response_msg(self, response, action_result):
        msg = response.get('msg')
        if msg is None:
            return
        if isinstance(msg, dict):
            line = msg.get('line')
            if line is None:
                return
            if isinstance(line, list):
                action_result["message"] = "{}".format(', '.join(line))
            else:
                action_result["message"] = "{}".format(line)
            return
        if type(msg) == str or type(msg) == unicode:
            action_result["message"] =  "{}".format(msg)

    def _parse_response(self, response_dict, action_result):
        response = response_dict.get('response')
        if response is None:
            action_result['status'] = 'No response'
            return
        status = response.get('@status')
        if status is None:
            action_result['status'] = 'No status'
            return
        if status != 'success':
            action_result['status'] = 'Not success'
        else:
            action_result['status'] = common.SUCCESS
        code = response.get('@code')
        if code is not None:
            action_result['code'] = "{}".format(code)
        self._parse_response_msg(response, action_result)

        # for enqueued request
        #  {"@status": "success", "@code": "19", "result": {"msg": {"line": "Commit job enqueued with jobid 35"}, "job": "35"}}
        result = response.get('result')
        if result is not None:
            action_result["data"] = result

        # If there is no result field, the success state means it is done.
        # {"@status": "success", "@code": "20", "msg": "command succeeded"}

        # return full information if it is not successful
        if action_result['status'] != common.SUCCESS:
            return "Palo Alto Networks Firewall failed to perform the action: {}".format(str(action_result))
        
        return common.SUCCESS

    def _make_rest_call(self, data, action_result):
        try:
            response = requests.post(self._dev_url, data=data, verify=False)
        except Exception as e:
            if self._logger:
                self._logger.info("Rest call failed {}".format(e))
            action_result['status'] = 'Rest call failed {}'.format(e)
            return "Exception in making the rest call: {}".format(str(e))

        xml = response.text
        try:
            response_dict = xmltodict.parse(xml)
        except Exception as e:
            if self._logger:
                self._logger.info("Parse rest call xml failed {}".format(e))
            action_result['status'] = "Parse rest call xml failed {}".format(e)
            return "Exception in parsing the rest call xml: {}".format(str(e))

        status = self._parse_response(response_dict, action_result)
        return status

    def _get_addr_name(self, ip):
        rem_slash = lambda x: re.sub('(.*)/(.*)', '\\1 mask \\2', x)
        name = '{0} {1}'.format(rem_slash(ip), AELLA_ADDRESS_NAME)
        return name

    def _add_address(self, block_ip, action_result):
        addr_type = 'ip-netmask'
        name = None
        tag = 'Stellar Cyber address'
        data = {'type': 'config',
            'action': 'set',
            'key': self._dev_key,
            'xpath': TAG_XPATH.format(vsys=self._vsys),
            'element': TAG_ELEM.format(tag=tag, tag_comment='Stellar Cyber Data action', tag_color=TAG_COLOR)}
        status = self._make_rest_call(data, action_result)
        if status != common.SUCCESS:
            return (status, name)

        name = self._get_addr_name(block_ip)
        address_xpath = IP_ADDR_XPATH.format(vsys=self._vsys, ip_addr_name=name)
        data = {'type': 'config',
         'action': 'set',
         'key': self._dev_key,
         'xpath': address_xpath,
         'element': IP_ADDR_ELEM.format(type=addr_type, ip=block_ip, tag=tag)}
        status = self._make_rest_call(data, action_result)
        return (status, name)

    def _commit_config(self, action_result):
        data = {'type': 'commit',
         'action': 'partial',
         'cmd': '<commit><partial><admin><member>{}</member></admin></partial></commit>'.format(self._api_username),
         'key': self._dev_key}
        status = self._make_rest_call(data, action_result)
        if status != common.SUCCESS:
            return status
        result_data = action_result.get("data", {})
        if len(result_data) == 0:
            if self._logger:
                self._logger.info("No task enqueue, got msg: {}".format(
                    action_result.get("message", "")))
            return status

        job_id = result_data['job']
        if self._logger:
            self._logger.info('Commit job id: {}'.format(job_id))
        while True:
            data = {'type': 'op',
             'key': self._dev_key,
             'cmd': '<show><jobs><id>{job}</id></jobs></show>'.format(job=job_id)}
            status_action_result = {}
            status = self._make_rest_call(data, status_action_result)
            if status != common.SUCCESS:
                action_result['message'] = status_action_result.get('message', '')
                return common.SUCCESS
            result_data = status_action_result.get('data', [])
            job = result_data['job']
            if job['status'] == 'FIN':
                break
            time.sleep(2)

        return status

    def block_ip(self, cidr, direction, **kwargs):
        return common.block_ip_wrapper(self, cidr, direction, **kwargs)

    def _block_one_ip(self, cidr, block_ip_grp):
        # Deal with one ip without commit
        self._logger.info("Block one ip {}, {}".format(cidr, block_ip_grp))
        status, addr_name = self._add_address(cidr, self._action_result)
        if status != common.SUCCESS:
            return status
        data = {'type': 'config',
            'action': 'set',
            'key': self._dev_key,
            'xpath': ADDR_GRP_XPATH.format(vsys=self._vsys, ip_group_name=block_ip_grp),
            'element': ADDR_GRP_ELEM.format(addr_name=addr_name)}
        status = self._make_rest_call(data, self._action_result)
        return status

    def _block_ip(self, cidr, egress):
        status = self._get_key()
        if status != common.SUCCESS:
            return "Login failed"
        if egress:
            block_ip_grp = self._dst_address_grp
        else:
            block_ip_grp = self._src_address_grp

        if isinstance(cidr, list):
            if len(cidr) > 1:
                self._logger.info("Block ip list {}".format(cidr))

            for cidr_1 in cidr:
                status = self._block_one_ip(cidr_1, block_ip_grp)
                if status != common.SUCCESS:
                    return status
        else:
            status = self._block_one_ip(cidr, block_ip_grp)
            if status != common.SUCCESS:
                return status

        status = self._commit_config(self._action_result)
        return status

    def unblock_ip(self, cidr, direction, **kwargs):
        return common.unblock_ip_wrapper(self, cidr, direction, **kwargs)

    def _unblock_one_ip(self, cidr, block_ip_grp):
        self._logger.info("Unblock one ip {}, {}".format(cidr, block_ip_grp))
        addr_name = self._get_addr_name(cidr)
        xpath = '{0}{1}'.format(ADDR_GRP_XPATH.format(vsys=self._vsys, ip_group_name=block_ip_grp), DEL_ADDR_GRP_XPATH.format(addr_name=addr_name))
        data = {'type': 'config',
         'action': 'delete',
         'key': self._dev_key,
         'xpath': xpath}
        status = self._make_rest_call(data, self._action_result)
        return status

    def _unblock_ip(self, cidr, egress):
        status = self._get_key()
        if status != common.SUCCESS:
            return "Login failed"
        if egress:
            block_ip_grp = self._dst_address_grp
        else:
            block_ip_grp = self._src_address_grp

        if isinstance(cidr, list):
            if len(cidr) > 1:
                self._logger.info("Unblock ip list {}".format(cidr))
            for cidr_1 in cidr:
                status = self._unblock_one_ip(cidr_1, block_ip_grp)
                if status != common.SUCCESS:
                    return status
        else:
            status = self._unblock_one_ip(cidr, block_ip_grp)
            if status != common.SUCCESS:
                return status

        status = self._commit_config(self._action_result)
        return status

    def _test_connection(self, **kwargs):
        run_on = kwargs.get("run_on", "dp")
        if run_on != "" and run_on != "dp":
            return self.notify_ds_to_test_connection(run_on)
        status = self._get_key()
        if status == common.SUCCESS:
            code = 200
        else:
            code = 400
        return utils.create_response("Palo Alto Networks Firewall", code, status)

    def notify_ds_to_test_connection(self, run_on):
        """
        Notify DS to perform the connection test
        :param run_on: str: the engid of sensor to run the test
        :return: str: the test results
        """
        script_path = "/opt/aelladata/connector/modules/firewall/pan.py"
        password = utils.aella_encode(utils.COLLECTOR_SECRET, self._api_password)
        command = "export PYTHONPATH={}; python {} -a test -v {} -t {} -y \"{}\" -u \"{}\" -p \"{}\" -s \"{}\" -d \"{}\"".format(
                  utils.PYTHONPATH, script_path, self._device, self._port, self._vsys, self._api_username,
                  password, self._src_address_grp, self._dst_address_grp)
        status_code, error_msg = utils.execute_action_on_ds(run_on, command, retry_count=1)
        if status_code > 0:
            return utils.error_msg_process("Palo Alto Networks Firewall", error_msg)
        return utils.create_response("Palo Alto Networks Firewall", 200, common.SUCCESS)

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
        if isinstance(cidr, list):
            cidr = ",".join(cidr)
        script_path = "/opt/aelladata/connector/modules/firewall/pan.py"
        password = utils.aella_encode(utils.COLLECTOR_SECRET, self._api_password)
        command = "export PYTHONPATH={}; python {} -a {} -v {} -t {} -y \"{}\" -u \"{}\" -p \"{}\" -s \"{}\" -d \"{}\" -c {} -e {}".format(
                  utils.PYTHONPATH, script_path, action, self._device, self._port, self._vsys, self._api_username,
                  password, self._src_address_grp, self._dst_address_grp,
                  cidr, egress)
        # especially with PAN v9, we need around ten minutes for blocking/unblocking actions to be finished
        status_code, error_msg = utils.execute_action_on_ds(run_on=run_on, command=command, timeout=PAN_TIMEOUT, retry_count=PAN_RETRY, retry_delta=PAN_DELTA)
        if status_code > 0:
            return "Firewall action on sensor fail with status code {}: {}".format(status_code, error_msg)
        return common.SUCCESS

if __name__ == '__main__':
    LOG_FILENAME = "/var/log/aella/firewall_action.log"
    FORMAT = "%(asctime)-15s|%(name)s|%(levelname)s|%(message)s"
    logger = logging.getLogger("pan_firewall")
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
    parser.add_argument('-y', '--vsys', action='store', dest='vsys', required=True,
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

    firewall_connector = PanConnector(results.username, results.password,
                                      results.device, results.vsys,
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
            res = firewall_connector._block_ip(results.cidr.split(","), egress)
        except Exception as e:
            sys.stderr.write("Failed to block ip: {} \n".format(e))
            sys.exit(1)
    elif results.action == "unblock_ip":
        try:
            res = firewall_connector._unblock_ip(results.cidr.split(","), egress)
        except Exception as e:
            sys.stderr.write("Failed to unblock ip: {}\n".format(e))
            sys.exit(1)
    if res != "Success":
        sys.stderr.write("Failed to perform {}: {}\n".format(results.action, res))
        sys.exit(1)
