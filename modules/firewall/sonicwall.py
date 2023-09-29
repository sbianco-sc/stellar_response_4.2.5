#!/usr/bin/env python
import argparse
import logging
import logging.handlers
import random
import sys
import os
import json
import requests
import time

import firewall.common as common

import utils

LOGIN_RETRY_WAIT = 5
LOGIN_RETRY_COUNT = 10
PERMISSION_RETRY_WAIT = 5
PERMISSION_RETRY_COUNT = 10
DEFAULT_PORT = 443
DEFAULT_TIMEOUT = 20
HEADERS= {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "Accept-Encoding": "application/json",
}

UNAUTHORIZED_ERR_CODE = "E_UNAUTHORIZED"
ACCESS_DENIED_CODE = "E_ACCESS_DENIED"
READ_ONLY_CODE = "E_READ_ONLY"
MULTIPLE_LOGIN_MSG = {
    ACCESS_DENIED_CODE: "Connection not allowed: reached maximum number of sessions.",
    READ_ONLY_CODE: "An administrator is already logged in for configuration."
}
NOT_FOUND_CODE = "E_NO_MATCH"

AUTH_PATH = "auth"
COMMIT_PATH = "config/pending"
ACCESS_RULES_PATH = "access-rules/ipv4"
ADDRESS_OBJECTS_PATH = "address-objects/ipv4"
ADDRESS_GROUPS_PATH = "address-groups/ipv4"
ZONES_PATH = "zones"
CONFIG_MODE_PATH = "config-mode"

class SonicwallConnector():

    def __init__(self, username, password, device, external_zone,
            src_ip_grp_name, dst_ip_grp_name, lgr=None, **kwargs):
        self._api_username = username
        self._api_password = utils.aella_decode(utils.COLLECTOR_SECRET, password)
        self._device = device
        self._external_zone = external_zone
        self._src_address_grp = src_ip_grp_name
        self._dst_address_grp = dst_ip_grp_name
        self._logger = lgr
        self._port = kwargs.get("port") if "port" in kwargs else DEFAULT_PORT
        self._dev_url = self.get_dev_url(self._device, self._port)
        self._is_v7_or_later = False

    def get_dev_url(self, device, port):
        if device.startswith("http"):
            return "{}:{}/api/sonicos".format(device, port)
        else:
            return "https://{}:{}/api/sonicos".format(device, port)

    def prepare(self, action_name, settings, source):
        return common.prepare(action_name, settings, source)

    def _test_connection(self, **kwargs):
        """
        Function used by Stellar Cyber for configuration validation
        :return: str: 'succeeded' if the connection test passes
            otherwise, a custom message to show to user
        """
        run_on = kwargs.get("run_on", "dp")
        if run_on != "" and run_on != "dp":
            return self.notify_ds_to_test_connection(run_on)
        try:
            login_result = self.login()
            if login_result != common.SUCCESS:
                self.logout()
                return utils.create_response("SonicWall", 400, login_result)

            external_zone = self.get_request(
                    self.get_name_api(ZONES_PATH, self._external_zone))
            if not external_zone.is_response_ok():
                err_msg = "External zone {} not found".format(self._external_zone)
                if not external_zone.get_status_info(NOT_FOUND_CODE):
                    err_msg = external_zone.get_default_error_message(
                            default_msg=err_msg)
                self.logout()
                return utils.create_response("SonicWall", 400, err_msg)

            source_address_grp = self.get_request(
                    self.get_name_api(ADDRESS_GROUPS_PATH, self._src_address_grp))
            if not source_address_grp.is_response_ok():
                err_msg = "Source address group {} not found".format(self._src_address_grp)
                if not source_address_grp.get_status_info(NOT_FOUND_CODE):
                    err_msg = source_address_grp.get_default_error_message(
                        default_msg=err_msg)
                self.logout()
                return utils.create_response("SonicWall", 400, err_msg)

            if self._src_address_grp != self._dst_address_grp:
                dest_address_grp = self.get_request(
                        self.get_name_api(ADDRESS_GROUPS_PATH, self._dst_address_grp))
                if not dest_address_grp.is_response_ok():
                    err_msg = "Destination address group {} not found".format(self._dst_address_grp)
                    if not dest_address_grp.get_status_info(NOT_FOUND_CODE):
                        err_msg = dest_address_grp.get_default_error_message(
                            default_msg=err_msg)
                    self.logout()
                    return utils.create_response("SonicWall", 400, err_msg)

            self.logout()
            return utils.create_response("SonicWall", 200, common.SUCCESS)
        except Exception as e:
            if self._logger:
                self._logger.error("Test connection failed: {}".format(str(e)))
            return utils.create_response("SonicWall", 400, str(e))

    def block_ip(self, cidr, direction, **kwargs):
        return common.block_ip_wrapper(self, cidr, direction, **kwargs)

    def _block_ip(self, cidr, egress):
        return self.block_or_unblock_ip(cidr, egress, block=True)

    def unblock_ip(self, cidr, direction, **kwargs):
        return common.unblock_ip_wrapper(self, cidr, direction, **kwargs)

    def _unblock_ip(self, cidr, egress):
        return self.block_or_unblock_ip(cidr, egress, block=False)

    def block_or_unblock_ip(self, cidr, egress, block=True):
        reply, login_result = self.login(return_reply=True)
        if login_result != common.SUCCESS:
            self.logout()
            return "SonicWall login failed: " + login_result
        
        info = reply.get("status", {}).get("info", None)
        if info and "config_mode" in info[0]:
            self._is_v7_or_later = True
            if info[0]["config_mode"] == "No":
                enter_config_mode_result = self.enter_config_mode()
                if enter_config_mode_result != common.SUCCESS:
                    self.logout()
                    return "SonicWall enter config mode failed: " + enter_config_mode_result

        if not self.address_exists(cidr):
            result = self.create_address_obj(cidr)
            if not result.is_response_ok():
                self.logout()
                return "SonicWall create address obj failed: " + result.get_default_error_message(
                    default_msg="Could not create address object for {}".format(
                        cidr))
        address_group_name = self._dst_address_grp if egress \
                else self._src_address_grp
        api = self.get_name_api(ADDRESS_GROUPS_PATH, address_group_name)
        address_group_req = self.get_request(api)
        address_group_obj = address_group_req.get_reply()
        if address_group_obj.has_key("address_group"):
            contents = address_group_obj["address_group"]
            address_group_obj = {"address_groups": [contents]}
        if not self.is_valid_address_group(address_group_obj):
            self.logout()
            return "Failed to retrieve info for address group {}".format(
                    address_group_name)
        result = self.update_address_group(address_group_obj, cidr, block)
        if result != common.SUCCESS:
            self.logout()
            return "SonicWall update address group failed: " + result

        commit_result = self.commit_changes()
        self.logout()
        if commit_result != common.SUCCESS:
            return "SonicWall commit changes failed: " + commit_result
        return commit_result

    def address_exists(self, cidr):
        address_name = self.get_address_name(cidr)
        api = self.get_name_api(ADDRESS_OBJECTS_PATH, address_name)
        address_obj = self.get_request(api)
        return not address_obj.is_not_found()

    def create_address_obj(self, cidr):
        body = self.get_address_obj(cidr)
        reply = self.post_request(
                ADDRESS_OBJECTS_PATH, data=body)
        return reply

    def get_address_name(self, cidr):
        rule_name = ["stellar"]
        rule_name.append(cidr.replace("/", "_"))
        rule_name.append(self._external_zone)
        return "-".join(rule_name)

    def get_address_obj(self, cidr):
        address_name = self.get_address_name(cidr)
        addr_obj = {
            "address_object": {
                "ipv4": {
                    "name": address_name,
                    "zone": self._external_zone
                }
            }
        }
        ip, mask = cidr.split("/")
        if mask == "32":
            addr_obj["address_object"]["ipv4"]["host"] = {"ip": ip}
        else:
            addr_obj["address_object"]["ipv4"]["network"] = {
                    "subnet": ip,
                    "mask": "/{}".format(mask)
            }

        contents = addr_obj["address_object"]
        address_objects = {"address_objects": [contents]}
        return address_objects

    def is_valid_address_group(self, address_group_obj):
        if not address_group_obj.has_key("address_groups"):
            return False
        if not address_group_obj["address_groups"][0].has_key("ipv4"):
            return False
        address_group = address_group_obj["address_groups"][0]["ipv4"]
        if not address_group.has_key("name") or not address_group.has_key("address_object"):
            if self._logger:
                self._logger.info("Missing name or address_object from address_group")
            return False
        return True

    def update_address_group(self, address_group_obj, cidr, block):
        address_group = address_group_obj["address_groups"][0]["ipv4"]
        address_group_name = address_group["name"]
        if block:
            return self.add_cidr_to_address_group(
                    cidr, address_group_obj)
        else:
            return self.remove_cidr_from_address_group(
                    cidr, address_group_obj)

    def add_cidr_to_address_group(self, cidr, address_group_obj):
        address_group_name = self.get_address_group_name(
                address_group_obj)
        if self.is_cidr_in_address_group(cidr, address_group_obj):
            if self._logger:
                self._logger.info("Address {} is already in the address group {}".format(cidr, address_group_name))
            return common.SUCCESS
        if self._is_v7_or_later:
            data = self.add_address_obj_to_address_group(cidr, address_group_obj)
        else:
            data = self.get_address_group_update_obj(cidr, address_group_obj)
        update_api = self.get_name_api(ADDRESS_GROUPS_PATH,
                address_group_name)
        result = self.put_request(update_api, data=data)
        if result.is_response_ok():
            return common.SUCCESS
        return result.get_default_error_message(
                default_msg="Failed to add {} to address group {}".format(
                    cidr, address_group_name))

    def remove_cidr_from_address_group(self, cidr, address_group_obj):
        address_group_name = self.get_address_group_name(
                address_group_obj)
        if not self.is_cidr_in_address_group(cidr, address_group_obj):
            if self._logger:
                self._logger.info("Address {} is already removed from the address group {}".format(cidr, address_group_name))
            return common.SUCCESS
        update_api = self.get_name_api(ADDRESS_GROUPS_PATH,
                address_group_name)
        if self._is_v7_or_later:
            data = self.remove_address_obj_from_address_group(cidr, address_group_obj)
            result = self.put_request(update_api, data=data)
        else:
            data = self.get_address_group_update_obj(cidr, address_group_obj)
            result = self.delete_request(update_api, data=data)
        if result.is_response_ok():
            return common.SUCCESS
        return result.get_default_error_message(
            default_msg="Failed to remove {} from address group {}".format(
                cidr, address_group_name))

    def add_address_obj_to_address_group(self, cidr, address_group_obj):
        request_body = address_group_obj
        address_name = self.get_address_name(cidr)
        address_objects = self.get_address_group_address_object(address_group_obj)
        new_address_object = {"name": address_name}
        request_body["address_groups"][0]["ipv4"]["address_object"]["ipv4"].append(new_address_object)
        if self._logger:
            self._logger.info("Adding {0} and constructed request_body: {1}".format(address_name, request_body))
        return request_body

    def remove_address_obj_from_address_group(self, cidr, address_group_obj):
        request_body = address_group_obj
        address_name = self.get_address_name(cidr)
        address_objects = self.get_address_group_address_object(address_group_obj)
        if len(address_objects["ipv4"]) == 1:
            del request_body["address_groups"][0]["ipv4"]["address_object"]
        else:
            remove_address_object = {"name": address_name}
            request_body["address_groups"][0]["ipv4"]["address_object"]["ipv4"].remove(remove_address_object)
        if self._logger:
            self._logger.info("Removed {0} and constructed request_body: {1}".format(address_name, request_body))
        return request_body

    def get_address_group_update_obj(self, cidr, address_group_obj):
        address_name = self.get_address_name(cidr)
        address_group_name = self.get_address_group_name(
                address_group_obj)
        address_group_uuid = self.get_address_group_uuid(
                address_group_obj)
        return {
            "address_group": {
                "ipv4": {
                    "name": address_group_name,
                    "uuid": address_group_uuid,
                    "address_object": {
                        "ipv4": [
                            {"name": address_name}
                        ]
                    }
                }
            }
        }


    def is_cidr_in_address_group(self, cidr, address_group_obj):
        address_name = self.get_address_name(cidr)
        address_object = self.get_address_group_address_object(
                address_group_obj)
        if "ipv4" not in address_object:
            return False
        for address in address_object["ipv4"]:
            if address.get("name") == address_name:
                return True
        return False

    def get_address_group_name(self, address_group_obj):
        return address_group_obj["address_groups"][0]["ipv4"]["name"]

    def get_address_group_uuid(self, address_group_obj):
        return address_group_obj["address_groups"][0]["ipv4"]["uuid"]

    def get_address_group_address_object(self, address_group_obj):
        return address_group_obj["address_groups"][0]["ipv4"]["address_object"]

    def login(self, return_reply=False):
        reply = self.post_request(AUTH_PATH)
        if not reply.is_response_ok():
            return reply.get_default_error_message(
                    default_msg="Failed to authenticate")
        if self._logger:
            self._logger.info("login success")
        if return_reply:
            return reply.get_reply(), common.SUCCESS
        return common.SUCCESS

    def enter_config_mode(self):
        reply = self.post_request(CONFIG_MODE_PATH)
        if not reply.is_response_ok():
            return reply.get_default_error_message(
                    default_msg="Failed to enter config-mode")
        if self._logger:
            self._logger.info("successfully entered config-mode")
        return common.SUCCESS

    def logout(self):
        reply = self.delete_request(AUTH_PATH)
        if not reply.is_response_ok():
            return reply.get_default_error_message(
                    default_msg="Failed to log out")
        if self._logger:
            self._logger.info("logout success")
        return common.SUCCESS

    def commit_changes(self):
        reply = self.post_request(COMMIT_PATH)
        if not reply.is_response_ok():
            return reply.get_default_error_message(
                    default_msg="Failed to commit changes")
        return common.SUCCESS

    def post_request(self, api, data=None, params=None):
        return self.make_request(requests.post, api, data, params)

    def put_request(self, api, data=None, params=None):
        return self.make_request(requests.put, api, data, params)

    def delete_request(self, api, data=None, params=None):
        return self.make_request(requests.delete, api, data, params)

    def get_request(self, api, data=None, params=None):
        return self.make_request(requests.get, api, data, params)

    def make_request(self, request_type, api, data=None, params=None,
            already_retried=False):
        if type(data) is dict:
            data = json.dumps(data)
        should_wait_for_permissions = True
        retry_count = 0
        while should_wait_for_permissions and retry_count < PERMISSION_RETRY_COUNT:
            if self._logger:
                self._logger.info(
                    "Making {} request to {} with data: {} and params: {}".format(
                            request_type, api, data, params))
            reply = request_type(
                    self.get_full_api_path(api),
                    headers=HEADERS,
                    auth=(self._api_username, self._api_password),
                    data=data,
                    params=params,
                    verify=False,
                    timeout=DEFAULT_TIMEOUT)
            reply = SonicwallResponse(reply)
            if self._logger:
                try:
                    reply_content = reply.get_reply()
                except Exception as e:
                    reply_content = str(e)
                self._logger.info("{} reply from {}: {}".format(
                    request_type, api, reply_content))
            should_wait_for_permissions = reply.should_wait_for_permissions()
            retry_count += 1
            if should_wait_for_permissions:
                time.sleep(PERMISSION_RETRY_WAIT)
        if api == AUTH_PATH:
            return reply
        if reply.is_response_unauthorized() and not already_retried:
            self.login()
            return self.make_request(request_type, api,
                    data=data, params=params, already_retried=True)
        else:
            return reply

    def get_full_api_path(self, api):
        return "{}/{}".format(self._dev_url, api)

    def get_name_api(self, api, name):
        return "{}/name/{}".format(api, name)

    def get_uuid_api(self, api, uuid):
        return "{}/uuid/{}".format(api, uuid)


    def notify_ds_to_test_connection(self, run_on):
        """
        Notify DS to perform the connection test
        :param run_on: str: the engid of sensor to run the test
        :return: str: the test results
        """
        script_path = "/opt/aelladata/connector/modules/firewall/sonicwall.py"
        password = utils.aella_encode(utils.COLLECTOR_SECRET, self._api_password)
        command = "export PYTHONPATH={}; python {} -a test -v {} -t {} -z \"{}\" -u \"{}\" -p \"{}\" -s \"{}\" -d \"{}\"".format(
                  utils.PYTHONPATH, script_path, self._device, self._port, self._external_zone, self._api_username,
                  password, self._src_address_grp, self._dst_address_grp)
        status_code, error_msg = utils.execute_action_on_ds(run_on, command, retry_count=1)
        if status_code > 0:
            return utils.error_msg_process("SonicWall", error_msg)
        return utils.create_response("SonicWall", 200, common.SUCCESS)

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
        script_path = "/opt/aelladata/connector/modules/firewall/sonicwall.py"
        password = utils.aella_encode(utils.COLLECTOR_SECRET, self._api_password)
        command = "export PYTHONPATH={}; python {} -a {} -v {} -t {} -z \"{}\" -u \"{}\" -p \"{}\" -s \"{}\" -d \"{}\" -c {} -e {}".format(
                  utils.PYTHONPATH, script_path, action, self._device, self._port,
                  self._external_zone, self._api_username, password, self._src_address_grp,
                  self._dst_address_grp, cidr, egress)
        status_code, error_msg = utils.execute_action_on_ds(run_on, command)
        if status_code > 0:
            return "Firewall action on sensor fail with status code {}: {}".format(status_code, error_msg)
        return common.SUCCESS


class SonicwallResponse():

    def __init__(self, reply):
        self.reply = reply

    def get_reply(self):
        try:
            return self.reply.json()
        except ValueError:
            raise Exception("No JSON object could be retrieved: {}".format(
                self.reply.content))

    def is_response_ok(self):
        return self.reply.status_code == 200

    def get_status_info(self, status_code=None):
        status_list = self.reply.json().get("status", {}).get("info", [])
        for status in status_list:
            if status_code is None:
                return status
            if status.get("code") == status_code:
                return status

    def get_default_error_message(self, status_code=None, default_msg=""):
        status = self.get_status_info(status_code)
        return status.get("message") if status else default_msg

    def should_wait_for_permissions(self):
        for error_code in MULTIPLE_LOGIN_MSG:
            info = self.get_status_info(status_code=error_code)
            if info:
                if info.get("message") == MULTIPLE_LOGIN_MSG[error_code]:
                    return True
        return False

    def is_response_unauthorized(self):
        return self.has_error_code(UNAUTHORIZED_ERR_CODE)

    def is_not_found(self):
        return self.has_error_code(NOT_FOUND_CODE)

    def has_error_code(self, code):
        if self.is_response_ok():
            return False
        if self.get_status_info(status_code=code):
            return True
        return False

if __name__ == "__main__":
    LOG_FILENAME = "/var/log/aella/firewall_action.log"
    FORMAT = "%(asctime)-15s|%(name)s|%(levelname)s|%(message)s"
    logger = logging.getLogger("sonicwall_firewall")
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
    parser.add_argument('-z', '--zone', action='store', dest='zone', required=True,
        help='The username to login firewall')
    parser.add_argument('-p', '--password', action='store', dest='password', required=True,
        help='The password to login firewall')
    parser.add_argument('-t', '--port', action='store', dest='port', required=False,
        help='The port of firewall')
    parser.add_argument('-s', '--src_ip_grp_name', action='store', dest='src_ip_grp_name', required=True,
        help='The name for source IP group')
    parser.add_argument('-d', '--dst_ip_grp_name', action='store', dest='dst_ip_grp_name', required=True,
        help='The name for destination IP group')
    parser.add_argument('-c', '--cidr', action='store', dest='cidr', required=False,
        help='The CIDR as input of action')
    parser.add_argument('-e', '--egress', action='store', dest='egress', required=False,
        help='True if direction is egress')

    results = parser.parse_args()

    port = DEFAULT_PORT
    if results.port:
        port = int(results.port)

    kwargs = {"port": port}

    firewall_connector = SonicwallConnector(results.username, results.password,
                                            results.device, results.zone,
                                            results.src_ip_grp_name,
                                            results.dst_ip_grp_name,
                                            lgr=logger, **kwargs)

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
