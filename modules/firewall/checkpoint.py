#!/usr/bin/env python
import argparse
import logging
import logging.handlers
import random
import os
import sys
import time
import json

from firewall.cplib import APIClient, APIClientArgs
import firewall.common as common
import utils

DEFAULT_RETRIES = 5
DEFAULT_RETRY_SLEEP = 60

class CheckpointConnector():
    def __init__(self, username, password, device, src_ip_grp_name, dst_ip_grp_name, policy_name, port=443, lgr=None, domain=None, **kwargs):
        # unsafe means not going to check fingerprint of server certificate
        self._client_args = APIClientArgs(server=device, port=port, unsafe=True)
        self._device = device
        self._port = int(port)
        self._api_username = username
        self._api_password = utils.aella_decode(utils.COLLECTOR_SECRET, password)
        self._domain = domain
        if not self._domain:
            self._domain = "SMC User"
        self._src_address_grp = src_ip_grp_name
        self._dst_address_grp = dst_ip_grp_name
        self._policy_name = policy_name

        # filename to debug request/response data
        self._debug_file = 'api_json'

        self._logger = lgr

    def prepare(self, action_name, settings, source):
        return common.prepare(action_name, settings, source)

    def block_ip(self, cidr, direction, **kwargs):
        return common.block_ip_wrapper(self, cidr, direction, **kwargs)

    def _run_action_on_ds(self, action, cidr, egress, run_on):
        script_path = "/opt/aelladata/connector/modules/firewall/checkpoint.py"
        password = utils.aella_encode(utils.COLLECTOR_SECRET, self._api_password)
        command = "export PYTHONPATH={}; python {} -a {} -v \"{}\" -t {} -u \"{}\" -p \"{}\" -s \"{}\" -d \"{}\" -l \"{}\" -n \"{}\" -c {} -e {}".format(
                  utils.PYTHONPATH, script_path, action, self._device, self._port, self._api_username,
                  password, self._src_address_grp, self._dst_address_grp,
                  self._policy_name, self._domain, cidr, egress)
        status_code, error_msg = utils.execute_action_on_ds(run_on, command)
        if status_code > 0:
            return "Firewall action on sensor fail with status code {}: {}".format(status_code, error_msg)
        return common.SUCCESS

    def _block_ip(self, cidr, egress, retries=DEFAULT_RETRIES):
        if self._logger:
            self._logger.info("Trying to block ip {} egress {}".format(cidr, egress))

        # cidr is ip/32, take out the ip part
        cidr = cidr[:-3]

        with APIClient(self._client_args) as client:
            client.debug_file = self._debug_file

            # login
            login_res = client.login(self._api_username, self._api_password, domain=self._domain)
            if login_res.success is False:
                if self._logger:
                    self._logger.info("Login failed. status {}".format(login_res.error_message))
                return "Login failed. status {}".format(login_res.error_message)

            if egress:
                block_ip_grp = self._dst_address_grp
            else:
                block_ip_grp = self._src_address_grp

            # First, check if the ip is already defined, if not, create ip range for it
            # The address range it created name start with stellar_
            ar_name = "stellar_{}".format(cidr)
            payload = {"name":ar_name}
            get_ar_res = client.api_call("show-address-range", payload=payload)
            if get_ar_res.success is False:
                if self._logger:
                    self._logger.info("Need to create address range object for {}".format(cidr))
                # Create new address range
                payload = {
                    "name": ar_name,
                    "ip-address-first": cidr,
                    "ip-address-last": cidr,
                    "groups": [block_ip_grp]
                }
                add_ar_res = client.api_call("add-address-range", payload=payload)
                if add_ar_res.success is False:
                    if self._logger:
                        self._logger.info("Failed to add address range: {}".format(add_ar_res.error_message))
                    return "Failed to add address range: {}".format(add_ar_res.error_message)
            else:
                # Address range object exist
                # First check if the address range is already in the group
                groups = get_ar_res.data.get("groups", [])
                grp_names = []
                for grp in groups:
                    gname = grp["name"]
                    if gname == block_ip_grp:
                        if self._logger:
                            self._logger.info("Address {} is already in the group {}".format(cidr, block_ip_grp))
                        return "Address {} is already in the group {}".format(cidr, block_ip_grp)
                    grp_names.append(gname)
                # Update the address range to be in the group
                grp_names.append(block_ip_grp)
                payload = {"name": ar_name, "groups": grp_names}
                set_ar_res = client.api_call("set-address-range", payload=payload)
                if set_ar_res.success is False:
                    if self._logger:
                        self._logger.info("Failed to add address range to group: {}".format(set_ar_res.error_message))
                    return "Failed to add address range to group: {}".format(set_ar_res.error_message)

            # To this point, the configuration has been changed, need to publish and install policy to targets
            result = self._publish_and_install(client)
            if "Failed to publish configuration" in result and retries > 0:
                time.sleep(DEFAULT_RETRY_SLEEP)
                return self._block_ip("{}/32".format(cidr), egress, retries=retries-1)
            return result

    def unblock_ip(self, cidr, direction, **kwargs):
        return common.unblock_ip_wrapper(self, cidr, direction, **kwargs)

    def _unblock_ip(self, cidr, egress, retries=DEFAULT_RETRIES):
        if self._logger:
            self._logger.info("Trying to unblock ip {} egress {}".format(cidr, egress))

        # cidr is ip/32, take out the ip part
        cidr = cidr[:-3]

        with APIClient(self._client_args) as client:
            client.debug_file = self._debug_file

            # login
            login_res = client.login(self._api_username, self._api_password, domain=self._domain)
            if login_res.success is False:
                if self._logger:
                    self._logger.info("Login failed. status {}".format(login_res.error_message))
                return "Login failed. status {}".format(login_res.error_message)

            if egress:
                block_ip_grp = self._dst_address_grp
            else:
                block_ip_grp = self._src_address_grp

            ar_name = "stellar_{}".format(cidr)
            payload = {"name": ar_name}
            get_ar_res = client.api_call("show-address-range", payload=payload)
            if get_ar_res.success is False:
                if self._logger:
                    self._logger.info("Cannot get address range object for {}".format(cidr))
                return "Cannot get address range object for {}".format(cidr)
            else:
                # Find address range object exist
                groups = get_ar_res.data.get("groups", [])
                grp_names = []
                grp_found = False
                for grp in groups:
                    gname = grp["name"]
                    if gname == block_ip_grp:
                        grp_found = True
                    else:
                        grp_names.append(gname)

                if not grp_found:
                    if self._logger:
                        self._logger.info("Address range for {} is not in group {}".format(cidr, block_ip_grp))
                    return "Address range for {} is not in group {}".format(cidr, block_ip_grp)

                if self._logger:
                    self._logger.info("Update address range {} in group {}".format(ar_name, block_ip_grp))
                # Update the address range
                payload = {"name": ar_name, "groups": grp_names}
                update_ar_res = client.api_call("set-address-range", payload=payload)
                if update_ar_res.success is False:
                    if self._logger:
                        self._logger.info("Failed to update address range object {}, {}".format(ar_name, update_ar_res.error_message))
                    return "Failed to update address range object {}, {}".format(ar_name, update_ar_res.error_message)

                # If the groups is not empty, remove the address range, otherwise update it with groups info
                if len(grp_names) == 0:
                    if self._logger:
                        self._logger.info("Delete address range {}".format(ar_name))
                    # Remove address range
                    payload = {"name": ar_name}
                    delete_ar_res = client.api_call("delete-address-range", payload=payload)
                    if delete_ar_res.success is False:
                        if self._logger:
                            self._logger.info("Failed to delete address range object {}, {}".format(ar_name, delete_ar_res.error_message))
                        # Since it has updated the address range, discard that change
                        client.api_call("discard")
                        return "Failed to delete address range object {}, {}".format(ar_name, delete_ar_res.error_message)

            # To this point, the configuration has been changed, need to publish and install policy to targets
            result = self._publish_and_install(client)
            if "Failed to publish configuration" in result and retries > 0:
                time.sleep(DEFAULT_RETRY_SLEEP)
                return self._unblock_ip("{}/32".format(cidr), egress, retries=retries-1)
            return result

    def _publish_and_install(self, client):
            if self._logger:
                self._logger.info("Publish configuration change")
            publish_res = client.api_call("publish")
            if publish_res.success is False:
                if self._logger:
                    self._logger.info("Failed to publish configuration: {}".format(publish_res.error_message))
                discard_res = client.api_call("discard")
                if self._logger:
                    self._logger.info("Discard result: {}".format(discard_res))
                return "Failed to publish configuration: {}".format(publish_res.error_message)

            payload = {"name": self._policy_name}
            show_policy_res = client.api_call("show-package", payload=payload)
            if show_policy_res.success is False:
                if self._logger:
                    self._logger.info("Checkpoint get policy failed. status {}".format(show_policy_res.error_message))
                return "Get policy failed. status {}".format(show_policy_res.error_message)
            targets = show_policy_res.data.get("installation-targets-revision", [])
            target_names = []
            for tgt in targets:
                target_names.append(tgt["target-name"])
            if self._logger:
                self._logger.info("Install policy {} to targets {}".format(self._policy_name, target_names))
            if len(target_names) > 0:
                payload = {"policy-package": self._policy_name, "targets": target_names}
                install_res = client.api_call("install-policy", payload=payload)
                if install_res.success is False:
                    if self._logger:
                        self._logger.info("Checkpoint install policy {} failed. status {}".format(self._policy_name, install_res.error_message))
                    return "Checkpoint install policy {} failed. status {}".format(self._policy_name, install_res.error_message)
            else:
                if self._logger:
                    self._logger.info("Empty target list, skip installation")

            if self._logger:
                self._logger.info("Publish and installation is done")
            return common.SUCCESS

    def _publish(self, client):
            if self._logger:
                self._logger.info("Publish configuration change")
            publish_res = client.api_call("publish")
            if publish_res.success is False:
                if self._logger:
                    self._logger.info("Failed to publish configuration: {}".format(publish_res.error_message))
                return "Failed to publish configuration: {}".format(publish_res.error_message)

            if self._logger:
                self._logger.info("Publish is done")
            return common.SUCCESS


    def notify_ds_to_test_connection(self, run_on):
        """
        Notify DS to perform the connection test
        :param run_on: str: the engid of sensor to run the test
        :return: str: the test results
        """
        script_path = "/opt/aelladata/connector/modules/firewall/checkpoint.py"
        password = utils.aella_encode(utils.COLLECTOR_SECRET, self._api_password)
        command = "export PYTHONPATH={}; python {} -a test -v {} -t {} -u \"{}\" -p \"{}\" -s \"{}\" -d \"{}\" -l \"{}\" -n \"{}\"".format(
                  utils.PYTHONPATH, script_path, self._device, self._port, self._api_username,
                  password, self._src_address_grp, self._dst_address_grp,
                  self._policy_name, self._domain)
        status_code, error_msg = utils.execute_action_on_ds(run_on, command, retry_count=1)
        if status_code > 0:
            return utils.error_msg_process("Checkpoint", error_msg)
        return utils.create_response("Checkpoint", 200, common.SUCCESS)

    def test_connection_on_ds(self):
        """
        This function will only be called on DS
        """
        kwargs = {}
        res = self._test_connection(**kwargs)
        if utils.test_response_success(res):
            return common.SUCCESS
        raise Exception(res)


    def _test_connection(self, **kwargs):
        run_on = kwargs.get("run_on", "dp")
        if run_on != "" and run_on != "dp":
            return self.notify_ds_to_test_connection(run_on)
        with APIClient(self._client_args) as client:
            client.debug_file = self._debug_file

            # login
            login_res = client.login(self._api_username, self._api_password, domain=self._domain)
            if login_res.success is False:
                if self._logger:
                    self._logger.info("Login failed. status {}".format(login_res.error_message))
                return utils.create_response("Checkpoint", 400, "Login failed. status {}".format(login_res.error_message))

            # Make sure the src and dst group exist
            show_grp_res = client.api_query("show-groups", "standard")
            if show_grp_res.success is False:
                if self._logger:
                    self._logger.info("Checkpoint get groups failed. status {}".format(show_grp_res.error_message))
                return utils.create_response("Checkpoint", 400, "Get group failed. status {}".format(show_grp_res.error_message))

            try:
                result = show_grp_res.data
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
                    self._logger.info("Cannot iterate through group list {}".format(e))
                return utils.create_response("Checkpoint", 400, "Cannot iterate through group list {}".format(e))

            if not src_grp_found:
                return utils.create_response("Checkpoint", 400, "Cannot find group {}".format(self._src_address_grp))
            if not dst_grp_found:
                return utils.create_response("Checkpoint", 400, "Cannot find group {}".format(self._dst_address_grp))

            # Make sure policy exists
            payload = {"name": self._policy_name}
            show_policy_res = client.api_call("show-package", payload=payload)
            if show_policy_res.success is False:
                if self._logger:
                    self._logger.info("Checkpoint get policy failed. status {}".format(show_policy_res.error_message))
                return utils.create_response("Checkpoint", 400, "Get policy failed. status {}".format(show_policy_res.error_message))

            return utils.create_response("Checkpoint", 200, common.SUCCESS)

    def _get_blocked_ip(self, egress):
        with APIClient(self._client_args) as client:
            client.debug_file = self._debug_file

            ip_list = []
            # login
            login_res = client.login(self._api_username, self._api_password)
            if login_res.success is False:
                if self._logger:
                    self._logger.info("Login failed. status {}".format(login_res.error_message))
                return ("Login failed. status {}".format(login_res.error_message), ip_list)

            if egress:
                block_ip_grp = self._dst_address_grp
            else:
                block_ip_grp = self._src_address_grp

            payload = {"name": block_ip_grp}
            get_grp_res = client.api_call("show-group", payload=payload)
            if get_grp_res.success is False:
                if self._logger:
                    self._logger.info("Checkpoint get group {} failed. status {}".format(block_ip_grp, show_grp_res.error_message))
                return ("Get group {} failed. status {}".format(block_ip_grp, show_grp_res.error_message), ip_list)

            try:
                members = get_grp_res.data.get("members", [])
                for member in members:
                    if member["type"] == "address-range":
                        mname = member["name"]
                        if mname.startswith("stellar_"):
                            ip_list.append(member["ipv4-address-first"])
            except Exception as e:
                return ("Exception: {}".format(e), ip_list)

            return (common.SUCCESS, ip_list)

    def _list_domain(self):
        with APIClient(self._client_args) as client:
            client.debug_file = self._debug_file

            # login
            login_res = client.login(self._api_username, self._api_password,  domain=self._domain)
            if login_res.success is False:
                if self._logger:
                    self._logger.info("Login failed. status {}".format(login_res.error_message))
                return "Login failed. status {}".format(login_res.error_message)

            show_domain_res = client.api_query("show-domains", "standard")
            if show_domain_res.success is False:
                if self._logger:
                    self._logger.info("Checkpoint get domains failed. status {}".format(show_domain_res.error_message))
                return "Get domains failed. status {}".format(show_domain_res.error_message)

            try:
                result = show_domain_res.data
                for item in result:
                    print item
            except Exception as e:
                if self._logger:
                    self._logger.info("Cannot iterate through domain list {}".format(e))
                return "Cannot iterate through domain list {}".format(e)

            return common.SUCCESS

    def _list_package(self):
        with APIClient(self._client_args) as client:
            client.debug_file = self._debug_file

            # login
            login_res = client.login(self._api_username, self._api_password,  domain=self._domain)
            # login_res = client.login(self._api_username, self._api_password)
            if login_res.success is False:
                if self._logger:
                    self._logger.info("Login failed. status {}".format(login_res.error_message))
                return "Login failed. status {}".format(login_res.error_message)

            show_package_res = client.api_query("show-packages", "standard")
            if show_package_res.success is False:
                if self._logger:
                    self._logger.info("Checkpoint get packages failed. status {}".format(show_package_res.error_message))
                return "Get packages failed. status {}".format(show_package_res.error_message)

            try:
                result = show_package_res.data
                for item in result:
                    print item
            except Exception as e:
                if self._logger:
                    self._logger.info("Cannot iterate through package list {}".format(e))
                return "Cannot iterate through package list {}".format(e)

            return common.SUCCESS

    def _add_grp(self, grp_name):
        with APIClient(self._client_args) as client:
            client.debug_file = self._debug_file

            # login
            login_res = client.login(self._api_username, self._api_password,  domain=self._domain)
            # login_res = client.login(self._api_username, self._api_password)
            if login_res.success is False:
                if self._logger:
                    self._logger.info("Login failed. status {}".format(login_res.error_message))
                return "Login failed. status {}".format(login_res.error_message)

            payload = {
                "name": grp_name,
            }
            add_grp_res = client.api_call("add-group", payload=payload)
            if add_grp_res.success is False:
                if self._logger:
                    self._logger.info("Failed to add group: {}".format(add_grp_res.error_message))
                return "Failed to add group: {}".format(add_ar_res.error_message)

            return self._publish(client)

    def _del_grp(self, grp_name):
        with APIClient(self._client_args) as client:
            client.debug_file = self._debug_file

            # login
            login_res = client.login(self._api_username, self._api_password,  domain=self._domain)
            # login_res = client.login(self._api_username, self._api_password)
            if login_res.success is False:
                if self._logger:
                    self._logger.info("Login failed. status {}".format(login_res.error_message))
                return "Login failed. status {}".format(login_res.error_message)

            payload = {
                "name": grp_name,
            }
            add_grp_res = client.api_call("delete-group", payload=payload)
            if add_grp_res.success is False:
                if self._logger:
                    self._logger.info("Failed to delete group: {}".format(add_grp_res.error_message))
                return "Failed to delete: {}".format(add_ar_res.error_message)

            return self._publish(client)

    def _list_group(self):
        with APIClient(self._client_args) as client:
            client.debug_file = self._debug_file

            # login
            login_res = client.login(self._api_username, self._api_password,  domain=self._domain)
            if login_res.success is False:
                if self._logger:
                    self._logger.info("Login failed. status {}".format(login_res.error_message))
                return "Login failed. status {}".format(login_res.error_message)

            show_group_res = client.api_query("show-groups", "standard")
            if show_group_res.success is False:
                if self._logger:
                    self._logger.info("Checkpoint get groups failed. status {}".format(show_group_res.error_message))
                return "Get groups failed. status {}".format(show_group_res.error_message)

            try:
                result = show_group_res.data
                for item in result:
                    print item
            except Exception as e:
                if self._logger:
                    self._logger.info("Cannot iterate through group list {}".format(e))
                return "Cannot iterate through group list {}".format(e)

            return common.SUCCESS

    def _show_group(self, grp_name):
        with APIClient(self._client_args) as client:
            client.debug_file = self._debug_file

            # login
            login_res = client.login(self._api_username, self._api_password,  domain=self._domain)
            if login_res.success is False:
                if self._logger:
                    self._logger.info("Login failed. status {}".format(login_res.error_message))
                return "Login failed. status {}".format(login_res.error_message)

            payload = {"name": grp_name}
            show_group_res = client.api_call("show-group", payload=payload)
            if show_group_res.success is False:
                if self._logger:
                    self._logger.info("Checkpoint get groups failed. status {}".format(show_group_res.error_message))
                return "Get groups failed. status {}".format(show_group_res.error_message)

            try:
                result = show_group_res.data
                for item in result:
                    print item
            except Exception as e:
                if self._logger:
                    self._logger.info("Cannot iterate through group list {}".format(e))
                return "Cannot iterate through group list {}".format(e)

            return common.SUCCESS

    def _list_address_range(self):
        with APIClient(self._client_args) as client:
            client.debug_file = self._debug_file

            # login
            login_res = client.login(self._api_username, self._api_password,  domain=self._domain)
            if login_res.success is False:
                if self._logger:
                    self._logger.info("Login failed. status {}".format(login_res.error_message))
                return "Login failed. status {}".format(login_res.error_message)

            show_address_range_res = client.api_query("show-address-ranges", "standard")
            if show_address_range_res.success is False:
                if self._logger:
                    self._logger.info("Checkpoint get address-ranges failed. status {}".format(show_address_range_res.error_message))
                return "Get address-ranges failed. status {}".format(show_address_range_res.error_message)

            try:
                result = show_address_range_res.data
                for item in result:
                    print item
            except Exception as e:
                if self._logger:
                    self._logger.info("Cannot iterate through address-range list {}".format(e))
                return "Cannot iterate through address-range list {}".format(e)

            return common.SUCCESS


if __name__ == '__main__':
    LOG_FILENAME = "/var/log/aella/firewall_action.log"
    FORMAT = "%(asctime)-15s|%(name)s|%(levelname)s|%(message)s"
    logger = logging.getLogger("checkpoint_firewall")
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
    parser.add_argument('-p', '--password', action='store', dest='password', required=True,
        help='The password to login firewall')
    parser.add_argument('-s', '--src_ip_grp_name', action='store', dest='src_ip_grp_name', required=True,
        help='The name for source IP group')
    parser.add_argument('-d', '--dst_ip_grp_name', action='store', dest='dst_ip_grp_name', required=True,
        help='The name for destination IP group')
    parser.add_argument('-l', '--policy_name', action='store', dest='policy_name', required=True,
        help='The policy name')
    parser.add_argument('-n', '--domain', action='store', dest='domain', required=False,
        help='The domain for AD')
    parser.add_argument('-c', '--cidr', action='store', dest='cidr', required=False,
        help='The CIDR as input of action')
    parser.add_argument('-e', '--egress', action='store', dest='egress', required=False,
        help='True if direction is egress')

    results = parser.parse_args()

    firewall_connector = CheckpointConnector(results.username, results.password,
                                             results.device, results.src_ip_grp_name,
                                             results.dst_ip_grp_name, results.policy_name,
                                             port=results.port,
                                             lgr=logger, domain=results.domain)

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
