#!/usr/bin/env python

import argparse
import logging
import logging.handlers
import sys
import requests
import json


import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import firewall.common as common
import utils


class MerakiConnector():
    def __init__(self, api_key, oragnization, network, lgr=None, **kwargs):
        self._url = "https://api.meraki.com/api/v1"
        self._api_key = utils.aella_decode(utils.COLLECTOR_SECRET, api_key)
        self._header = {"Content-Type": "application/json","Accept": "application/json","X-Cisco-Meraki-API-Key": self._api_key}
        self._dst_comment = "Stellar Cyber dst rule"
        self._src_comment = "Stellar Cyber src rule"
        self._dst_key = "destCidr"
        self._src_key = "srcCidr"
        self._dst_temp = '{"comment": "Stellar Cyber dst rule","policy": "deny","protocol": "tcp","destPort": "Any","destCidr": "","srcPort": "Any","srcCidr": "Any","syslogEnabled": false}'
        self._src_temp = '{"comment": "Stellar Cyber src rule","policy": "deny","protocol": "tcp","destPort": "Any","destCidr": "Any","srcPort": "Any","srcCidr": "","syslogEnabled": false}'
        self._logger = lgr
        self._organization_id, self._organization_err_msg = self._get_organization_id(oragnization)
        self._network_id, self._network_err_msg = self._get_network_id(self._organization_id, network)

    def prepare(self, action_name, settings, source):
        return common.prepare(action_name, settings, source)

    def _get_organization_id(self, organization):
        headers = self._header
        url =  self._url + "/organizations"
        try:
            response = requests.get(url, headers=headers, verify=False)
        except requests.RequestException as e:
            self._logger.error("Get organization failed: %s", e)
            return None, "Get organization failed: {0}".format(e)
        if response.status_code == 200:
            res = response.content
            for item in json.loads(res):
                if item["name"] == organization:
                    return item["id"], ""
            self._logger.error("Organization name doesn't exist")
            return None, "Organization name doesn't exist"
        else:
            self._logger.error("Get organization returned status %s, %s",
                response.status_code, response.content)
            return None, "Get organization returned status {0}, {1}".format(response.status_code, response.content)

    def _get_network_id(self, organization_id, network):
        headers = self._header
        url = self._url + "/organizations/{}/networks".format(organization_id)
        try:
            response = requests.get(url, headers=headers, verify=False)
        except requests.RequestException as e:
            self._logger.error("Get network failed: %s", e)
            return None, "Get network failed: {0}".format(e)
        if response.status_code == 200:
            res = response.content
            for item in json.loads(res):
                if item["name"] == network:
                    return item["id"], ""
        else:
            self._logger.error("Get network returned status %s, %s",
                response.status_code, response.content)

        # if cannot find the network, we check if the name belongs to a template
        url = self._url + "/organizations/{}/configTemplates".format(organization_id)
        try:
            response = requests.get(url, headers=headers, verify=False)
        except requests.RequestException as e:
            self._logger.error("Get network template failed: %s", e)
            return None, "Get network template failed: {0}".format(e)
        if response.status_code == 200:
            res = response.content
            for item in json.loads(res):
                if item["name"] == network:
                    return item["id"], ""
        else:
            self._logger.error("Get network template returned status %s, %s",
                response.status_code, response.content)
        self._logger.error("Network or template name doesn't exist")
        return None, "Network or template name doesn't exist"

    def _get_rules(self, network_id):
        headers = self._header
        url = self._url + "/networks/{}/appliance/firewall/l3FirewallRules".format(network_id)
        try:
            response = requests.get(url, headers=headers, verify=False)
        except requests.RequestException as e:
            self._logger.error("Get Meraki firewall rules failed: %s", e)
            return None
        if response.status_code == 200:
            res = response.content
            return json.loads(res)
        else:
            self._logger.error("Get Meraki firewall rules returned status %s, %s",
                response.status_code, response.content)
            return None

    def unblock_ip(self, cidr, direction, **kwargs):
        return common.unblock_ip_wrapper(self, cidr, direction, **kwargs)

    def _unblock_ip(self, cidr, egress):
        ip = cidr.split('/')[0] + "/" + cidr.split('/')[1]
        rules = self._get_rules(self._network_id)
        if not rules:
            self._logger.error("Fail to get Meraki firewall rules")
            return "Fail to get Meraki firewall rules"

        if egress:
            rule_comment = self._dst_comment
            rule_key = self._dst_key
        else:
            rule_key = self._src_key
            rule_comment = self._src_comment

        new_rules = []
        for item in rules["rules"]:
            if item["comment"] == rule_comment:
                ip_list = item[rule_key].split(',')
                if ip not in ip_list:
                    self._logger.error("Cidr {} not exist in Meraki firewall rules".format(ip))
                    return "Cidr {} not exist in Meraki firewall rules".format(ip)
                ip_list.remove(ip)
                if len(ip_list) > 0:
                    item[rule_key] = ",".join(ip_list)
                    new_rules.insert(0, item)
            else:
                # Avoid creating duplicated Default rule
                if item["comment"] != "Default rule":
                    new_rules.append(item)

        url = self._url +"/networks/{}/appliance/firewall/l3FirewallRules".format(self._network_id)
        s = json.dumps({"rules": new_rules})
        try:
            response = requests.put(url, headers=self._header, data = s, verify=False)
        except requests.RequestException as e:
            self._logger.error("Update Meraki firewall rules failed: %s", e)
            return e
        if response.status_code == 200:
            self._logger.info("Unblock ip {} success".format(ip))
            return common.SUCCESS
        else:
            self._logger.error("Update Meraki firewall rules returned status %s, %s",
                response.status_code, response.content)
            return response.content

    def block_ip(self, cidr, direction, **kwargs):
        return common.block_ip_wrapper(self, cidr, direction, **kwargs)

    def _block_ip(self, cidr, egress):
        ip = cidr.split('/')[0] + "/" + cidr.split('/')[1]
        rules = self._get_rules(self._network_id)
        if not rules:
            self._logger.error("Fail to get Meraki firewall rules")
            return "Fail to get Meraki firewall rules"

        if egress:
            rule_comment = self._dst_comment
            rule_key = self._dst_key
            rule_temp = self._dst_temp
        else:
            rule_key = self._src_key
            rule_comment = self._src_comment
            rule_temp = self._src_temp

        new_rules = []
        has_rule = False
        for item in rules["rules"]:
            if item["comment"] == rule_comment:
                has_rule = True
                if ip not in item[rule_key].split(','):
                    item[rule_key] = item[rule_key] + "," + ip
                new_rules.insert(0, item)
            else:
                # Avoid creating duplicated Default rule
                if item["comment"] != "Default rule":
                    new_rules.append(item)
        if has_rule == False:
            new_rule = json.loads(rule_temp)
            new_rule[rule_key] = ip
            new_rules.insert(0, new_rule)

        url = self._url +"/networks/{}/appliance/firewall/l3FirewallRules".format(self._network_id)
        s = json.dumps({"rules": new_rules})
        try:
            response = requests.put(url, headers=self._header, data = s, verify=False)
        except requests.RequestException as e:
            self._logger.error("Update Meraki firewall rules failed: %s", e)
            return e
        if response.status_code == 200:
            self._logger.info("Block ip {} success".format(ip))
            return common.SUCCESS
        else:
            self._logger.error("Update Meraki firewall rules returned status %s, %s",
                response.status_code, response.content)
            return response.content

    def _test_connection(self, **kwargs):
        headers = self._header
        url =  self._url + "/organizations"
        if not self._organization_id:
            if self._organization_err_msg:
                return utils.create_response("Meraki", 401, "Get organization failed: {0}".format(self._organization_err_msg))
            return utils.create_response("Meraki", 401, "organization name is not valid")
        if not self._network_id:
            if self._network_err_msg:
                return utils.create_response("Meraki", 401, "Get network failed: {0}".format(self._network_err_msg))
            return utils.create_response("Meraki", 401, "network name is not valid")
        try:
            response = requests.get(url, headers=headers, verify=False)
        except requests.RequestException as e:
            self._logger.error("Test connection failed: %s", e)
            return utils.create_response("Meraki", 400, e)
        if response.status_code == 200:
            return utils.create_response("Meraki", 200, "")
        else:
            return utils.create_response("Meraki", response.status_code, response.content)

if __name__ == '__main__':
    LOG_FILENAME = "/var/log/aella/firewall_action.log"
    FORMAT = "%(asctime)-15s|%(name)s|%(levelname)s|%(message)s"
    logger = logging.getLogger("meraki_firewall")
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter(FORMAT)
    handler = logging.handlers.WatchedFileHandler(LOG_FILENAME)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--action', action='store', dest='action', required=True,
        help='The action to take, can be block or unblock ip')
    parser.add_argument('-v', '--api_key', action='store', dest='api_key', required=True,
        help='The api key to login Meraki firewall')
    parser.add_argument('-t', '--organization', action='store', dest='organization', required=True,
        help='The organization name of Meraki firewall')
    parser.add_argument('-u', '--network', action='store', dest='network', required=True,
        help='The network name to login Meraki firewall')
    parser.add_argument('-c', '--cidr', action='store', dest='cidr', required=False,
        help='The CIDR as input of action')

    results = parser.parse_args()

    firewall_connector = MerakiConnector(results.api_key, results.organization,
                                         results.network,
                                         lgr=logger)

    if results.action == "block_ip":
        try:
            res = firewall_connector._block_ip(results.cidr)
        except Exception as e:
            sys.stderr.write("Failed to block ip: {} \n".format(e))
            sys.exit(1)
    elif results.action == "unblock_ip":
        try:
            res = firewall_connector._unblock_ip(results.cidr)
        except Exception as e:
            sys.stderr.write("Failed to unblock ip: {}\n".format(e))
            sys.exit(1)
    if res != "Success":
        sys.stderr.write("Failed to perform {}: {}\n".format(results.action, res))
        sys.exit(1)

