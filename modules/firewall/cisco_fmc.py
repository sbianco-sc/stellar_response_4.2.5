#!/usr/bin/env python
import argparse
from ipaddress import ip_address
import logging
import logging.handlers
import random
import sys
import os
import json
import requests
import time
from requests.auth import HTTPBasicAuth
import urllib3
import json
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import firewall.common as common

import utils

AUTH_PATH = "/api/fmc_platform/v1/auth/generatetoken"
ADDR_GRP_PATH = "/api/fmc_config/v1/domain/{domain_uuid}/object/networkgroups"
HOST_PATH = "/api/fmc_config/v1/domain/{domain_uuid}/object/hosts"

class CiscoFMCConnector():
    def __init__(self, username, password, device, src_ip_grp_name, dst_ip_grp_name, lgr=None, **kwargs):
        self._server = "https://{0}".format(device)
        self._username = username
        self._password = utils.aella_decode(utils.COLLECTOR_SECRET, password)
        self._header = {"Content-Type": "application/json","Accept": "application/json"}
        self._src_grp = src_ip_grp_name
        self._dst_grp = dst_ip_grp_name
        self._logger = lgr

    def prepare(self, action_name, settings, source):
        return common.prepare(action_name, settings, source)
    
    def _log_in(self):
        url = self._server + AUTH_PATH
        response = requests.post(url, verify=False, auth=HTTPBasicAuth(self._username, self._password))
        if "X-auth-access-token" and "DOMAIN_UUID" in response.headers:
            self._header["X-auth-access-token"] = response.headers["X-auth-access-token"]
            self._domain_uuid = response.headers["DOMAIN_UUID"]
            return common.SUCCESS
        else:
            return "Failed to get the authentication token"
    
    def block_ip(self, cidr, direction, **kwargs):
        return common.block_ip_wrapper(self, cidr, direction, block_subnet=False, **kwargs)
    
    def unblock_ip(self, cidr, direction, **kwargs):
        return common.unblock_ip_wrapper(self, cidr, direction, block_subnet=False, **kwargs)
    
    def _block_ip(self, cidr, egress):
        log_in_res = self._log_in()
        if log_in_res != common.SUCCESS:
            return log_in_res
        if egress:
            addr_grp = self._dst_grp
        else:
            addr_grp = self._src_grp
        valid_grp_res, grp_id = self._validate_grp(addr_grp)
        if valid_grp_res != common.SUCCESS:
            return valid_grp_res
        get_grp_res, grp_info = self._get_grp(grp_id)
        objects = grp_info.get("objects", [])
        if get_grp_res != common.SUCCESS:
            return get_grp_res
        ip_addr = "stellar_cyber_{0}".format(cidr)
        get_host_res, host_info = self._get_host(ip_addr)
        if get_host_res != common.SUCCESS:
            return get_host_res
        if host_info is not None:
            for object in objects:
                if object.get("id", "") == host_info.get("id", ""):
                    if self._logger:
                        self._logger.info("The ip {0} is already blocked".format(cidr))
                    return common.SUCCESS
        else:
            create_host_res, host_info = self._create_host(ip_addr, cidr)
            if create_host_res != common.SUCCESS:
                return create_host_res
        objects.append({"name": host_info.get("name"), "id": host_info.get("id"), "type": "Host"})
        url = self._server + ADDR_GRP_PATH.format(domain_uuid=self._domain_uuid) + "/" + grp_id
        grp_info["objects"] = objects
        response = requests.put(url, headers=self._header, verify=False, json=grp_info)
        if response.status_code == 200:
            return common.SUCCESS
        else:
            return "Failed to block ip {0}".format(cidr)

    def _unblock_ip(self, cidr, egress):
        log_in_res = self._log_in()
        if log_in_res != common.SUCCESS:
            return log_in_res
        if egress:
            addr_grp = self._dst_grp
        else:
            addr_grp = self._src_grp
        valid_grp_res, grp_id = self._validate_grp(addr_grp)
        if valid_grp_res != common.SUCCESS:
            return valid_grp_res
        get_grp_res, grp_info = self._get_grp(grp_id)
        objects = grp_info.get("objects", [])
        if get_grp_res != common.SUCCESS:
            return get_grp_res
        ip_addr = "stellar_cyber_{0}".format(cidr)
        get_host_res, host_info = self._get_host(ip_addr)
        if get_host_res != common.SUCCESS:
            return get_host_res
        host_found = False
        if host_info is not None:
            for object in objects:
                host_id = object.get("id", "")
                if host_id == host_info.get("id", ""):
                    host_found = True
                    objects.remove(object)
                    url = self._server + ADDR_GRP_PATH.format(domain_uuid=self._domain_uuid) + "/" + grp_id
                    grp_info["objects"] = objects
                    response = requests.put(url, headers=self._header, verify=False, json=grp_info)
                    if response.status_code == 200:
                        break
                    else:
                        return "Failed to unblock ip {0}".format(cidr)
            if not host_found:
                return "Failed to find the ip {0} in the {1}".format(cidr, addr_grp)
        else:
            return "Failed to find the host {0}".format(cidr)
        
        return self._remove_host(host_info.get("id", ""))
    
    def _remove_host(self, host_id):
        url = self._server + HOST_PATH.format(domain_uuid=self._domain_uuid)
        response = requests.get(url, headers=self._header, verify=False, params={"filter": "unusedOnly:true"})
        host_unused = False
        if response.status_code == 200:
            for item in response.json().get("items", []):
                if item.get("id", "") == host_id:
                    host_unused = True
                    break
        else:
            return "Failed to get host"
        if host_unused:
            url = self._server + HOST_PATH.format(domain_uuid=self._domain_uuid) + "/" + host_id
            response = requests.delete(url, headers=self._header, verify=False)
            if response.status_code == 200:
                return common.SUCCESS
            else:
                return "Failed to remove the host"
        return common.SUCCESS
        
    def _create_host(self, ip_addr, cidr):
        payload = {"name": ip_addr, "type": "Host", "value": cidr}
        url = self._server + HOST_PATH.format(domain_uuid=self._domain_uuid)
        r = requests.post(url, headers=self._header, verify=False, json=payload)
        if r.status_code == 201:
            return common.SUCCESS, r.json()
        return "Failed to create the host with ip {0}".format(cidr), None
        
    def _get_host(self, ip_addr):
        url = self._server + HOST_PATH.format(domain_uuid=self._domain_uuid)
        response = requests.get(url, headers=self._header, verify=False, params={"filter": "nameOrValue:{}".format(ip_addr)})
        if response.status_code == 200:
            for item in response.json().get("items", []):
                if item.get("name", "") == ip_addr:
                    return common.SUCCESS, item
            return common.SUCCESS, None
        return "Failed to get host", None
    
    def _get_grp(self, grp_id):
        url = self._server + ADDR_GRP_PATH.format(domain_uuid=self._domain_uuid) + "/" + grp_id
        response = requests.get(url, headers=self._header, verify=False)
        if response.status_code == 200:
            return common.SUCCESS, response.json()
        else:
            return "Failed to get the network group", None
    
    def _validate_grp(self, addr_grp):
        url = self._server + ADDR_GRP_PATH.format(domain_uuid=self._domain_uuid)
        response = requests.get(url, headers=self._header, verify=False, params={"filter": "nameOrValue:{}".format(addr_grp)}).json()
        for item in response.get("items", []):
            if item.get("name", "") == addr_grp:
                grp_id = item.get("id", "")
                if grp_id:
                    return common.SUCCESS, grp_id
        return "Failed to find the network group", None
    
    def _test_connection(self, **kwargs):      
        try:
            log_in_res = self._log_in()
            if log_in_res != common.SUCCESS:
                return utils.create_response("Cisco FMC", 401, log_in_res)
            url = self._server + ADDR_GRP_PATH.format(domain_uuid=self._domain_uuid)
            response = requests.get(url, headers=self._header, verify=False).json()
            dst_grp_found = False
            src_grp_found = False
            for item in response.get("items", []):
                addr_grp_name = item.get("name", "")
                if addr_grp_name == self._src_grp:
                    src_grp_found = True
                elif addr_grp_name == self._dst_grp:
                    dst_grp_found = True
            if not src_grp_found:
                return utils.create_response("Cisco FMC", 401, "The source IP group is not found")
            elif not dst_grp_found:
                return utils.create_response("Cisco FMC", 401, "The destination IP group is not found")
            else:
                return utils.create_response("Cisco FMC", 200, "")
        except Exception as e:
            self._logger.error("Test connection failed: {0}", e)
            return utils.create_response("Cisco FMC", 400, e)

if __name__ == '__main__':
    LOG_FILENAME = "/var/log/aella/firewall_action.log"
    FORMAT = "%(asctime)-15s|%(name)s|%(levelname)s|%(message)s"
    logger = logging.getLogger("cisco_fmc_firewall")
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
    parser.add_argument('-c', '--cidr', action='store', dest='cidr', required=False,
        help='The CIDR as input of action')
    parser.add_argument('-e', '--egress', action='store', dest='egress', required=False,
        help='True if direction is egress')

    results = parser.parse_args()

    firewall_connector = CiscoFMCConnector(results.username, results.password, results.device,
                                         results.src_ip_grp_name,
                                         results.dst_ip_grp_name,
                                         lgr=logger)

    if results.action == "test":
        try:
            res = firewall_connector._test_connection()
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
