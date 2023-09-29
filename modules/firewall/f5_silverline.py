#!/usr/bin/env python

import argparse
import copy
import logging
import logging.handlers
import random
import sys
import os
import requests
import re
import time
import json

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import firewall.common as common

import utils


class F5SilverlineConnector():
    def __init__(self, api_token, lgr=None, **kwargs):
        self._api_token = utils.aella_decode(utils.COLLECTOR_SECRET, api_token)
        self._logger = lgr
        self._base_url = "https://portal.f5silverline.com/api/v1/ip_lists/denylist/ip_objects"
        self._headers = {"Content-Type": "application/json",
                         "X-Authorization-Token": self._api_token}


    def prepare(self, action_name, settings, source):
        return common.prepare(action_name, settings, source)


    def _parse_response(self, response):
        try:
            if response.status_code > 299:
                if response.content:
                    try:
                        res = json.loads(response.content)
                        if "errors" in res:
                            errors = res.get("errors", [])
                            for error in errors:
                                error.pop("id", None)
                                error.pop("href", None)
                                error.pop("links", None)
                        return None, "Silverline API error: {}".format(json.dumps(errors))
                    except Exception as e:
                        self._logger.error("Silverlie API response error: %s", e)
                        return None, "Silverline API call returns {}".format(response.status_code)
                else:
                    return None, "Silverline API call returns {}".format(response.status_code)
            else:
                res = response.content
                if not res:
                    return {}, common.SUCCESS
                try:
                    ret = json.loads(res)
                    if "errors" in ret:
                        return None, res
                    return json.loads(res), common.SUCCESS
                except Exception as e:
                    self._logger.error("Failed to parse response with code 200 %s: %s", res, e)
                    return None, "Response parsing failure: {}".format(e)
        except Exception as e:
            self._logger.error("Failed to parse response %s: %s", res, e)
            return None, "Failed to parse response: {}".format(e)

    def _get_request(self, url, params=None):
        try:
            response = requests.get(
                url, headers=self._headers,
                params=params, verify=False)
        except requests.RequestException as e:
            self._logger.error("Get request failed %s: %s", url, e)
            return None, str(e)
        return self._parse_response(response)

    def _post_request(self, url, payload):
        try:
            response = requests.post(
                url,
                data=json.dumps(payload),
                headers=self._headers,
                params=None, timeout=120,
                verify=False)
            return self._parse_response(response)
        except Exception as e:
            return None, "Failed to post silverline API: {}".format(e)

    def _delete_request(self, url):
        try:
            response = requests.delete(
                url,
                headers=self._headers,
                timeout=120,
                verify=False)
            return self._parse_response(response)
        except Exception as e:
            return None, str(e)

    def _get_object_id(self, cidr):
        return cidr.replace('.', '-').replace('/', '_')

    def unblock_ip(self, cidr, direction, **kwargs):
        return common.unblock_ip_wrapper(self, cidr, direction, **kwargs)

    def _unblock_ip(self, cidr, egress):
        object_id = self._get_object_id(cidr)
        url = "{}/{}".format(self._base_url, object_id)
        res, msg = self._delete_request(url)
        return msg

    def block_ip(self, cidr, direction, **kwargs):
        return common.block_ip_wrapper(self, cidr, direction, **kwargs)

    def _block_ip(self, cidr, egress):
        object_id = self._get_object_id(cidr)
        tokens = cidr.split('/')
        address = tokens[0]
        mask = tokens[1]
        payload = {
                    "data": {
                      "id": object_id,
                      "type": "ip_objects",
                      "attributes": {
                          "mask": mask,
                          "ip": address,
                         "duration": 0
                      }
                    }
                  }
        res, msg = self._post_request(self._base_url, payload)
        return msg

    def _test_connection(self, **kwargs):
        res, msg = self._get_request(self._base_url)
        if res is None:
            return utils.create_response("F5 Silverline", 400, msg)

        return utils.create_response("F5 Silverline", 200, common.SUCCESS)

if __name__ == '__main__':
    LOG_FILENAME = "/var/log/aella/firewall_action.log"
    FORMAT = "%(asctime)-15s|%(name)s|%(levelname)s|%(message)s"
    logger = logging.getLogger("f5_silverline_firewall")
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter(FORMAT)
    handler = logging.handlers.WatchedFileHandler(LOG_FILENAME)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--action', action='store', dest='action', required=True,
        help='The action to take, can be block or unblock ip')
    parser.add_argument('-p', '--api_token', action='store', dest='api_token', required=True,
        help='The API token login firewall')
    parser.add_argument('-c', '--cidr', action='store', dest='cidr', required=False,
        help='The CIDR as input of action')
    parser.add_argument('-e', '--egress', action='store', dest='egress', required=False,
        help='True if direction is egress')

    results = parser.parse_args()

    firewall_connector = F5SilverlineConnector(results.api_token,
                                     lgr=logger)

    if results.action == "test":
        try:
            res = firewall_connector.test_connection_on_ds()
        except Exception as e:
            sys.stderr.write("Connection test failed: {}\n".format(e))
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
