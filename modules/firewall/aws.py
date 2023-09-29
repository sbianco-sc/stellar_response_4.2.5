#!/usr/bin/env python

import os
import boto3
import pdb

import firewall.common as common

import utils

# AWS max rule number is 32766, we will use rule number less than 16000
AWS_MAX_RULE_NUMBER = 16000
AWS_PROTO_ALL = "-1"

class AwsConnector():
    def __init__(self, username, password, region_name, acl_id, lgr=None, **kwargs):
        self._api_username = username
        self._api_password = utils.aella_decode(utils.COLLECTOR_SECRET, password)
        self._region_name = region_name
        self._acl_id = acl_id
        self._logger = lgr
        self._client = None

    def prepare(self, action_name, settings, source):
        return common.prepare(action_name, settings, source)

    def _test_connection(self, **kwargs):
        """
        Function used by Stellar Cyber for configuration validation
        :return: str: 'succeeded' if the connection test passes
            otherwise, a custom message to show to user
        """
        status, acl = self._find_acl()
        if status == common.SUCCESS:
            code = 200
        else:
            code = 400
        return utils.create_response("AWS", code, status)

    def _find_acl(self):
        if not self._client:
            try:
                self._client = boto3.client('ec2', aws_access_key_id=self._api_username, aws_secret_access_key=self._api_password, region_name=self._region_name, verify=False)
            except Exception as e:
                if self._logger:
                    self._logger.info("Cannot connect to aws ec2 {}".format(e))
                return ("Cannot connect to aws ec2 {}".format(e), None)
        try:
            acl = self._client.describe_network_acls()
            acl_list = acl.get("NetworkAcls", [])
            for item in acl_list:
                acl_id = item.get("NetworkAclId", "")
                if acl_id == self._acl_id:
                    return (common.SUCCESS, item)
        except Exception as e:
            self._client = None
            if self._logger:
                self._logger.info("Cannot find the acl {}".format(e))
            return ("Exception trying to find the acl {}".format(e), None)

        return ("Cannot find the acl", None)

    def block_ip(self, cidr, direction, **kwargs):
        return common.block_ip_wrapper(self, cidr, direction, **kwargs)

    def _block_ip(self, cidr, egress):
        status, acl = self._find_acl()
        if status != common.SUCCESS:
            return status

        entries = acl.get("Entries", [])
        max_rule_number = AWS_MAX_RULE_NUMBER
        for item in entries:
            rule_egress = item.get("Egress")
            if rule_egress != egress:
                continue
            rule_number = item.get("RuleNumber")
            if rule_number < max_rule_number:
                max_rule_number = rule_number
            rule_cidr = item.get("CidrBlock")
            rule_action = item.get("RuleAction")
            rule_protocol = item.get("Protocol")
            rule_port_range= item.get("PortRange", None)
            rule_icmp = item.get("IcmpTypeCode", None)

            if rule_cidr == cidr and rule_egress == egress and rule_protocol == AWS_PROTO_ALL and rule_port_range is None and rule_icmp is None:
                # Find the rule for this IP
                if rule_action == 'deny':
                    return common.SUCCESS
                else:
                    # Change the rule_action to deny
                    response = self._client.replace_network_acl_entry(
                            DryRun=False,
                            CidrBlock=cidr,
                            Egress=egress,
                            NetworkAclId=self._acl_id,
                            RuleAction='deny',
                            Protocol=AWS_PROTO_ALL,
                            RuleNumber=rule_number)
                    return common.SUCCESS

        # No entry is found, need to create one
        if max_rule_number <= 1:
            # If it cannot add the rule at the top, fail the operation
            return "Cannot insert rule before rule number 1"
        rule_number = max_rule_number - 1
        response = self._client.create_network_acl_entry(
            CidrBlock=cidr,
            DryRun=False,
            Egress=egress,
            NetworkAclId=self._acl_id,
            Protocol=AWS_PROTO_ALL,
            RuleAction='deny',
            RuleNumber=rule_number
        )
        return common.SUCCESS

    def unblock_ip(self, cidr, direction, **kwargs):
        return common.unblock_ip_wrapper(self, cidr, direction, **kwargs)

    def _unblock_ip(self, cidr, egress):
        status, acl = self._find_acl()
        if status != common.SUCCESS:
            return status

        entries = acl.get("Entries", [])
        for item in entries:
            rule_number = item.get("RuleNumber")
            rule_egress = item.get("Egress")
            rule_cidr = item.get("CidrBlock")
            rule_action = item.get("RuleAction")
            rule_protocol = item.get("Protocol")
            rule_port_range= item.get("PortRange", None)
            rule_icmp = item.get("IcmpTypeCode", None)

            if rule_cidr == cidr and rule_egress == egress and rule_protocol == AWS_PROTO_ALL and rule_port_range is None and rule_icmp is None and rule_action == "deny":
                # Found it, will delete the rule
                response = self._client.delete_network_acl_entry(
                    DryRun=False,
                    Egress=egress,
                    NetworkAclId=self._acl_id,
                    RuleNumber=rule_number
                )
                return common.SUCCESS
        # Did not find it
        return "Cannot find the the rule to remove"
