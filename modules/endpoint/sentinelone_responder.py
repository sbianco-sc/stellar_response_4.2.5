import argparse
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

import utils

VALID_ACTIONS = ["scan", "kill", "quarantine", "un_quarantine", "remediate", "rollback_remediation", "contain_host", "contain_host_revert"]

class SentineloneResponder:
    action_url = {
                    "scan" : "/web/api/v2.1/agents/actions/initiate-scan",
                    "kill" : "/web/api/v2.1/threats/mitigate/kill",
                    "quarantine": "/web/api/v2.1/threats/mitigate/quarantine",
                    "un_quarantine" : "/web/api/v2.1/threats/mitigate/un-quarantine",
                    "remediate" : "/web/api/v2.1/threats/mitigate/remediate",
                    "rollback_remediation" : "/web/api/v2.1/threats/mitigate/rollback-remediation",
                    "contain_host" : "/web/api/v2.1/agents/actions/disconnect",
                    "contain_host_revert" : "/web/api/v2.1/agents/actions/connect"
                    }
    
    
    def __init__(self, host, api_key, lgr=None, **kwargs):
        self.host = host.rstrip('/')
        self.api_key = utils.aella_decode(utils.COLLECTOR_SECRET, api_key)
        self._headers = {'Content-Type': 'application/json', 'accept': 'application/json', 'Authorization': 'APIToken {0}'.format(self.api_key)}
        if lgr is None:
            self.logger = utils.action_agent_logger
        else:
            self.logger = lgr
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    def test(self):
        test_endpoints = ['/threats?limit=1', '/agents?limit=1']
        base_url = '/web/api/v2.1'
        for endpoint in test_endpoints:
            auth_url = utils.build_url(self.host, base_url + endpoint, logger=self.logger)
            r = requests.get(auth_url, headers=self._headers, verify=False)
            resp = r.json()
            if resp and 'data' in resp:
                if not self.logger is None:
                    self.logger.info("SentinelOne management authentication success")
            else:
                if not self.logger is None:
                    self.logger.error("Failed to authenticate SentinelOne management: authorization failed")
                raise RuntimeError("Failed to authenticate SentinelOne management")

    def call_sentinelone_api(self, url, method, params={}):
        if method == "get":
            status = requests.get(url, headers=self._headers, verify=False, params=params, timeout=120)
        elif method == "post":
            status = requests.post(url, headers=self._headers, verify=False, json=params, timeout=120)
        else:
            status = None
        return status

    def prepare(self, action_name, settings, source):
        """
        Function used by Stellar Cyber for threat hunting integration
        :param action_name: str: function to call
        :param settings: obj: additional info that may be needed
        :param source: obj: threat hunting results
        :return: list of obj: list of parameters to call <action_name> with.
            Each object in the list represents one function call, so a list
            of length n will result in n separate calls
        """
        params = []
        return params

    def test_connection(self, **kwargs):
        try:
            self.test()
            return utils.create_response("Sentinel One", 200, "")
        except Exception as e:
            return utils.create_response("Sentinel One", 400, str(e))

    def scan(self, ids, **kwargs):
        reply = self.call_sentinelone_action(ids, "scan")
        if not self.logger is None:
            self.logger.info("Sentinelone responder scan: {}".format(reply))        
        return reply

    def kill(self, ids, **kwargs):
        reply = self.call_sentinelone_action(ids, "kill")
        if not self.logger is None:
            self.logger.info("Sentinelone responder kill: {}".format(reply))        
        return reply

    def quarantine(self, ids, **kwargs):
        reply = self.call_sentinelone_action(ids, "quarantine")
        if not self.logger is None:
            self.logger.info("Sentinelone responder quarantine: {}".format(reply))        
        return reply

    def un_quarantine(self, ids, **kwargs):
        reply = self.call_sentinelone_action(ids, "un_quarantine")
        if not self.logger is None:
            self.logger.info("Sentinelone responder un_quarantine: {}".format(reply))        
        return reply

    def remediate(self, ids, **kwargs):
        reply = self.call_sentinelone_action(ids, "remediate")
        if not self.logger is None:
            self.logger.info("Sentinelone responder remediate: {}".format(reply))        
        return reply
    
    def rollback_remediation(self, ids, **kwargs):
        reply = self.call_sentinelone_action(ids, "rollback_remediation")
        if not self.logger is None:
            self.logger.info("Sentinelone responder rollback_remediation: {}".format(reply))        
        return reply
    
    def contain_host(self, ids, **kwargs):
        reply = self.call_sentinelone_action(ids, "contain_host")
        if not self.logger is None:
            self.logger.info("Sentinelone responder disconnect agent: {}".format(reply))        
        return reply    

    def contain_host_revert(self, ids, **kwargs):
        reply = self.call_sentinelone_action(ids, "contain_host_revert")
        if not self.logger is None:
            self.logger.info("Sentinelone responder connect agent: {}".format(reply))        
        return reply   

    def call_sentinelone_action(self, ids, action):
        url = utils.build_url(self.host, self.action_url[action], logger=self.logger)
        params = {"data" : {},
                  "filter": {"ids" : ids}
                  }
        reply = self.call_sentinelone_api(url, "post", params)
        return self.process_reply(reply)
    
    def process_reply(self, reply):
        if reply.status_code >= 200 and reply.status_code < 300:
            return {"result_msg": reply.text}
        else:
            if self.logger:
                self.logger.error("Sentinelone mitigate action error: {}".format(reply.text))
            raise Exception(reply.text)

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--host', action='store', dest='host', required=True,
        help="Host")    
    parser.add_argument('-k', '--apikey', action='store', dest='api_key', required=True,
        help="Login API key")
    parser.add_argument('-a', '--action', action='store', dest='action', required=True,
        choices=VALID_ACTIONS,
        help="The action to take: {}".format(", ".join(VALID_ACTIONS)))
    parser.add_argument('-i', '--ids', action='store', dest='ids', required=True,
        help="The threat/agent ids")

    results = parser.parse_args()
    responder = SentineloneResponder(results.host, results.user, results.password, results.api_key)

    if results.action == "scan":
        action_fn = responder.scan
    elif results.action == "kill":
        action_fn = responder.kill
    elif results.action == "quarantine":
        action_fn = responder.quarantine
    elif results.action == "un_quarantine":
        action_fn = responder.un_quarantine
    elif results.action == "contain_host":
        action_fn = responder.contain_host
    elif results.action == "contain_host_revert":
        action_fn = responder.contain_host_revert
    elif results.action == "remediate":
        action_fn = responder.remediate
    elif results.action == "rollback_remediation":
        action_fn = responder.rollback_remediation    
        
    result = action_fn(results.ids)
    print(str(result))
