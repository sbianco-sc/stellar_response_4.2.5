import argparse
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

import utils

VALID_ACTIONS = ["remediate_emails"]

class BarracudaResponder:
    TENANT_URL = "https://api.barracudanetworks.com/beta/accounts/{0}/forensics/tenants"

    action_url = {
        "remediate_emails" : "https://api.barracudanetworks.com/beta/accounts/{0}/forensics/{1}/incident"
    }

    def __init__(self, client_id, client_secret, logger=None, **kwargs):
        self.client_id = client_id
        self.client_secret = utils.aella_decode(utils.COLLECTOR_SECRET, client_secret)
        self._headers = {}
        if logger is None:
            self.logger = utils.action_agent_logger
        else:
            self.logger = logger
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    @property
    def headers(self):
        """
        Generate headers once then return from cache.
        :return: authorization headers to use in https requests
        """
        if not self._headers:
            self._headers = self.login()
        return self._headers

    def login(self):
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        auth_url = "https://login.bts.barracudanetworks.com/token"
        data = "grant_type=client_credentials&scope=forensics%3Aaccount%3Awrite%20forensics%3Aaccount%3Aread&client_id={0}&client_secret={1}".format(self.client_id, self.client_secret)
        r = requests.post(auth_url, headers=headers, data=data, verify=False)
        resp = r.json()
        if resp and "access_token" in resp:
            self._headers["Authorization"] = "Bearer " + resp["access_token"]
            if self.logger:
                self.logger.info("Barracuda login success")
        else:
            if self.logger:
                self.logger.error("Failed to login Barracuda")
            raise RuntimeError("Failed to login Barracuda")
        return self._headers

    def call_barracuda_api(self, url, method, data={}):
        if method == "get":
            status = requests.get(url, headers=self._headers, verify=False, timeout=120)
        elif method == "post":
            self._headers["Content-Type"] = "application/json"
            status = requests.post(url, headers=self._headers, verify=False, json=data, timeout=120)
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
            if self.headers:
                return utils.create_response("Barracuda", 200, "")
        except Exception as e:
            return utils.create_response("Barracuda", 400, str(e))

    def remediate_emails(self, account_id, attachment_name, email_subject, include_quarantined, include_sent, sender_display_name, email_address, time_frame, cont_rem, message_action, notify, send_summary, **kwargs):
        self.login()
        response = self.call_barracuda_api(self.TENANT_URL.format(account_id), "get")
        tenants = response.json()
        num_tenants = tenants.get("resultsCount", 0)
        if "results" in tenants and num_tenants > 0:
            tenant_id = tenants["results"][0].get("tenantId", "")
        else:
            self.logger.error("No tenants found for account_id {0}".format(account_id))
            raise Exception("Barracuda Error: No tenants found")
        data = {
            "searchCriteria": {
                "attachmentName": attachment_name, 
                "emailSubject": email_subject, 
                "includeQuarantined": int(include_quarantined), 
                "includeSent": int(include_sent), 
                "sender": {
                    "displayName": sender_display_name, 
                    "email": email_address
                },
                "timeframe": time_frame
            },
            "remediationActions": {
                "enableContinuousRemediation": int(cont_rem),
                "messageAction": message_action, 
                "notify": int(notify),
                "sendSummary": int(send_summary)
            }
        }
        reply = self.call_barracuda_action(account_id, tenant_id, data, "remediate_emails")
        if self.logger:
            self.logger.info("Barracuda create incident: {0}".format(reply))
        return reply

    def call_barracuda_action(self, account_id, tenant_id, data, action):
        url = self.action_url[action].format(account_id, tenant_id)
        reply = self.call_barracuda_api(url, "post", data)
        return self.process_reply(reply)
            
    def process_reply(self, reply):
        if 200 <= reply.status_code < 300:
            return {"result_msg": reply.text}
        else:
            if self.logger:
                self.logger.error("Barracuda mitigate action error: {}".format(reply.text))
            raise Exception(reply.text)

        
if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--clientid', action='store', dest='client_id', required=True,
        help="Client ID")    
    parser.add_argument('-s', '--clientsecret', action='store', dest='client_secret', required=True,
        help="Client Secret")
    parser.add_argument('-i', '--accountid', action='store', dest='account_id', required=True,
        help="Account ID")
    parser.add_argument('-at', '--attachment', action='store', dest='attachment_name', required=True,
        help="Attachment Name")
    parser.add_argument('-es', '--emailsubject', action='store', dest='email_subject', required=True,
        help="Email Subject")
    parser.add_argument('-q', '--includequarantined', action='store', dest='include_quarantined', required=True,
        help="Include Quarantined")
    parser.add_argument('-s', '--includesent', action='store', dest='include_sent', required=True,
        help="Include Sent")
    parser.add_argument('-dn', '--displayname', action='store', dest='sender_display_name', required=True,
        help="Sender Display Name")  
    parser.add_argument('-e', '--email', action='store', dest='email_address', required=True,
        help="Sender Email Address") 
    parser.add_argument('-t', '--timeframe', action='store', dest='time_frame', required=True,
        help="Time Frame")
    parser.add_argument('-cr', '--continuousremediation', action='store', dest='cont_rem', required=True,
        help="Enable Continuous Remediation")
    parser.add_argument('-ma', '--messageaction', action='store', dest='message_action', required=True,
        help="Message Action")  
    parser.add_argument('-n', '--notify', action='store', dest='notify', required=True,
        help="Notify")
    parser.add_argument('-ss', '--sendsummary', action='store', dest='send_summary', required=True,
        help="Send Summary")    
    parser.add_argument('-a', '--action', action='store', dest='action', required=True,
        choices=VALID_ACTIONS,
        help="The action to take: {}".format(", ".join(VALID_ACTIONS)))

    results = parser.parse_args()
    responder = BarracudaResponder(results.client_id, results.client_secret)

    if results.action == "remediate_emails":
        action_fn = responder.remediate_emails
        
    result = action_fn(results.account_id, results.attachment_name, results.email_subject, results.include_quarantined, results.include_sent, results.sender_display_name, results.email_address, results.time_frame, results.cont_rem, results.message_action, results.notify, results.send_summary)
    print(str(result))
