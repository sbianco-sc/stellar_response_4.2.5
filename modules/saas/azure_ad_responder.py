import argparse
import requests
#from requests.packages.urllib3.exceptions import InsecureRequestWarning
import json

'''
    2023/03/21 - adding confirm_compromise capability for risky user response - sb
    
    example from : https://learn.microsoft.com/en-us/graph/api/riskyuser-confirmcompromised?view=graph-rest-1.0&tabs=http
    
    POST https://graph.microsoft.com/v1.0/identityProtection/riskyUsers/confirmCompromised
    Content-Type: application/json
    
    {
      "userIds": [
        "29f270bb-4d23-4f68-8a57-dc73dc0d4caf",
        "20f91ec9-d140-4d90-9cd9-f618587a1471"
      ]
    }

'''


import utils

VALID_ACTIONS = ["disable_user", "enable_user", "confirm_compromise", "dismiss_risk", "list_risky_users", "list_risky_user"]

class AzureADResponder:
    
    def __init__(self, tenant_id, client_id, password, **kwargs):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.password = utils.aella_decode(utils.COLLECTOR_SECRET, password)
        self._auth_token = None
        self.scope = "https://graph.microsoft.com/.default"
        self.grant_type = "client_credentials"
        self.content_type = "application/x-www-form-urlencoded"
        self.logger = utils.action_agent_logger    	            
        #requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    @property
    def auth_token(self):
        """
        Generate auth_token
        """
        if not self._auth_token:
            self._auth_token = self.login()
        return self._auth_token

    def login(self):
        data = {
            "grant_type": self.grant_type,
            "client_id": self.client_id,
            "client_secret": self.password,
            "scope": self.scope
        }
        header = { "content-Type": self.content_type}
        auth_url = 'https://login.microsoftonline.com/'+ self.tenant_id + '/oauth2/v2.0/token'
        try:
            auth_response = requests.post(auth_url, headers=header, data=data)
            # Read token from auth response
            auth_response_json = auth_response.json()
            auth_token = auth_response_json["access_token"]
        except Exception as e:
            self.logger.error("Failed to login azure AD: {}".format(e))
            return None
        return auth_token

    def test_connection(self, **kwargs):
        try:
            if self.auth_token:
                return utils.create_response("Azure AD", 200, "")
        except Exception as e:
            return utils.create_response("Azure AD", 400, str(e))

    def confirm_compromise(self, user_principal_name, **kwargs):
        # this endpoint requires the users id
        user_id = user_principal_name
        auth_token = self.auth_token
        headers = {'Authorization': 'Bearer ' + auth_token, 'Content-Type': 'application/json'}
        user_data = {
            "userIds": [user_id]
        }
        jdata = json.dumps(user_data)
        patch_url = "https://graph.microsoft.com/v1.0//identityProtection/riskyUsers/confirmCompromised"
        self.logger.info("Azure AD responder: start risky user confirm compromise action")
        r = requests.post(patch_url, headers=headers, data=jdata)
        return self.process_reply(r)

    def dismiss_risk(self, user_principal_name, **kwargs):
        # this endpoint requires the users id
        user_id = user_principal_name
        auth_token = self.auth_token
        headers = {'Authorization': 'Bearer ' + auth_token, 'Content-Type': 'application/json'}
        user_data = {
            "userIds": [user_id]
        }
        jdata = json.dumps(user_data)
        patch_url = "https://graph.microsoft.com/v1.0//identityProtection/riskyUsers/dismiss"
        self.logger.info("Azure AD responder: start dismiss risk action")
        r = requests.post(patch_url, headers=headers, data=jdata)
        return self.process_reply(r)

    def list_risky_users(self, user_principal_name, **kwargs):
        # this endpoint requires the users id
        user_id = user_principal_name
        auth_token = self.auth_token
        headers = {'Authorization': 'Bearer ' + auth_token, 'Content-Type': 'application/json'}
        patch_url = "https://graph.microsoft.com/v1.0//identityProtection/riskyUsers"
        self.logger.info("Azure AD responder: start list risky users")
        r = requests.get(patch_url, headers=headers)
        rr = json.loads(r.text)
        if 'value' in rr:
            rus = rr['value']
            for ru in rus:
                # print(risky_user)
                outstr = "{}   {: <35}   {: <8}   {: <10}   {}".format(ru['id'], ru['userPrincipalName'], ru['riskLevel'], ru['riskState'], ru['riskDetail'])
                print(outstr)
        # rr = r.text
        # print(rr)
        return self.process_reply(r)

    def list_risky_user(self, user_principal_name, **kwargs):
        # this endpoint requires the users id
        user_id = user_principal_name
        auth_token = self.auth_token
        headers = {'Authorization': 'Bearer ' + auth_token, 'Content-Type': 'application/json'}
        patch_url = "https://graph.microsoft.com/v1.0//identityProtection/riskyUsers/{}".format(user_id)
        self.logger.info("Azure AD responder: start list risky users")
        r = requests.get(patch_url, headers=headers)
        rr = json.loads(r.text)
        str_rr = json.dumps(rr, indent=4)
        # if 'value' in rr:
        #     rus = rr['value']
        #     for ru in rus:
        #         # print(risky_user)
        #         print(ru['id'], ru['userPrincipalName'], ru['riskLevel'], ru['riskState'])
        # rr = r.text
        print(str_rr)
        return rr

    def disable_user(self, user_principal_name, **kwargs):
        auth_token = self.auth_token
        headers = {'Authorization': 'Bearer ' + auth_token, 'Content-Type': 'application/json'}
        user_data = {
            "accountEnabled": False,
            "userPrincipalName": user_principal_name,
        }
        jdata = json.dumps(user_data)
        patch_url = "https://graph.microsoft.com/v1.0/users/" + user_principal_name
        self.logger.info("Azure AD responder: start disable action")
        r = requests.patch(patch_url, headers=headers, data=jdata)      
        return self.process_reply(r)

    def enable_user(self, user_principal_name, **kwargs):
        auth_token = self.auth_token
        headers = {'Authorization': 'Bearer ' + auth_token, 'Content-Type': 'application/json'}
        user_data = {
            "accountEnabled": True,
            "userPrincipalName": user_principal_name,
        }
        jdata = json.dumps(user_data)
        patch_url = "https://graph.microsoft.com/v1.0/users/" + user_principal_name
        self.logger.info("Azure AD responder: start enable action")
        r = requests.patch(patch_url, headers=headers, data=jdata)       
        return self.process_reply(r)
    
    def process_reply(self, reply):
        if reply.status_code >= 200 and reply.status_code < 300:
            self.logger.info("Azure AD responder action success")
            return {"result_msg": "Azure AD responder action success"}
        else:
            if self.logger:
                self.logger.error("Azure AD responder action error: {}".format(reply.content))
            raise Exception(reply.content)

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--tenant_id', action='store', dest='tenant_id', required=True,
        help="Tenant ID")    
    parser.add_argument('-u', '--client_id', action='store', dest='client_id', required=True,
        help="Client ID")
    parser.add_argument('-p', '--password', action='store', dest='password', required=True,
        help="Client Secret")
    parser.add_argument('-a', '--action', action='store', dest='action', required=True,
        choices=VALID_ACTIONS,
        help="The action to take: {}".format(", ".join(VALID_ACTIONS)))
    parser.add_argument('-i', '--user_principal_name', action='store', dest='user_principal_name', required=True,
        help="The user principal name or user_id")

    results = parser.parse_args()
    responder = AzureADResponder(results.tenant_id, results.client_id, results.password)

    if results.action == "disable_user":
        action_fn = responder.disable_user
    elif results.action == "enable_user":
        action_fn = responder.enable_user
    elif results.action == "confirm_compromise":
        action_fn = responder.confirm_compromise
    elif results.action == "dismiss_risk":
        action_fn = responder.dismiss_risk
    elif results.action == "list_risky_users":
        action_fn = responder.list_risky_users
    elif results.action == "list_risky_user":
        action_fn = responder.list_risky_user

    result = action_fn(results.user_principal_name)
    print(str(result))
