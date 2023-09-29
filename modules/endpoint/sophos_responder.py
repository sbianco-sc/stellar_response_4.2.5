import argparse
import logging
import logging.handlers
import json
import requests

from requests.packages.urllib3.exceptions import InsecureRequestWarning
import utils

VALID_ACTIONS = ["isolate_machine", "unisolate_machine"]

class SophosResponder():


    TOKEN_URL = "https://id.sophos.com/api/v2/oauth2/token"
    TENANT_URL = "https://api.central.sophos.com/whoami/v1"
    ISOLATION_API = "/endpoint/v1/endpoints/isolation"

    def __init__(self, client_id, client_secret, lgr=None, **kwargs):
        self._base_url = ""
        self._tenant_id = ""
        self._client_id = client_id
        self._client_secret = utils.aella_decode(utils.COLLECTOR_SECRET, client_secret)
        if lgr is None:
            self._logger = utils.action_agent_logger
        else:
            self._logger = lgr

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

    def get_tenant_id(self, **kwargs):
        r = None
        try:
            data = {"grant_type": "client_credentials", "client_id": self._client_id,
             "client_secret": self._client_secret,"scope": "token"}
            header = {"Content-Type":"application/x-www-form-urlencoded"}
            r = requests.request(method="POST", url=self.TOKEN_URL, headers=header, data=data, verify=False)
            self._token = r.json().get('access_token',"")
            self._logger.info("Access Token response: {0}".format(r.json()))
        except Exception as e:
            self._logger.error("Failed to get access token: {0}".format(str(e)))
            return r

        try:
            header = {"Authorization": "Bearer {0}".format(self._token)}
            r = requests.request(method="GET", url=self.TENANT_URL, headers=header, data=None, verify=False)
            self._base_url = r.json().get('apiHosts', {}).get('dataRegion','')
            self._tenant_id = r.json().get('id','')
            self._logger.info("Tenant ID response: {0}".format(r.json()))
        except Exception as e:
            self._logger.error("Failed to get tenant ID: {0}".format(str(e)))
            return r

        return r


    def endpoint_action(self, endpoint_id, isolate, **kwargs):
        try:
            if isolate:
                enabled = True
                action_name = "isolate"
            else:
                enabled = False
                action_name = "unisolate"

            autho_res = self.get_tenant_id()
            if autho_res.status_code != 200:
                raise Exception("Failed to {0}_machine: {1} {2}".format(action_name, endpoint_id, "Authentication Failure"))

            payload = json.dumps({
                "enabled": enabled,
                "comment": "{0} endpoints with suspicious health".format(action_name),
                "ids": [str(endpoint_id)]
                })
            headers = {'X-Tenant-ID': self._tenant_id, 'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(self._token)}
            url = self._base_url + self.ISOLATION_API
            response = requests.request("POST", url, headers=headers, data=payload)
            if response.status_code == 202:
                if not self._logger is None:
                    self._logger.info("{0}_machine: {1}".format(action_name,str(endpoint_id)))
                if response.json().get("result", ""):
                    """
                    successful response example with 202 status code
                    {"items":[{"id":"c132e142-bc6e-4549-8dc4-67322f57262b","isolation":{"enabled":true,"lastEnabledBy":{"id":"81d43c06-5b26-4d3a-8190-7c08b451d55b"},"comment":"Isolating endpoints with suspicious health"}}]}
                    """
                    if self._logger:
                        self._logger.info("{0}_machine: {1} {2}".format(action_name, endpoint_id, response.json()["items"]))
                    return {"result_msg": "{0}_machine: {1} successfully".format(action_name, str(endpoint_id))}
                elif not response.json().get("error") is None:
                    """
                    failed response example with 400 status code
                    { "error": "badRequest", "correlationId": "408a245d-9120-4f00-8639-b9a97701d6b3", "requestId": "a622fbf6-103d-4fab-a1d0-c90ae7ff8f3c", "createdAt": "2022-12-14T16:47:21.94Z", "message": "Invalid request" }
                    """
                    if self._logger:
                        self._logger.info("{0}_machine: {1} {2}: {3}".format(action_name, endpoint_id, response.json().get("error",""), response.json().get("message","")))
                    try:
                        raise Exception("Failed to {0}_machine: {1} {2}: {3}".format(action_name, endpoint_id, response.json().get("error",""), response.json().get("message","")))
                    except KeyError:
                        self._logger.error("{0}_machine has unsupported json data".format(self.action_name))
            else:
                if self._logger:
                    self._logger.error("Failed to {0}_machine: {1} {2}".format(action_name, endpoint_id, response.json()))
                raise Exception("Fail to {0}_machine: {1}, status code {2}".format(action_name, str(endpoint_id), response.status_code))
        except Exception as e:
            self._logger.error("Exception in {0}_machine: {1}".format(action_name, str(e)))
            raise Exception("Exception in {0}_machine: {1}".format(action_name, str(e)))
        return  {"result_msg": "Success"}

    def isolate_machine(self, endpoint_id, **kwargs):
        return self.endpoint_action(endpoint_id, True)

    def unisolate_machine(self, endpoint_id, **kwargs):
        return self.endpoint_action(endpoint_id, False)

    def test_connection(self, **kwargs):
        try:
            resp = self.get_tenant_id()
            if self._logger:
                self._logger.info("resp {0}".format(resp.content))
            if resp.status_code == 200:
                return utils.create_response("Sophos", 200, "")
            else:
                return utils.create_response("Sophos", resp.status_code, "Fail to authenticate Sophos: {0}".format(resp.json().get("errorCode", "")))
        except Exception as e:
            return utils.create_response("Sophos", 400, str(e))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--client_id', action='store', dest='client_id', required=True,
        help="Client ID")
    parser.add_argument('-s', '--client_secret', action='store', dest='client_secret', required=True,
        help="Client Secret")
    parser.add_argument('-a', '--action', action='store', dest='action', required=True,
        choices=VALID_ACTIONS,
        help="The action to take: {}".format(", ".join(VALID_ACTIONS)))
    parser.add_argument('-d', '--endpoint_id', action='store', dest='endpoint_id', required=True,
        help="Endpoint ID")

    results = parser.parse_args()
    responder = SophosResponder(results.client_id, results.client_secret)

    if results.action == "isolate_machine":
        action_fn = responder.isolate_machine
    elif results.action == "unisolate_machine":
        action_fn = responder.unisolate_machine

    action_fn(results.endpoint_id)