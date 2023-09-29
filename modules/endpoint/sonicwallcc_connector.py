import argparse
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

import utils

HOST = "https://captureclient.sonicwall.com"
EMAIL = "sonicwall@stellarcyber.ai"
PASSWORD = "****"
VALID_ACTIONS = ["connect", "disconnect", "restart", "scan", "shutdown"]

class SonicwallccConnector:

    def __init__(self, host, email, password, lgr=None, **kwargs):
        self.host = host.rstrip('/')
        self.email = email
        self.password = utils.aella_decode(utils.COLLECTOR_SECRET, password)
        self.logger = lgr
        self._headers = None

    @property
    def headers(self):
        """
        Generate headers once then return from cache.
        :return: authorization headers to use in https requests
        """
        if not self._headers:
            self._headers = self.get_headers()
        return self._headers

    def get_headers(self):
        headers = {"Content-Type": "application/json"}
        auth_url = utils.build_url(self.host, "/api/login", logger=self.logger)
        body = {"email": self.email, "password": self.password}
        r = requests.post(auth_url, headers=headers, json=body)
        try:
            resp = r.json()
            if "token" in resp:
                headers["Authorization"] = resp["token"]
            return headers
        except Exception as e:
            error_msg = "Failed to log in to Sonicwall management console: {}".format(str(e))
            if self.logger:
                self.logger.error(error_msg)
            raise Exception(error_msg)

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
        if action_name in VALID_ACTIONS:
            for hit in source["ctx"]["payload"]["filtered"]:
                hit_src = hit["_source"]
                if "device" not in hit_src:
                    continue
                device_info = hit_src["device"]
                if "deviceId" not in device_info or "installToken" not in device_info:
                    continue
                params.append({
                    "device_id": device_info["deviceId"],
                    "install_token": device_info["installToken"]
                })
        return params

    def test_connection(self, **kwargs):
        try:
            if self.headers:
                return utils.create_response("Sonicwall Capture Client", 200, "")
        except Exception as e:
            return utils.create_response("Sonicwall Capture Client", 400, str(e))

    def call_sonicwallcc_api(self, url, method, params={}):
        """
        Make an API request
        :param url: string (e.g. api/s1/agents/initiate-scan)
        :param method: post, get
        :return: python-requests response object
        """
        url = utils.build_url(self.host, url, logger=self.logger)
        if method == "get":
            status = requests.get(url, headers=self.headers, params=params, timeout=120)
        else:
            status = requests.post(url, headers=self.headers, json=params, timeout=120)
        return status

    def scan(self, device_id, install_token, **kwargs):
        assert self.is_device_online(device_id, install_token), \
                "Device {} is offline".format(device_id)
        url = "api/s1/agents/initiate-scan"
        uuid = self.get_uuid(device_id, install_token)
        params = {"uuid": uuid}
        reply = self.call_sonicwallcc_api(url, "post", params)
        return self.process_reply(reply)

    def disconnect(self, device_id, install_token, **kwargs):
        assert self.is_device_online(device_id, install_token), \
                "Device {} is offline".format(device_id)
        url = "api/s1/agents/disconnectFromNetwork"
        params = {"deviceId": device_id, "installToken": install_token}
        reply = self.call_sonicwallcc_api(url, "post", params)
        return self.process_reply(reply)

    def connect(self, device_id, install_token, **kwargs):
        url = "api/s1/agents/connectToNetwork"
        uuid = self.get_uuid(device_id, install_token)
        params = {"uuid": uuid}
        reply = self.call_sonicwallcc_api(url, "post", params)
        return self.process_reply(reply)

    def restart(self, device_id, install_token, **kwargs):
        assert self.is_device_online(device_id, install_token), \
                "Device {} is offline".format(device_id)
        url = "api/s1/agents/restart-machine"
        uuid = self.get_uuid(device_id, install_token)
        params = {"uuid": uuid}
        reply = self.call_sonicwallcc_api(url, "post", params)
        return self.process_reply(reply)

    def shutdown(self, device_id, install_token, **kwargs):
        assert self.is_device_online(device_id, install_token), \
                "Device {} is offline".format(device_id)
        url = "api/s1/agents/shutdown"
        uuid = self.get_uuid(device_id, install_token)
        params = {"uuid": uuid}
        reply = self.call_sonicwallcc_api(url, "post", params)
        return self.process_reply(reply)

    def get_uuid(self, device_id, install_token):
        url = "api/endpoints/{}/{}".format(device_id, install_token)
        reply = self.call_sonicwallcc_api(url, "get")
        try:
            uuid = reply.json().get("s1AgentId")
            assert uuid, "No s1AgentId value found"
            return uuid
        except Exception as e:
            raise Exception("Failed to retrieve uuid: {}".format(str(e)))

    def is_device_online(self, device_id, install_token):
        url = "api/endpoints/{}/{}".format(device_id, install_token)
        reply = self.call_sonicwallcc_api(url, "get")
        try:
            online_status = reply.json().get("onlineStatus")
            assert online_status is not None, "Could not retrieve device's online status"
            return online_status
        except Exception as e:
            raise Exception("Failed to retrieve device's online status: {}".format(str(e)))

    def process_reply(self, reply):
        if reply.status_code >= 200 and reply.status_code < 300:
            try:
                result = reply.json()
            except:
                result = {}
            if result.get("data", {}).get("affected") == 0:
                raise Exception("No devices were affected")
            return {"result_msg": reply.text}
        else:
            raise Exception(reply.text)

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('-h', '--host', action='store', dest='host', required=False,
        help="Sonicwall Capture Client host url")
    parser.add_argument('-e', '--email', action='store', dest='email', required=False,
        help="Login email")
    parser.add_argument('-p', '--password', action='store', dest='password', required=False,
        help="Login password")
    parser.add_argument('-a', '--action', action='store', dest='action', required=True,
        choices=VALID_ACTIONS,
        help="The action to take: {}".format(", ".join(VALID_ACTIONS)))
    parser.add_argument('-d', '--deviceId', action='store', dest='deviceId', required=True,
        help="The target machine's device id")
    parser.add_argument('-i', '--installToken', action='store', dest='installToken', required=True,
        help="The taget machine's install token")

    results = parser.parse_args()
    host = results.host if results.host else HOST
    email = results.email if results.email else EMAIL
    password = results.password if results.password else PASSWORD
    connector = SonicwallccConnector(host, email, password)

    if results.action == "scan":
        action_fn = connector.scan
    elif results.action == "disconnect":
        action_fn = connector.disconnect
    elif results.action == "connect":
        action_fn = connector.connect 
    elif results.action == "restart":
        action_fn = connector.restart
    elif results.action == "shutdown":
        action_fn = connector.shutdown
    result = action_fn(results.deviceId, results.installToken)
    print result
