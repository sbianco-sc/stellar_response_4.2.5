import argparse
import requests
import utils
from requests.packages.urllib3.exceptions import InsecureRequestWarning


VALID_ACTIONS = ["contain_host", "shutdown_host"]

class CynetResponder:
    """
    Cynet Responder class
    """
    action_url = {
        "contain_host": "/api/host/remediation/disableNetwork",
        "shutdown_host": "/api/host/remediation/shutdown"
    }

    def __init__(self, host, username, password, client_id, lgr=None, **kwargs):
        self.host = host.rstrip('/')
        self.username = username
        self.password = utils.aella_decode(utils.COLLECTOR_SECRET, password)
        self.client_id = client_id
        self._headers = None
        if lgr is None:
            self.logger = utils.action_agent_logger
        else:
            self.logger = lgr
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
        headers = {
            'Content-Type': 'application/json', 
            'accept': 'application/json',
            'client_id': '{0}'.format(self.client_id)
        }
        auth_url = utils.build_url(self.host, "/api/account/token", logger=self.logger)
        json_data = {"user_name": self.username, "password": self.password}
        try:
            r = requests.post(url=auth_url, headers=headers, json=json_data, verify=False)
            response = r.json()
            if response and "access_token" in response:
                headers['access_token'] = response["access_token"]
                self._headers = headers
                if self.logger:
                    self.logger.info("Cynet login success")
            else: 
                if self.logger:
                    self.logger.error("Failed to login Cynet")
                raise RuntimeError("Failed to login Cynet")
            return headers
        except Exception as e: 
            error_msg = "Failed to log in to Cynet: {}".format(str(e))
            if self.logger:
                self.logger.error(error_msg)
            raise Exception(error_msg)


    def call_cynet_api(self, url, method, params={}):
        self._headers = self.login()
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
            if self.headers:
                return utils.create_response("Cynet", 200, "")
            else:
                return utils.create_response("Cynet", 400, "Failed to login to Cynet")
        except Exception as e:
            return utils.create_response("Cynet", 400, str(e))

    def contain_host(self, hostname, **kwargs):
        reply = self.call_cynet_action(hostname, "contain_host")
        if not self.logger is None:
            self.logger.info("Cynet responder disconnect host: {}".format(reply))        
        return reply

    def shutdown_host(self, hostname, **kwargs):
        reply = self.call_cynet_action(hostname, "shutdown_host")
        if not self.logger is None:
            self.logger.info("Cynet responder shutdown host: {}".format(reply))        
        return reply

    def call_cynet_action(self, hostname, action):
        url = utils.build_url(self.host, self.action_url[action], logger=self.logger)
        params = {"host": hostname}
        reply = self.call_cynet_api(url, "post", params)
        return self.process_reply(reply)

    def process_reply(self, reply):
        if 200 <= reply.status_code < 300:
            return {"result_msg": reply.text}
        else: 
            if self.logger: 
                self.logger.error("Cynet mitigate action error: {0}".format(reply.text))
            raise Exception(reply.text)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--host', action='store', dest='host', required=True,
        help="Host")    
    parser.add_argument('-u', '--user', action='store', dest='user', required=True,
        help="Login user")
    parser.add_argument('-p', '--password', action='store', dest='password', required=True,
        help="Login password")
    parser.add_argument('-c', '--clientid', action='store', dest='client_id', required=True,
        help="Login password")
    parser.add_argument('-a', '--action', action='store', dest='action', required=True,
        choices=VALID_ACTIONS,
        help="The action to take: {}".format(", ".join(VALID_ACTIONS)))
    parser.add_argument('-h', '--hostname', action='store', dest='hostname', required=True,
        help="The threat hostname")

    results = parser.parse_args()
    responder = CynetResponder(results.host, results.user, results.password, results.client_id)

    if results.action == "contain_host":
        action_fn = responder.contain_host
    elif results.action == "shutdown_host": 
        action_fn = responder.shutdown_host

    result = action_fn(results.hostname)
    print(str(result))
