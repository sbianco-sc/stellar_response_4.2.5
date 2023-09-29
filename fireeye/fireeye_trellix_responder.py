import argparse
import requests
import json
from requests.auth import HTTPBasicAuth
import logging.handlers
import sys
# import utils

'''
    2023/03/30      - building containment and undo-containment for trellix
                      https://fireeye.dev/apis/lighthouse/

'''

VALID_ACTIONS = ["contain_asset", "reverse_containment", "list_containments", "list_containment", "get_alerts"]


class HellixResponder:

    AUTH_PATH = "/token"

    def __init__(self, host_name, user_id, user_password, logger):
        self._base_url = "https://" + host_name + "/hx/api/v3"
        self._user_id = user_id
        self._user_password = user_password
        self.logger = logger
        r = self.test_connection()

    @property
    def login(self):
        url = self._base_url + self.AUTH_PATH
        response = requests.get(url=url, auth=HTTPBasicAuth(self._user_id, self._user_password))
        if response.status_code == 204 and "X-FeApi-Token" in response.headers:
            self._headers = {"X-FeApi-Token": response.headers['X-FeApi-Token']}
            self.logger.info("FireEye HX login success")
        else:
            self.logger.error("Failed to login FireEye HX: authorization failed")
            raise Exception("Failed to login FireEye HX: authorization failed")

    def test_connection(self, **kwargs):
        try:
            if self.login:
                return utils.create_response("Fireeye Hellix", 200, "")
        except Exception as e:
            return utils.create_response("Fireeye Hellix", 400, str(e))

    def list_containments(self, garbage=None):
        self.logger.info("FireEye HX: listing containments")
        url = self._base_url + "/containment_states"
        r = requests.get(url=url, headers=self._headers)
        rr = json.loads(r.text)
        rr = rr.get('data', None)
        if 'entries' in rr:
            containments = rr['entries']
            for c in containments:
                cc = json.dumps(c, indent=4)
                print(cc)
        return self.process_reply(r)

    def list_containment(self, fe_agent_id):
        self.logger.info("FireEye HX: listing containment for agent id: [{}]".format(fe_agent_id))
        url = self._base_url + "/hosts/{}/containment".format(fe_agent_id)
        r = requests.get(url=url, headers=self._headers)
        rr = json.loads(r.text)
        c = rr.get('data', None)
        if c:
            cc = json.dumps(c, indent=4)
            print(cc)
        return self.process_reply(r)

    def contain_asset(self, fe_agent_id):
        self.logger.info("FireEye HX: requesting containment for agent id: [{}]".format(fe_agent_id))
        url = self._base_url + "/hosts/{}/containment".format(fe_agent_id)
        data = {"state": "contain"}
        r = requests.post(url=url, headers=self._headers, json=data)
        print(r.text)
        self.list_containment(fe_agent_id)
        return self.process_reply(r)

    def reverse_containment(self, fe_agent_id):
        self.logger.info("FireEye HX: requesting containment for agent id: [{}]".format(fe_agent_id))
        url = self._base_url + "/hosts/{}/containment".format(fe_agent_id)
        # data = {"state": "contain"}
        r = requests.delete(url=url, headers=self._headers)
        print(r.text)
        self.list_containment(fe_agent_id)
        return self.process_reply(r)

    def process_reply(self, reply):
        if reply.status_code >= 200 and reply.status_code < 300:
            self.logger.info("FireEye HX: responder action success")
            return {"result_msg": "FireEye HX: responder action success"}
        else:
            if self.logger:
                self.logger.error("FireEye HX: responder action error: {}".format(reply.content))
            raise Exception(reply.content)

    def get_alerts(self, garbage=None):
        r = self._query()
        return r
        # self.logger.info("Getting alerts")
        # url = self._base_url + "/alerts"
        # # data = {"state": "contain"}
        # r = requests.get(url=url, headers=self._headers)
        # rr = json.loads(r.text)
        # print(r.text)

   # Private method start
    def _query(self):
        start_date = "2023-04-04T14:11:05Z"
        end_date = "2023-04-04T14:21:05Z"
        in_statistic = None
        params = {"limit": "200"}
        query = json.dumps({"operator": "between", "arg": [start_date, end_date], "field" :"reported_at"})
        params.update({"filterQuery": query})
        url = self._base_url + "/alerts"
        response = requests.get(url=url, headers=self._headers, params=params)
        response = response.json()
        if self._http_success(response):
            result = self._pagination(response, url, params)
            # CollectorStatistic.try_set_statistic_value(in_statistic, False, CollectorStatistic.KEY_IN_RECORDS_DELTA, len(result))
            return result
        return None

    def _pagination(self, response, url, params, statistic_session=None):
        result = []
        result.extend(response.get("data", {}).get("entries"))
        while response.get("data", {}).get("entries"):
            in_statistic = None
            # if statistic_session is not None:
            #     in_statistic = CollectorStatistic.create_statistic_event()
            #     CollectorStatistic.add_statistic_event(statistic_session, in_statistic)
            offset = response.get("data", {}).get("offset") + 200
            params.update({"offset": offset})
            new_response = requests.get(url=url, headers=self._headers, params=params)
            new_response = new_response.json()
            if self._http_success(new_response):
                response = new_response
                result.extend(response.get("data", {}).get("entries"))
        return result

    def _http_success(self, response):
        return (not response is None) and ('entries' in response.get("data", {})) and ('offset' in response.get("data", {}))


if __name__ == "__main__":

    l = logging.getLogger(__name__)
    l_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    l_handler = logging.StreamHandler(sys.stdout)
    l_handler.setFormatter(l_format)
    l.addHandler(l_handler)
    l.setLevel(logging.INFO)

    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--server', action='store', dest='server', required=True,
        help="Tenant ID")    
    parser.add_argument('-u', '--user_name', action='store', dest='user_name', required=True,
        help="Client ID")
    parser.add_argument('-p', '--password', action='store', dest='password', required=True,
        help="Client Secret")
    parser.add_argument('-a', '--action', action='store', dest='action', required=True,
        choices=VALID_ACTIONS,
        help="The action to take: {}".format(", ".join(VALID_ACTIONS)))
    parser.add_argument('-i', '--hellix_guid', action='store', dest='hellix_guid', required=True,
        help="The user principal name or user_id")

    results = parser.parse_args()
    responder = HellixResponder(results.server, results.user_name, results.password, l)

    # VALID_ACTIONS = ["contain_asset", "reverse_containment", "list_containments", "list_containment"]
    if results.action == "contain_asset":
        action_fn = responder.contain_asset
    elif results.action == "reverse_containment":
        action_fn = responder.reverse_containment
    elif results.action == "list_containments":
        action_fn = responder.list_containments
    elif results.action == "list_containment":
        action_fn = responder.list_containment
    elif results.action == "get_alerts":
        action_fn = responder.get_alerts

    result = action_fn(results.hellix_guid)
    for e in result:
        e_test = e.get('event_values', None)
        if isinstance(e_test, dict):
            print("dict")
        elif isinstance(e_test, list):
            print('list')

    # print(str(result))
