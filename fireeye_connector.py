"""
FireEye HX Connector class to access data via API
"""
from aella_rest_client import AellaRestClient
from collector_statistic import CollectorStatistic
from collections import OrderedDict
import requests
import os
import json
import re
from requests.auth import HTTPBasicAuth
from collections import OrderedDict

class FireEyeHXConnector:
    """FireEye HX Connector class"""
    CONTENT_TYPE_HOST = "hosts"
    CONTENT_TYPE_HOST_SET = "host_sets"
    CONTENT_TYPE_ALERT = "alerts"

    AUTH_PATH = "/token"
    HOST_PATH = "/hosts"
    HOST_SET_PATH = "/host_sets"
    ALERT_PATH = "/alerts"
    HOST_ID_PATH = "/hosts/{0}"

    LIMIT = 200

    def __init__(self, host_name, user_id, user_password, cache_size=0, logger=None):
        self._logger = logger
        self._base_url = "https://" + host_name + "/hx/api/v3"
        self._user_id = user_id
        self._user_password = user_password
        self._host_cache = OrderedDict()
        self._host_cache_updated = False
        self._cache_size = cache_size
        if self._logger:
            self._rest_client = AellaRestClient(self._logger)
            self._logger.info("Cache size is {0}".format(self._cache_size))

    def login(self):
        url = self._base_url + self.AUTH_PATH
        response = requests.get(url=url, auth=HTTPBasicAuth(self._user_id, self._user_password))
        if response.status_code == 204 and "X-FeApi-Token" in response.headers:
            self._headers = {"X-FeApi-Token": response.headers['X-FeApi-Token']}
            self._logger.info("FireEye HX login success")
        else:
            self._logger.error("Failed to login FireEye HX: authorization failed")
            raise Exception("Failed to login FireEye HX: authorization failed")

    def query_host(self, agent_url, statistic_session=None):
        in_statistic = None
        if statistic_session is not None:
            in_statistic = CollectorStatistic.create_statistic_event()
            CollectorStatistic.add_statistic_event(statistic_session, in_statistic)
        host_id = re.sub(r'/hx/api/v3/hosts/', '', agent_url)
        host_ip = ""
        host_name = ""
        if not host_id:
            return host_ip, host_name
        if host_id in self._host_cache:
            host_info = self._host_cache.pop(host_id)
            self._host_cache[host_id] = host_info
            return host_info.get("ip"), host_info.get("name")
        url = self._base_url + self.HOST_ID_PATH.format(host_id)
        response = self._rest_client.get_request(url=url, auth_header=self._headers, params={}, statistic=in_statistic)
        if (not response is None) and ("data" in response):
            host_ip = response["data"].get("primary_ip_address", "")
            host_name = response["data"].get("hostname", "")
            self._host_cache[host_id] = {"ip": host_ip, "name": host_name}
            if len(self._host_cache) > self._cache_size:
                self._host_cache.popitem(last=False)
            self._host_cache_updated = True
        return host_ip, host_name

    def update_host_cache(self, host_id, host_ip, host_name):
        if host_id in self._host_cache:
            self._host_cache[host_id] = {"ip": host_ip, "name": host_name}

    def load_host_cache(self, path):
        """Load host cache from file"""
        try:
            if os.path.exists(path):
                with open(path) as json_file:
                    self._host_cache = json.load(json_file, object_pairs_hook=OrderedDict)
        except Exception as e:
            if self._logger:
                self._logger.error("Failed to load cache {0}".format(str(e)))

    def save_host_cache(self, path):
        """Save host cache to file"""
        if not self._host_cache_updated:
            return
        with open(path, 'w') as outfile:
            json.dump(self._host_cache, outfile)
        self._host_cache_updated = False

    def remove_host_cache(self, path):
        """Remove host cache"""
        if os.path.exists(path):
            os.remove(path)
            if self._logger:
                self._logger.info("Removed host cache file {0}".format(path))

    # Public method start
    def query_hosts(self, content_type, start_time, end_time, statistic_session=None):
        """Query hosts between start_time and end_time"""
        url = self._base_url + self.HOST_PATH
        return self._query(url, content_type, start_time, end_time, statistic_session)

    def query_host_sets(self, content_type, start_time, end_time, statistic_session=None):
        """Query host sets between start_time and end_time"""
        url = self._base_url + self.HOST_SET_PATH
        return self._query(url, content_type, start_time, end_time, statistic_session)

    def query_alerts(self, content_type, start_time, end_time, statistic_session=None):
        """Query alerts between start_time and end_time"""
        url = self._base_url + self.ALERT_PATH
        return self._query(url, content_type, start_time, end_time, statistic_session)

    # Private method start
    def _query(self, url, content_type, start_time, end_time, statistic_session=None):
        in_statistic = None
        if statistic_session is not None:
            in_statistic = CollectorStatistic.create_statistic_event()
            in_statistic[CollectorStatistic.KEY_CONNECTOR][CollectorStatistic.KEY_START_TIMESTAMP] = int(start_time.strftime('%s'))*1000
            in_statistic[CollectorStatistic.KEY_CONNECTOR][CollectorStatistic.KEY_END_TIMESTAMP] = int(end_time.strftime('%s'))*1000
            CollectorStatistic.add_statistic_event(statistic_session, in_statistic)

        params = {"limit": self.LIMIT}
        if content_type == self.CONTENT_TYPE_ALERT:
            start_date = start_time.isoformat() + 'Z'
            end_date = end_time.isoformat() + 'Z'
            query = json.dumps({"operator": "between", "arg": [start_date, end_date], "field" :"reported_at"})
            params.update({"filterQuery": query})

        response = self._rest_client.get_request(url=url, auth_header=self._headers, params=params, statistic=in_statistic)
        if self._http_success(response):
            result = self._pagination(response, url, params, statistic_session)
            CollectorStatistic.try_set_statistic_value(in_statistic, False, CollectorStatistic.KEY_IN_RECORDS_DELTA, len(result))
            return result
        return None

    def _pagination(self, response, url, params, statistic_session=None):
        result = []
        result.extend(response.get("data", {}).get("entries"))
        while response.get("data", {}).get("entries"):
            in_statistic = None
            if statistic_session is not None:
                in_statistic = CollectorStatistic.create_statistic_event()
                CollectorStatistic.add_statistic_event(statistic_session, in_statistic)
            offset = response.get("data", {}).get("offset") + self.LIMIT
            params.update({"offset": offset})
            new_response = self._rest_client.get_request(url=url, auth_header=self._headers, params=params, statistic=in_statistic)
            if self._http_success(new_response):
                response = new_response
                result.extend(response.get("data", {}).get("entries"))
        return result

    def _http_success(self, response):
        return (not response is None) and ('entries' in response.get("data", {})) and ('offset' in response.get("data", {}))