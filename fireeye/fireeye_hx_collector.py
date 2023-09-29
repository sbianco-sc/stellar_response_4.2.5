#!/usr/local/bin/python
"""
This is the class to continously collectc FireEye HX logs
"""
# /var/lib/docker/overlay2/fee3bcdd84bdb56ef0eb7640faf3a0aceb9ad79f3715bee14d7186f9d4548a39/merged/fireeye_hx/fireeye_hx_collector.py
import argparse
import json
import time
from datetime import datetime, timedelta
from builtins import super
import os

import collector_kafka_sender as kafka_sender
from fireeye_hx_connector import FireEyeHXConnector
from aella_oauth2 import AellaOauth2Credential
from collector_logger import CollectorLogger
from collector_base import CollectorBase
from collector_statistic import CollectorStatistic

class FireEyeHXCollector(CollectorBase):
    """The collector class"""

    LOG_PATH = "/work/log-collector/logs/fireeye_hx_collector.log"
    CHECKPOINT_PATH_TEMPLATE = "/work/log-collector/config/fireeye_hx_checkpoint_{0}.yml"
    NORMALIZATION_CONFIG_PATH = "/work/log-collector/fireeye_hx/normalization.json"
    HOST_CACHE_PATH_TEMPLATE = "/work/log-collector/config/fireeye_hx_cache_{0}.json"
    SOURCE = "fireeye_hx"

    CONFIG_KEY_HOST_NAME = "host"
    CONFIG_KEY_USER_ID = "user_id"
    CONFIG_KEY_PASSWORD = "password"
    CONFIG_KEY_CACHE_SIZE = "cache_size"

    CHECKPOINT_KEY_HOSTS = "hosts_last_success"
    CHECKPOINT_KEY_HOST_SETS = "host_sets_last_success"
    CHECKPOINT_KEY_ALERTS = "alerts_last_success"

    CONTENT_TYPE_HOST = "hosts"
    CONTENT_TYPE_HOST_SET = "host_sets"
    CONTENT_TYPE_ALERT = "alerts"

    HOST_INTERVAL = 60 * 60 * 24
    HOST_CACHE_CAPACITY = 500

    def __init__(self, config_path):
        super().__init__(config_path, self.LOG_PATH, self.SOURCE, self.CHECKPOINT_PATH_TEMPLATE, self.NORMALIZATION_CONFIG_PATH)
        self._refresh_credential("", "", "", self.HOST_CACHE_CAPACITY)
        default_checkpoint = {
            self.CHECKPOINT_KEY_HOSTS : (datetime.utcnow() -timedelta(hours=self.INITIAL_BACK_FILL_HOUR + 24)).strftime('%s'),
            self.CHECKPOINT_KEY_HOST_SETS : (datetime.utcnow() - timedelta(hours=self.INITIAL_BACK_FILL_HOUR + 24)).strftime('%s'),
            self.CHECKPOINT_KEY_ALERTS : (datetime.utcnow() -timedelta(hours=self.INITIAL_BACK_FILL_HOUR)).strftime('%s')
        }
        self._load_checkpoint(default_checkpoint)
        self._content_func_map = {
            self.CONTENT_TYPE_HOST : self._get_host,
            self.CONTENT_TYPE_HOST_SET : self._get_host,
            self.CONTENT_TYPE_ALERT : self._get_content
        }
        self._content_para_map = {
            self.CONTENT_TYPE_HOST : {"content_type": self.CONTENT_TYPE_HOST},
            self.CONTENT_TYPE_HOST_SET : {"content_type": self.CONTENT_TYPE_HOST_SET},
            self.CONTENT_TYPE_ALERT : {"content_type": self.CONTENT_TYPE_ALERT}
        }
        self._host_cache_path = self.HOST_CACHE_PATH_TEMPLATE.format(os.path.basename(config_path))
        self._connector.load_host_cache(self._host_cache_path)

    # The entrypoint
    def start_collector(self):
        while True:
            try:
                # Refresh config for user changes
                # If configuration file is removed or deprecated, the collector needs to shut down itself
                tenantid = self._aella_tenantid
                host_name = self._collector_config[self.CONFIG_KEY_HOST_NAME]
                user_id = self._collector_config[self.CONFIG_KEY_USER_ID]
                user_password = self._collector_config[self.CONFIG_KEY_PASSWORD]
                cache_size = self._collector_config.get(self.CONFIG_KEY_CACHE_SIZE, self.HOST_CACHE_CAPACITY)
                if not self._load_config():
                    self._connector.remove_host_cache(self._host_cache_path)
                    self._remove_checkpoint()
                    return
                # Force to collect host information
                if self.CONTENT_TYPE_HOST not in self._content_list:
                    self._content_list.append(self.CONTENT_TYPE_HOST)
                self._refresh_credential(host_name, user_id, user_password, cache_size)
                self._refresh_kafka_client(tenantid)
                self._collect_content(self._content_func_map, self._content_para_map)
            except Exception as e:
                self._logger.error("Exception in start_collector {0}".format(str(e)))
            time.sleep(self._interval*60)

    def _get_host(self, content_type):
        if content_type == self.CONTENT_TYPE_HOST:
            checkpoint_key = self.CHECKPOINT_KEY_HOSTS
            func = self._connector.query_hosts
        elif content_type == self.CONTENT_TYPE_HOST_SET:
            checkpoint_key = self.CHECKPOINT_KEY_HOST_SETS
            func = self._connector.query_host_sets
        try:
            self._load_checkpoint()
            last_time = int(self._checkpoint_info[checkpoint_key])
            now_time = int(datetime.utcnow().strftime('%s'))
            if now_time - last_time >= self.HOST_INTERVAL:
                statistic_session = CollectorStatistic.create_statistic_session()
                self._connector.login()
                data = func(content_type, datetime.utcnow(), datetime.utcnow(), statistic_session)
                out_statistic = CollectorStatistic.create_statistic_event(count_statistic=False)
                if data is None:
                    raise RuntimeError("Failed to query for {0}".format(content_type))
                if len(data) > 0:
                    normalized_results = self._normalizer.normalization(data, content_type)
                    enriched_data = self.enrichment(normalized_results, content_type)
                    if content_type == self.CONTENT_TYPE_HOST:
                        host_json = self.create_host_data(enriched_data)
                        if host_json:
                            if not self.send_data(host_json, self.SOURCE + '_' + content_type, statistic=out_statistic):
                                raise RuntimeError("Failed to send host json")
                            self._logger.info("{0}|Sent {1} host message".format(content_type, len(host_json)))
                    if not self.send_data(enriched_data, self.SOURCE + '_' + content_type, statistic=out_statistic):
                        raise RuntimeError("Failed to send data")
                    self._logger.info("{0}|Sent {1} json message".format(content_type, len(enriched_data)))
                else:
                    self._logger.info("{0}|No new data to fetch".format(content_type))
                self._checkpoint_info.update({checkpoint_key : str(now_time)})
                self._save_checkpoint(self._checkpoint_info)
                out_statistic[CollectorStatistic.KEY_CONNECTOR][CollectorStatistic.KEY_HTTP_CODE] = 200
                CollectorStatistic.add_statistic_event(statistic_session, out_statistic)
                summary = CollectorStatistic.summarize_statistic_session(statistic_session, CollectorStatistic.KEY_HTTP_CODE, self._logger, sys_stats = self._sys_health)
                normalized_stat_summary = self._normalizer.stat_normalization(summary, content_type, self._ds_name)
                if not self.send_data(normalized_stat_summary, (self.SOURCE + '_' + content_type).lower()):
                    self._logger.error("{0}|Failed to send statistic summary".format(content_type))
        except Exception as e:
            self._logger.error("{0}|Exception in _get_host {1}".format(content_type, str(e)))

    def _get_content(self, content_type):
        if content_type == self.CONTENT_TYPE_ALERT:
            check_point_key = self.CHECKPOINT_KEY_ALERTS
            func = self._connector.query_alerts

        try:
            # Call connector to get content
            self._load_checkpoint()
            start_time_range = datetime.fromtimestamp(int(self._checkpoint_info[check_point_key]))
            end_time_range = datetime.utcnow() - timedelta(minutes=self._query_delay)
            statistic_session = CollectorStatistic.create_statistic_session()

            self._connector.login()
            for start_time, end_time in self.time_split(start_time_range, end_time_range, timedelta(minutes=self.DEFAULT_INTERVAL_WINDOW_SIZE)):
        self._logger.info("getting data")
                data = func(content_type, start_time, end_time, statistic_session)
        self._logger.info("got data")
                out_statistic = CollectorStatistic.create_statistic_event(count_statistic=False)
                if data is None:
                    raise RuntimeError("Failed to query for {0}".format(content_type))
                if len(data) > 0:
                    normalized_results = self._normalizer.normalization(data, content_type)
                    enriched_data = self.enrichment(normalized_results, content_type, statistic_session)
                    #enriched_data = normalized_results

                    if not self.send_data(enriched_data, (self.SOURCE + '_' + content_type).lower(), statistic=out_statistic):
                        raise RuntimeError("Failed to send data")
                    self._logger.info("{0}|Sent {1} json message".format(content_type, len(enriched_data)))
                else:
                    self._logger.info("{0}|No new data to fetch".format(content_type))

                self._checkpoint_info.update({check_point_key : end_time.strftime('%s')})
                self._save_checkpoint(self._checkpoint_info)
                self._connector.save_host_cache(self._host_cache_path)
                out_statistic[CollectorStatistic.KEY_CONNECTOR][CollectorStatistic.KEY_HTTP_CODE] = 200
                CollectorStatistic.add_statistic_event(statistic_session, out_statistic)
        except Exception as e:
            self._logger.error("{0}|Exception in _get_content {1}".format(content_type, str(e)))
        finally:
            summary = CollectorStatistic.summarize_statistic_session(statistic_session, CollectorStatistic.KEY_HTTP_CODE, self._logger, sys_stats = self._sys_health)
            normalized_stat_summary = self._normalizer.stat_normalization(summary, content_type, self._ds_name)
            if not self.send_data(normalized_stat_summary, (self.SOURCE + '_' + content_type).lower()):
                self._logger.error("{0}|Failed to send statistic summary".format(content_type))

    def _refresh_credential(self, host_name, user_id, user_password, cache_size):
        if (host_name != self._collector_config[self.CONFIG_KEY_HOST_NAME] or
            user_id != self._collector_config[self.CONFIG_KEY_USER_ID] or
            user_password != self._collector_config[self.CONFIG_KEY_PASSWORD] or
            cache_size != self._collector_config.get(self.CONFIG_KEY_CACHE_SIZE, self.HOST_CACHE_CAPACITY)):
            self._connector = FireEyeHXConnector(self._collector_config[self.CONFIG_KEY_HOST_NAME],
                                self._collector_config[self.CONFIG_KEY_USER_ID],
                                self.decode_credential(self._collector_config[self.CONFIG_KEY_PASSWORD]),
                                self._collector_config.get(self.CONFIG_KEY_CACHE_SIZE, self.HOST_CACHE_CAPACITY), self._logger)

    def enrichment(self, json_object, content_type, statistic_session=None):
        if not json_object:
            return json_object

        if isinstance(json_object, list):
            result = []
            for element in json_object:
                result.append(self._enrichment(element, content_type, statistic_session=None))
            return result
        elif isinstance(json_object, dict):
            return self._enrichment(json_object, content_type, statistic_session=None)
        else:
            return json_object

    def _enrichment(self, json_object, content_type, statistic_session=None):
        fireeye_hx = json_object.get("fireeye", {})
        if content_type == self.CONTENT_TYPE_HOST:
            host_id = fireeye_hx.get("_id", "")
            host_ip = json_object.get("srcip", "")
            host_name = json_object.get("srcip_host", "")
            if host_id and host_ip and host_name:
                self._connector.update_host_cache(host_id, host_ip, host_name)
        elif content_type == self.CONTENT_TYPE_ALERT:
            if "host" not in json_object:
                json_object["host"] = {}
            agent_url = fireeye_hx.get("agent", {}).get("url", "")
            if agent_url:
                host_ip, host_name = self._connector.query_host(agent_url, statistic_session)
            if host_ip:
                json_object["hostip"] = host_ip
                json_object["host"]["ip"] = host_ip
            if host_name:
                json_object["host"]["name"] = host_name

            indicator = fireeye_hx.get("indicator", {})
            if not indicator:
                if fireeye_hx.get("multi_indicators", []):
                    indicator = fireeye_hx["multi_indicators"][0]
            if "event" not in json_object:
                json_object["event"] = {}
            if indicator:
                event_name = indicator.get("name", "")
                event_display_name = indicator.get("display_name", "")
            try:
            if event_name:
                    json_object["event"]["name"] = event_name
                if event_display_name:
                    json_object["event"]["displayname"] = event_display_name
        except:
            pass

        if isinstance(fireeye_hx.get("event_values", None), dict):
            if "user" not in json_object:
                json_object["user"] = {}
            username = fireeye_hx.get("event_values", {}).get("fileWriteEvent/username", "")
            if not username:
                username = fireeye_hx.get("event_values", {}).get("processEvent/username", "")
            if not username:
                username = fireeye_hx.get("event_values", {}).get("regKeyEvent/username", "")
            if not username:
                username = fireeye_hx.get("event_values", {}).get("urlMonitorEvent/username", "")
            if username:
                json_object["user"]["name"] = username


            if "file" not in json_object:
                json_object["file"] = {}
            file_name = fireeye_hx.get("event_values", {}).get("fileWriteEvent/fileName", "")
            if file_name:
                json_object["file"]["name"] = file_name
            file_path = fireeye_hx.get("event_values", {}).get("fileWriteEvent/fullPath", "")
            if file_path:
                json_object["file"]["path"] = file_path

            if "process" not in json_object:
                json_object["process"] = {}
            process_name = fireeye_hx.get("event_values", {}).get("processEvent/process", "")
            if not process_name:
                process_name = fireeye_hx.get("event_values", {}).get("fileWriteEvent/process", "")
            if not process_name:
                process_name = fireeye_hx.get("event_values", {}).get("regKeyEvent/process", "")
            if not process_name:
                process_name = fireeye_hx.get("event_values", {}).get("urlMonitorEvent/process", "")
            if process_name:
                json_object["process"]["name"] = process_name
            process_executable = fireeye_hx.get("event_values", {}).get("processEvent/processPath", "")
            if not process_executable:
                process_executable = fireeye_hx.get("event_values", {}).get("fileWriteEvent/processPath", "")
            if not process_executable:
                process_executable = fireeye_hx.get("event_values", {}).get("regKeyEvent/processPath", "")
            if not process_executable:
                process_executable = fireeye_hx.get("event_values", {}).get("urlMonitorEvent/processPath", "")
            if process_executable:
                json_object["process"]["executable"] = process_executable
            # process pid, parent process pid, and dstport are of type integer and can be zero, so cannot use if not to check
            process_pid = fireeye_hx.get("event_values", {}).get("processEvent/pid", "")
            if process_pid == "":
                process_pid = fireeye_hx.get("event_values", {}).get("regKeyEvent/pid", "")
            if process_pid == "":
                process_pid = fireeye_hx.get("event_values", {}).get("urlMonitorEvent/pid", "")
            if process_pid == "":
                process_pid = fireeye_hx.get("event_values", {}).get("fileWriteEvent/pid", "")
            if process_pid == "":
                process_pid = fireeye_hx.get("event_values", {}).get("ipv4NetworkEvent/pid", "")
            if process_pid != "":
            json_object["process"]["pid"] = process_pid
            if "parent" not in json_object.get("process", {}):
                json_object["process"]["parent"] = {}
            parent_name = fireeye_hx.get("event_values", {}).get("processEvent/parentProcess", "")
            if not parent_name:
            parent_name = fireeye_hx.get("event_values", {}).get("fileWriteEvent/parentProcess", "")
            if parent_name:
            json_object["process"]["parent"]["name"] = parent_name
            parent_executable = fireeye_hx.get("event_values", {}).get("processEvent/parentProcessPath", "")
            if not parent_executable:
            parent_executable = fireeye_hx.get("event_values", {}).get("fileWriteEvent/parentProcessPath", "")
            if parent_executable:
            json_object["process"]["parent"]["executable"] = parent_executable
            parent_pid = fireeye_hx.get("event_values", {}).get("processEvent/parentPid", "")
            if parent_pid == "":
            parent_pid = fireeye_hx.get("event_values", {}).get("fileWriteEvent/parentPid", "")
            if parent_pid != "":
            json_object["process"]["parent"]["pid"] = parent_pid
            command_line = fireeye_hx.get("event_values", {}).get("processEvent/processCmdLine", "")
            if command_line:
            json_object["process"]["command_line"] = command_line

            hostname  = fireeye_hx.get("event_values", {}).get("urlMonitorEvent/hostname", "")
            request_url = fireeye_hx.get("event_values", {}).get("urlMonitorEvent/requestUrl", "")
            url = hostname + request_url
            if url:
            json_object["url"] = url
            dstip = fireeye_hx.get("event_values", {}).get("urlMonitorEvent/remoteIpAddress", "")
            if not dstip:
            dstip = fireeye_hx.get("event_values", {}).get("ipv4NetworkEvent/remoteIP", "")
            if dstip:
            json_object["dstip"] = dstip
            dstport = fireeye_hx.get("event_values", {}).get("urlMonitorEvent/remotePort", "")
            if dstport == "":
            dstport = fireeye_hx.get("event_values", {}).get("ipv4NetworkEvent/remotePort", "")
            if dstport != "":
            json_object["dstport"] = dstport
        return json_object

if __name__ == "__main__":
    description = \
    """
    Retrieve log contents from FireEye HX API and save to kafka.
    """
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('-c', action='store', dest='config_file',
                        help='The configuration file that defines the FireEye HX data source.')
    args = parser.parse_args()
    argsdict = vars(args)

    collector = FireEyeHXCollector(argsdict['config_file'])
    collector.start_collector()