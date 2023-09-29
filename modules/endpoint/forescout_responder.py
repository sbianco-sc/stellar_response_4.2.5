#!/usr/bin/python
"""
Forescout Responder class
"""
import argparse
import logging
import logging.handlers
import sys
import json
import utils
from forescout_connector import ForescoutConnector

class ForescoutResponder:
    DS_SCRIPT_PATH = "/opt/aelladata/connector/modules/endpoint/forescout_responder.py"

    def __init__(self, hostname, username, password, app_name, lgr=None, **kwargs):
        self._hostname = hostname
        self._username = username
        self._password = password
        self._app_name = app_name
        self._connector = ForescoutConnector(hostname, username, utils.aella_decode(utils.COLLECTOR_SECRET, password), app_name, lgr)

    # Public method start
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
        # No implementation for now since this connector does not support automation
        return params

    def update_device(self, mac, cidr, properties, **kwargs):
        """Update device properties using action api"""
        run_on = kwargs.get("run_on", "dp")
        if run_on != "" and run_on != "dp":
            return self._run_action_on_ds("update_device", cidr, mac, properties, run_on)
        return self._connector.update_device(mac, cidr, properties)

    def test_connection(self, **kwargs):
        """Test connection to api"""
        run_on = kwargs.get("run_on", "dp")
        if run_on != "" and run_on != "dp":
            return self._notify_ds_to_test_connection(run_on)
        if self._connector.test_connection() == "succeeded":
            code = 200
        else:
            code = 400
        return utils.create_response("Forescout", code, self._connector.test_connection())

    # Private method start
    def _run_action_on_ds(self, action, cidr, mac, properties, run_on):
        # properties is a JSON string, so we need to escape " in the cmd for -d "JSON string"   
        properties = properties.replace('"','\\"')
        command = "export PYTHONPATH={}; python {} -a {} -t \"{}\" -u \"{}\" -p \"{}\" -b \"{}\"".format(
                  utils.PYTHONPATH, self.DS_SCRIPT_PATH, action, self._hostname, self._username, self._password, self._app_name)
        if mac is not None:
            command += " -m \"{}\"".format(mac)
        if cidr is not None:
            command += " -c \"{}\"".format(cidr)
        command += " -d \"{}\"".format(properties)
        status_code, error_msg = utils.execute_action_on_ds(run_on, command)
        if status_code > 0:
            raise Exception("Action fail with status code {}: {}".format(status_code, error_msg))
        return {"result_msg": "Action succeeded"}

    def _notify_ds_to_test_connection(self, run_on):
        command = "export PYTHONPATH={}; python {} -a test -t \"{}\" -u \"{}\" -p \"{}\" -b \"{}\"".format(
                  utils.PYTHONPATH, self.DS_SCRIPT_PATH, self._hostname, self._username, self._password, self._app_name)
        status_code, error_msg = utils.execute_action_on_ds(run_on, command, retry_count=1)
        if status_code > 0:
            return utils.error_msg_process("Forescout", error_msg)
        return utils.create_response("Forescout", 200, "succeeded")

    def test_connection_on_ds(self):
        """
        This function will only be called on DS
        """
        res = self.test_connection()
        if utils.test_response_success(res):
            return "succeeded"
        raise Exception(res)

if __name__ == '__main__':
    LOG_FILENAME = "/var/log/aella/forescout_responder.log"
    FORMAT = "%(asctime)-15s|%(name)s|%(levelname)s|%(message)s"
    logger = logging.getLogger("forescout_responder")
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter(FORMAT)
    handler = logging.handlers.WatchedFileHandler(LOG_FILENAME)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--action', action='store', dest='action', required=True,
        help='The action to take')
    parser.add_argument('-t', '--hostname', action='store', dest='hostname', required=True,
        help='The hostname of EM')
    parser.add_argument('-u', '--username', action='store', dest='username', required=True,
        help='The username to login EM')
    parser.add_argument('-p', '--password', action='store', dest='password', required=True,
        help='The password to login EM')
    parser.add_argument('-b', '--app_name', action='store', dest='app_name', required=True,
        help='The app name to access API')
    parser.add_argument('-c', '--cidr', action='store', dest='cidr', required=False,
        help='The CIDR as input of action')
    parser.add_argument('-m', '--mac', action='store', dest='mac', required=False,
        help='The MAC as input of action')
    parser.add_argument('-d', '--properties', action='store', dest='properties', required=False,
        help='The properties as input of action')

    results = parser.parse_args()
    responder = ForescoutResponder(results.hostname, results.username, results.password, results.app_name, logger)

    if results.action == "test":
        try:
            res = responder.test_connection_on_ds()
        except Exception as e:
            sys.stderr.write(utils.ERROR_HEAD + str(e) + utils.ERROR_END)
            sys.exit(1)
        print res
        sys.exit()

    if results.action == "update_device":
        try:
            res = responder.update_device(results.mac, results.cidr, results.properties)
        except Exception as e:
            sys.stderr.write("Failed to update device: {} \n".format(e))
            sys.exit(1)
        print res
        sys.exit()
