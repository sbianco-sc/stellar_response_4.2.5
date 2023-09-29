import hashlib
import json
import random
import subprocess
import time

import utils

TIMEOUT_RC = 124

class SshConnector:

    def __init__(self, user, password, host, port=22, **kwargs):
        self.user = user
        self.password = utils.aella_decode(utils.COLLECTOR_SECRET, password)
        self.host = host
        self.port = str(port)

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
        if action_name == "run_command":
            run_on = settings.get("run_on", "")
            command_list = settings.get("command_list", [])
            timeout = settings.get("timeout", 300)
            for command in command_list:
                now = int(time.time() * 1000)
                seed = "{}{}{}".format(now, command, random.randint(0, 99999999))
                action_id = hashlib.md5(seed).hexdigest()
                curr_params = {"command": command, "timeout": timeout,
                    "time_and_cmd_id": action_id}
                if run_on:
                    curr_params["run_on"] = run_on
                params.append(curr_params)
        return params

    def test_connection(self, **kwargs):
        """
        Function used by Stellar Cyber for configuration validation
        :return: str: 'succeeded' if the connection test passes
            otherwise, a custom message to show to user
        """
        run_on = kwargs.get("run_on", "dp")
        if run_on != "" and run_on != "dp":
            return self.notify_ds_to_test_connection(run_on)
        status_code, error_msg = self.run_command_helper("exit")
        if status_code == 0:
            return utils.create_response("SSH", 200, "")
        return utils.create_response("SSH", 400, error_msg)

    def notify_ds_to_test_connection(self, run_on):
        """
        Notify DS to perform the connection test
        :param run_on: str: the engid of sensor to run the test
        :return: str: the test results
        """
        command = "timeout 30 sshpass -p {} ssh -o StrictHostKeyChecking=no -p {} {}@{} exit".format(
            utils.aella_encode(utils.COLLECTOR_SECRET, self.password), self.port, self.user, self.host)
        status_code, error_msg = utils.execute_action_on_ds(run_on, command, retry_count=1)
        if status_code > 0:
            return utils.create_response("SSH", 400, "Connection test failed: {}".format(error_msg))
        return utils.create_response("SSH", 200, "succeeded")

    def run_command(self, command, timeout=300, **kwargs):
        run_on = kwargs.get("run_on", "dp")
        if run_on.lower() == "dp" or run_on == "":
            status_code, error_msg = self.run_command_helper(command, timeout=timeout)
        else:
            status_code, error_msg = self.run_command_on_sensor_helper(command, run_on, timeout=timeout)
        if status_code != 0:
            raise Exception("Failed to run command: rc {}: {}".format(
                status_code, error_msg))
        return {"result_msg": "Success"}

    def run_command_helper(self, command, timeout=300):
        ssh_cmd = ["timeout", str(timeout), "sshpass", "-p", self.password,
                "ssh", "-o", "StrictHostKeyChecking=no", "-p", self.port,
                "{}@{}".format(self.user, self.host), command]
        ssh_proc = subprocess.Popen(ssh_cmd,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        result, error_msg = ssh_proc.communicate()
        status_code = ssh_proc.returncode
        if status_code == TIMEOUT_RC:
            error_msg = "Command timed out"
        return status_code, error_msg


    def run_command_on_sensor_helper(self, command, run_on, timeout=300):
        status_code = 0
        error_msg = ""
        cm_url = "https://aella-cm:5000/api/1.0/de_notify/{}".format(run_on)
        start_time = int(time.time())
        now = int(time.time() * 1000)
        seed = "{}{}{}".format(now, command, random.randint(0, 99999999))
        action_id = hashlib.md5(seed).hexdigest()
        payload = {"json":
                      {"msg":
                          {"action": "run_script",
                           "params":[action_id, self.host, self.port, self.user,
                                     utils.aella_encode(utils.COLLECTOR_SECRET, self.password),
                                     command]
                          }
                      }
                  }
        res = utils.put_request(cm_url, payload, logger=utils.logger)
        if res is None:
            return 1, "Failed to notify sensor to execute action"
        utils.logger.info("Notified DS %s to run action %s", run_on, action_id)
        get_feedback = False
        abort_time = start_time + timeout
        current_time = int(time.time())
        # Pulling status from CM every 15 seconds
        while True:
            try:
                current_time = int(time.time())
                if current_time > abort_time:
                    break
                feedback_url = "https://aella-cm:5000/api/1.0/feedback/{}".format(action_id)
                res = utils.get_request(feedback_url, logger=utils.logger)
                if res is None:
                    time.sleep(15)
                    continue
                feedback_info = json.loads(res)
                feedback_str = feedback_info.get("feedback", "{}")
                feedback = json.loads(feedback_str).get("feedback", {})
                status_code = feedback.get("retcode", 0)
                utils.logger.info("Action %s got return code of %s", action_id, status_code)
                error_msg = feedback.get("stderr", "")
                get_feedback = True
                delete_url = "https://aella-cm:5000/api/1.0/feedback/{}".format(action_id)
                utils.delete_request(delete_url, logger=utils.logger)
                break
            except Exception as e:
                utils.logger.error("Failed to get feedback status: %s", e)
            time.sleep(15)
        if not get_feedback:
            return 1, "Timed out waiting for sensor to report execution results"
        return status_code, error_msg
