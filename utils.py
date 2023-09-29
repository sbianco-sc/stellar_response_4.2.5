import base64
import imp
import hashlib
import json
import logging
from logging.handlers import WatchedFileHandler
import random
import requests
import os
import subprocess
import time
try:
    import urlparse, urllib
except:
    # python3 import
    import urllib
    import urllib.parse as urlparse

### Constants ###
SERVER_USER = "stellar"
SERVER_PASS = "SvGaXzkg3p7CEf9gJwdD"
SERVER_FQDN = "acps.stellarcyber.ai"

MONGODB_SVC_NAME = "custom-response-mongodb"
MONGODB_URL = "mongodb://{}:27017".format(MONGODB_SVC_NAME)
DB_NAME = "thirdparty"
CUSTOM_RESPONSE_TABLE_NAME = "custom_response"
CUSTOM_RESPONSE_ACTION_TABLE_NAME = "custom_response_action"
RESERVED_KEYS = ["action_name", "revert_action_name", "duration",
        "component_name", "cust_id", "status", "timestamp", "execution_start",
        "execution_end", "params", "unique_key", "error_msg"]

REQUEST_TIMEOUT = 60
MISSING_JSON_DATA_MSG = "No json data received\n"
DUPLICATE_ENTRY_MSG = "Duplicate entry, no action taken\n"
NOT_FOUND_MSG = "Record not found\n"
MULTIPLE_FOUND_MSG = "Found more than one record\n"
OK_MSG = "OK\n"
DEFAULT_MONGO_ERROR_MSG = "An exception occurred. No action taken\n"
DEFAULT_EXCEPTION_MSG = "An exception occurred\n"

WAITING = "waiting"
IN_PROGRESS = "in progress"
SUCCESS = "succeeded"
FAILURE = "failed"
EXPIRING = "expiring"
EXPIRED = "expired"
REVERTING = "reverting"
REVERTED = "reverted"
DONE_STATES = [SUCCESS, FAILURE, EXPIRED, REVERTED]
PENDING_STATES = [WAITING, IN_PROGRESS, EXPIRING, REVERTING]

FW_CONNECTION_SUCCESS = "Success"
ERROR_HEAD = "STELLAR_MESSAGE_HEAD"
ERROR_END = "STELLAR_MESSAGE_TAIL"

### Paths ###
BASE_DIR = "/opt/thirdparty"
CONFIG_DIR = "{}/config".format(BASE_DIR)
LOG_DIR = "{}/log".format(BASE_DIR)
MODULE_CONFIG_FILE = "{}/module_config.json".format(CONFIG_DIR)
MODULE_PACKAGE_FILE = "{}/custom_response.deb".format(BASE_DIR)
LOG_FILE = "{}/custom_response.log".format(LOG_DIR)

SERVER_MODULE_CONFIG_FILE = "release/thirdparty/config.json"
SERVER_MODULE_PACKAGE_FILE = "release/thirdparty/custom_response.deb"

COLLECTOR_SECRET = 'Configure Collector'

### Logging ###
def get_logger(name):
    logger = logging.getLogger(name)
    FORMAT = '%(asctime)-15s|%(name)s|%(levelname)s|%(message)s'
    formatter = logging.Formatter(FORMAT)
    handler = WatchedFileHandler("{}.log".format(name))
    # handler = WatchedFileHandler("{}/{}.log".format(LOG_DIR, name))
    handler.setFormatter(formatter)
    handler.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    return logger
logger = get_logger("custom_response")
action_agent_logger = get_logger("action_agent")

### Configuration ###
module_map = {}
module_config = {}

PYTHONPATH="/opt/aelladata/connector:/opt/aelladata/connector/modules:/opt/aelladata/connector/common:/opt/aelladata/connector/connector"

### PROXY ###
def get_proxy_settings():
    try:
        proxy = {}
        proxy_url = os.getenv('APP_PROXY')
        if proxy_url:
            proxy = {"https": proxy_url}
        logger.info("The proxy got from get_proxy_settings {}".format(proxy_url))
        return proxy
    except Exception as e:
        logger.error("Exception Raised from get_proxy_settings {}".format(e))
        return proxy

PROXY = get_proxy_settings()

def update_module_map(module=None):
    failed = False
    if not load_module_config():
        return False
    if module is None:
        module_list = list(module_config.keys())
    else:
        module_list = [module]
    for module in module_list:
        if not update_single_module_in_map(module, module_config[module]):
            failed = True
    return not failed

def update_single_module_in_map(name, config):
    global module_map
    file_path = config.get("filepath")
    if not file_path or not os.path.isfile(file_path):
        logger.error("Filepath missing for {}".format(name))
        return False
    class_name = config.get("class_name")
    if not class_name:
        logger.error("Class name missing for {}".format(name))
        return False
    module_map[name] = getattr(imp.load_source(name, file_path), class_name)
    return True

def load_module_config():
    global module_config
    if not os.path.isfile(MODULE_CONFIG_FILE):
        download_and_install_module_files()
    try:
        with open(MODULE_CONFIG_FILE, "r") as f:
            module_config = json.load(f)
    except:
        return False
    return True

def download_and_install_module_files():
    if not download_module_files():
        return False
    if not install_module_files():
        return False
    return True

def download_module_files():
    if not download_server_file(SERVER_MODULE_CONFIG_FILE,
            MODULE_CONFIG_FILE):
        return False
    if not download_server_file(SERVER_MODULE_PACKAGE_FILE,
            MODULE_PACKAGE_FILE):
        return False
    return True

def install_module_files():
    install_cmd = "dpkg -i {}".format(MODULE_PACKAGE_FILE)
    result, msg = run_command_with_shell(install_cmd)
    if result:
        return True
    else:
        logger.error("Failed to install module package: {}".format(msg))
        return False

def get_inverse_action(action_name, component_config):
    module_name = component_config.get("type")
    action_config = module_config.get(module_name, {}).get(
            "actions", {}).get(action_name, {})
    inverse_action = action_config.get("revert_action_name", "")
    return inverse_action

def get_connection_test_name(component_config):
    module_name = component_config.get("type")
    function_name = module_config.get(module_name, {}).get(
            "connection_test_name")
    return function_name

def get_unique_key_list_from_config(component_config, action_name):
    module_name = component_config.get("type")
    key_list = module_config.get(module_name, {}).get(
            "actions", {}).get(action_name, {}).get("unique_key", [])
    return key_list

def get_unique_keys(key_list, action_params):
    unique_keys = {}
    for unique_key in key_list:
        unique_keys[unique_key] = action_params[unique_key]
    return unique_keys

def get_many_unique_keys(component_config, action_name, action_params):
    processed_key_list = []
    key_list = get_unique_key_list_from_config(component_config, action_name)
    for action in action_params:
        processed_keys = get_unique_keys(key_list, action)
        processed_key_list.append(processed_keys)
    return processed_key_list

def get_module_instance(component_config, logger=None):
    module_name = component_config.get("type")
    instance_params = json.loads(component_config.get("conf"))
    instance_params["lgr"] = logger
    module_instance = module_map[module_name](**instance_params)
    return module_instance

def get_action_params(component_config, action_name, settings, context):
    module_instance = get_module_instance(component_config)
    settings["component_name"] = component_config["name"]
    return module_instance.prepare(action_name, settings, context)

### Provision Server ###
def download_server_file(source, dest):
    """
    Downloads a file from the provision server
    :param source: remote path (<path> in <url>:<port>/<path>)
    :param dest: full file path to destination on host
    :return: bool, True if success, else False
    """
    download_cmd = "wget --no-check-certificate --user={} --password={} " \
            "https://{}/{} -O {}".format(
                    SERVER_USER, SERVER_PASS, SERVER_FQDN, source, dest)
    result, message = run_command_with_shell(download_cmd)
    if result:
        logger.debug("{} downloaded".format(source))
    else:
        logger.error("Failed to download {}: {}".format(source, message))
    return result

### Misc ###
def run_command_with_shell(cmd):
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, shell=True)
        result, error = proc.communicate()
        if proc.returncode == 0:
            return True, result
        else:
            return False, error
    except:
        return False, "Exception occurred"

def get_request(url, data=None, params=None, auth=False,
                logger=None, USER=None, PASSWD=None, headers=None):
    if auth:
        auth_info = (USER, PASSWD)
    else:
        auth_info = None
    try:
        if headers:
            response = requests.get(
                url, headers=headers, auth=auth_info,
                params=params, data=data, verify=False, timeout=REQUEST_TIMEOUT)
        else:
            response = requests.get(
                url, auth=auth_info,
                params=params, data=data, verify=False, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as e:
        if logger:
            logger.error("Get request {0} failed: {1}".format(url, e))
            return None
    if response.status_code == 200:
        return response.content
    else:
        if logger:
            logger.error("Get request {0} returned status {1}. {2}".format(url, response.status_code, response.content))
        return None

def put_request(url, payload, logger=None, auth=False, USER=None, PASSWD=None, params=None):
    headers = {"Content-Type": "application/json"}
    if auth:
        auth_info = (USER, PASSWD)
    else:
        auth_info = None
    try:
        response = requests.put(
            url,
            data=json.dumps(payload),
            headers=headers,
            params=params,
            auth=auth_info,
            verify=False,
            timeout=REQUEST_TIMEOUT)
    except requests.RequestException as e:
        if logger:
            logger.error("Put request {0} failed: {1}".format(url, e))
        return None
    if response.status_code == 200:
        return response.content
    else:
        if logger:
            logger.error("Put request {0} returned status {1}. {2}".format(url, response.status_code, response.content))
        return None

def delete_request(url, data=None, params=None, auth=False,
                logger=None, USER=None, PASSWD=None):
    headers = {"Content-Type": "application/json"}
    if auth:
        auth_info = (USER, PASSWD)
    else:
        auth_info = None
    try:
        response = requests.delete(
            url, headers=headers, auth=auth_info,
            verify=False, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as e:
        if logger:
            logger.error("Delete request {0} failed: {1}".format(url, e))
            return None
    if response.status_code == 200:
        return response.content
    else:
        if logger:
            logger.error("Delete request {0} returned status {1}. {2}".format(url, response.status_code, response.content))
        return None

def execute_action_on_ds(run_on, command, timeout=180, retry_count=5, retry_delta=60):
    retry = retry_count
    status_code = 1
    error_msg = ""
    while retry > 0 and status_code > 0:
        logger.info("Trying command of {0} run on {1} with retry count {2}".format(command, run_on, retry))
        status_code, error_msg = _execute_action_on_ds(run_on, command, timeout)
        retry -= 1
        timeout += retry_delta
    return status_code, error_msg

def _execute_action_on_ds(run_on, command, timeout=180):
    status_code = 0
    error_msg = ""
    logger.info("Notifying {} to run action: {}".format(run_on, command))
    cm_url = "https://aella-cm:5000/api/1.0/de_notify/{}".format(run_on)
    start_time = int(time.time())
    now = int(time.time() * 1000)
    seed = "{}{}{}".format(now, command, random.randint(0, 99999999))
    action_id = hashlib.md5(seed).hexdigest()
    payload = {"json":
                  {"msg":
                      {"action": "run_local_script",
                       "params":[action_id, command]
                      }
                  }
              }
    res = put_request(cm_url, payload, logger=logger)
    if res is None:
        return 1, "Failed to notify sensor to perform the operation"
    logger.info("Notified DS %s to run action %s", run_on, action_id)
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
            res = get_request(feedback_url, logger=logger)
            if res is None:
                time.sleep(15)
                continue
            feedback_info = json.loads(res)
            feedback_str = feedback_info.get("feedback", "{}")
            feedback = json.loads(feedback_str).get("feedback", {})
            status_code = feedback.get("retcode", 0)
            logger.info("Action %s got return code of %s", action_id, status_code)
            error_msg = feedback.get("stderr", "")
            error_lines = error_msg.split('\n')
            errors = []
            for error in error_lines:
                if "RequestsDependencyWarning" not in error:
                    errors.append(error)
            error_msg = "\n".join(errors)
            get_feedback = True
            delete_url = "https://aella-cm:5000/api/1.0/feedback/{}".format(action_id)
            delete_request(delete_url, logger=logger)
            break
        except Exception as e:
            logger.error("Failed to get feedback status: %s", e)
        time.sleep(15)
    if not get_feedback:
        return 1, "Timed out waiting for sensor to report execution results"
    return status_code, error_msg

def aella_decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(str(enc))
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        # dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec_c = chr((256 + enc[i] - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)


def aella_encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc))

def create_response(connector_name, status_code, log_content):
    message_map = {
        200 : "Success",
        400 : "Bad request, please check configuration",
        401 : "Unauthorized, please check Auth ID/KEY",
        403 : "Failed to get access token, please check Auth ID/KEY",
        404 : "Target not found on this host",
        500 : "Internal server error, could not connect to server",
        502 : "Bad gateway",
        504 : "Time out",
        505 : "HTTP Version not supported",
        0 : "Error on responder connection test"
    }
    response_text = connector_name + " - " + message_map.get(status_code, "Connector Failed") + " - status_code : " + str(status_code)
    response = '{"response":"' + response_text + '", "status":' + str(status_code) + ', "mimetype":"application/json","log":' + json.dumps(log_content) + '}'
    return response

def test_response_success(response):
    try:
        response_obj = json.loads(response)
        if response_obj["status"] >= 200 and response_obj["status"] < 300:
            return True
        return False
    except:
        return False

def error_msg_process(connector_name, error_msg):
    try:
        split_head = error_msg.split(ERROR_HEAD)
        head = split_head[0]
        split_end = split_head[1].split(ERROR_END)
        msg = split_end[0]
        end = split_end[1]
        msg_json = json.loads(msg.replace('\\', ''))
        return create_response(connector_name, int(msg_json["status"]), msg_json["log"] + " stderr: " + head + end)
    except Exception as e:
        return create_response(connector_name, 400, error_msg)

def build_url(base_url, path="", query_dict=None, logger=None):
    try:
        # the url_parts is parsed as 
        # scheme='https', netloc='', path='', params='', query='', fragment=''
        url_parts = list(urlparse.urlparse(base_url))
        if not url_parts[0] or not url_parts[1]:
            raise ValueError("Invalid input Base URL: {}".format(base_url))
        if url_parts[2].strip('/') == "":
            # the path in input base_url has only ending slashes
            url_parts[2] = path
        else:
            # keep the path in base_url
            url_parts[2] = url_parts[2].rstrip('/') + path
        if query_dict:
            url_parts[4] = urllib.urlencode(query_dict)
        return urlparse.urlunparse(url_parts)
    except Exception as e:
        if logger:
            logger.error(e)
        return None

def get_value(source, key):
        """
        Returns the value of <key> in <source>.
        copy from stellar-alert > image > util > templateutils.py, but remove list support
        """
        try:
            if not key:
                return source
            curr = source
            subkeys = key.split(".")
            for subkey in subkeys:
                curr = curr[subkey]
            return curr
        except Exception as e:
            # For backward compatibility
            logger.error("Could not get value at {}: {}".format(key, str(e)))
            return None