# aws, checkpoint, fortigate, hillstone & palo alto network firewalls
# will all use the same prepare function
import random
import string
import utils

SUCCESS = "Success"

DIRECTION_MAP = {
        "any": ["src", "dst"],
        "src": ["src"],
        "dst": ["dst"]
}

IP_TYPE_MAP = {
        "both": ["srcip", "dstip"],
        "srcip": ["srcip"],
        "dstip": ["dstip"]
}

def prepare(action_name, settings, source):
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
    batch_id = ""
    query_conf = settings.get("query_conf")
    is_correlation = query_conf is not None
    if settings.get("use_batch") is True:
        batch_id = {"src": get_batch_id(), "dst": get_batch_id()}
    if action_name == "block_ip" or action_name == "unblock_ip":
        for hit in source["ctx"]["payload"]["filtered"]:
            hit_src = hit["_source"]
            if is_correlation:
                correlation_info = hit_src.get("correlation_info", [])
                for query_info in correlation_info:
                    query_name = query_info.get("query_name", "")
                    fw_params = query_conf.get(query_name, {})
                    if not fw_params:
                        continue
                    for direction in DIRECTION_MAP[fw_params["direction"]]:
                        for ip_type in IP_TYPE_MAP[fw_params["ip_type"]]:
                            cidr = query_info.get(ip_type)
                            if not cidr:
                                continue
                            curr_params = {"direction": direction, "cidr": cidr}
                            if batch_id:
                                curr_params["batch_id"] = batch_id[direction]
                            params.append(curr_params)
            else:
                for direction in DIRECTION_MAP[settings.get("direction")]:
                    for ip_type in IP_TYPE_MAP[settings.get("ip_type")]:
                        cidr = hit_src.get(ip_type)
                        if not cidr:
                            continue
                        curr_params = {"direction": direction, "cidr": cidr}
                        if batch_id:
                            curr_params["batch_id"] = batch_id[direction]
                        params.append(curr_params)
    return params

def get_batch_id():
    chars = string.digits + string.ascii_letters
    base = "" 
    for _ in range(12):
        base += chars[random.randint(0, len(chars) - 1)]
    return base

def batch_process(action):
    new_params = {}
    for params in action["params"]:
        if new_params == {}:
            new_params["direction"] = params["direction"]
            new_params["cidr"] = []
        new_params["cidr"].append(params["cidr"])
    action["params"] = new_params

def block_ip_wrapper(connector_instance, cidr, direction, block_subnet=True, **kwargs):
    # Wrapper that's compatible with the custom response framework
    cidr_ip = cidr
    if block_subnet:
        if isinstance(cidr, list):
            cidr_ip = []
            for item in cidr:
                cidr_ip.append("{}/32".format(item))
        else:
            cidr_ip = "{}/32".format(cidr)

    if direction == "dst":
        egress = True
    else:
        egress = False
    run_on = kwargs.get("run_on", "dp")
    if run_on == "" or run_on == "dp":
        result = connector_instance._block_ip(cidr_ip, egress)
    else:
        result = connector_instance._run_action_on_ds("block_ip", cidr_ip, egress, run_on)
    if result != SUCCESS:
        raise Exception(result)
    return {"result_msg": result}

def unblock_ip_wrapper(connector_instance, cidr, direction, block_subnet=True, **kwargs):
    # Wrapper that's compatible with the custom response framework
    cidr_ip = cidr
    if block_subnet:
        if isinstance(cidr, list):
            cidr_ip = []
            for item in cidr:
                cidr_ip.append("{}/32".format(item))
        else:
            cidr_ip = "{}/32".format(cidr)

    if direction == "dst":
        egress = True
    else:
        egress = False
    run_on = kwargs.get("run_on", "dp")
    if run_on == "" or run_on == "dp":
        result = connector_instance._unblock_ip(cidr_ip, egress)
    else:
        result = connector_instance._run_action_on_ds("unblock_ip", cidr_ip, egress, run_on)
    if result != SUCCESS:
        raise Exception(result)
    return {"result_msg": result}
