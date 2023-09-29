#!/usr/bin/env python

from flask import Flask, request, make_response, jsonify
import logging
from logging.handlers import WatchedFileHandler
import pymongo
from pymongo import MongoClient
import time

import utils

app = Flask("custom_response_rest")
app.config["JSONIFY_PRETTYPRINT_REGULAR"] = False

### Logging ###
logging.basicConfig(level=logging.DEBUG)
FORMAT = "%(asctime)-15s|%(levelname)s|%(thread)d|%(threadName)s|%(module)s|%(lineno)d|%(message)s"
formatter = logging.Formatter(FORMAT)
handler = WatchedFileHandler(utils.LOG_FILE)
handler.setFormatter(formatter)
handler.setLevel(logging.DEBUG)
app.logger.addHandler(handler)

app.logger.info("Initializing custom response server")

app.logger.info("Loading module configuration")
if not utils.update_module_map():
    app.logger.error("Failed to initialize module map from config")
else:
    app.logger.info("Module map updated")

app.logger.info("Connecting to MongoDB")
mongo_db_connected = False
while not mongo_db_connected:
    try:
        db_client = MongoClient(utils.MONGODB_URL)
        mongo_db_connected = True
    except pymongo.errors.ConnectionFailure, e:
        app.logger.error("Failed to connect to MongoDB: {}, {}".format(
            utils.MONGODB_URL, str(e)))
        time.sleep(5)

custom_response_table = db_client[utils.DB_NAME][
        utils.CUSTOM_RESPONSE_TABLE_NAME]
try:
    custom_response_table.drop_index("cust_id_1_name_1")
except:
    pass
custom_response_table.create_index([("name", pymongo.ASCENDING),
    ("category", pymongo.ASCENDING)], unique=True)

custom_response_action_table = db_client[utils.DB_NAME][
        utils.CUSTOM_RESPONSE_ACTION_TABLE_NAME]
try:
    old_index = "cust_id_1_component_name_1_action_name_1_unique_key_1"
    if old_index in custom_response_action_table.index_information():
        custom_response_action_table.drop_index(old_index)
except Exception as e:
    app.logger.error("Failed to drop old index: {}".format(str(e)))
custom_response_action_table.create_index([("cust_id", pymongo.ASCENDING),
    ("component_name", pymongo.ASCENDING), ("action_name", pymongo.ASCENDING),
    ("unique_key", pymongo.ASCENDING), ("timestamp", pymongo.ASCENDING)],
    unique=True)

app.logger.info("Connected to MongoDB")

@app.route("/api/1.0/load_modules", methods=["POST"])
def Load_modules():
    if not utils.update_module_map():
        return make_response("Could not load modules from config\n", 500)
    return make_response("Modules loaded\n", 200)

@app.route("/api/1.0/remote_sync_config", methods=["POST"])
def Remote_sync_config():
    if not utils.download_and_install_module_files():
        return make_response("Could not download module files from remote\n", 500)
    return make_response("Module files synced\n", 200)

@app.route("/api/1.0/custom_response", methods=["POST"])
def Custom_response_create():
    json_obj = request.json
    app.logger.debug("Post custom response request: {}".format(json_obj))

    is_valid, response = validate_json_input(json_obj)
    if not is_valid:
        return response

    reply = custom_response_create(json_obj)
    app.logger.debug("Post custom response reply: {}".format(reply.response))
    return reply

@app.route("/api/1.0/custom_response/<category>/<name>", methods=["PUT"])
def Custom_response_modify(**kwargs):
    json_obj = request.json
    app.logger.debug("Put custom response request: {}".format(json_obj))
    name = kwargs.get("name", None)
    category = kwargs.get("category", None)
    if name is None:
        return make_response(jsonify({"Missing fields": "name"}), 400)
    if category is None:
        return make_response(jsonify({"Missing fields": "category"}), 400)

    is_valid, response = validate_json_input(json_obj)
    if not is_valid:
        return response

    reply = custom_response_modify(name, category, json_obj)
    app.logger.debug("Put custom response reply: {}".format(reply.response))
    return reply

@app.route("/api/1.0/custom_response/<category>/<name>", methods=["DELETE"])
def Custom_response_delete(**kwargs):
    is_valid, response = validate_json_input(request.args)
    if not is_valid:
        return response
    cust_id = request.args.get("cust_id")

    name = kwargs.get("name", None)
    category = kwargs.get("category", None)
    if name is None:
        return make_response(jsonify({"Missing fields": "name"}), 400)
    if category is None:
        return make_response(jsonify({"Missing fields": "category"}), 400)

    app.logger.debug("Delete custom response request: {}".format(name))
    reply = custom_response_delete(name, category, cust_id)
    app.logger.debug("Delete custom response reply: {}".format(reply.response))
    return reply

@app.route("/api/1.0/custom_response", methods=["GET"])
def Custom_response_get_all():
    is_valid, response = validate_json_input(request.args)
    if not is_valid:
        return response
    cust_id = request.args.get("cust_id")
    category = request.args.get("category")
    subtype = request.args.get("type")

    app.logger.debug("Get all custom response request: {}".format(request.args))
    row_obj = {}
    if category is not None:
        row_obj["category"] = category
    if subtype is not None:
        row_obj["type"] = subtype
    reply = get_all_data_by_json_obj(custom_response_table,
            row_obj, cust_id=cust_id)
    app.logger.debug("Get all custom response reply: {}".format(reply.response))
    return reply

@app.route("/api/1.0/custom_response/<category>/<name>", methods=["GET"])
def Custom_response_get(**kwargs):
    is_valid, response = validate_json_input(request.args)
    if not is_valid:
        return response
    cust_id = request.args.get("cust_id")

    name = kwargs.get("name", None)
    category = kwargs.get("category", None)
    if name is None:
        return make_response(jsonify({"Missing fields": "name"}), 400)
    if category is None:
        return make_response(jsonify({"Missing fields": "category"}), 400)
    row_obj = {"name": name, "category": category, "cust_id": cust_id}

    app.logger.debug("Get custom response request: {} {}".format(name, request.args))
    reply = get_data_by_json_obj(custom_response_table, row_obj)
    app.logger.debug("Get custom response reply: {}".format(reply.response))
    return reply

@app.route("/api/1.0/custom_response/<category>/<name>/connection_test", methods=["GET"])
def Custom_response_connection_test(**kwargs):
    is_valid, response = validate_json_input(request.args)
    if not is_valid:
        return response
    cust_id = request.args.get("cust_id")

    run_on = request.args.get("run_on", "dp")

    name = kwargs.get("name", None)
    category = kwargs.get("category", None)
    if name is None:
        return make_response(jsonify({"Missing fields": "name"}), 400)
    if category is None:
        return make_response(jsonify({"Missing fields": "category"}), 400)

    app.logger.debug("Connection test request: {}".format(name))
    reply = custom_response_connection_test(name, category, cust_id, run_on)
    app.logger.debug("Connection test reply: {}".format(reply.response))
    return reply

@app.route("/api/1.0/custom_response/connector/connector_test", methods=["POST"])
def Custom_response_connector_test():
    json_obj = request.json
    app.logger.debug("Post connector test request: {}".format(json_obj))

    is_valid, response = validate_json_input(json_obj)
    if not is_valid:
        return response

    run_on = json_obj.get("run_on", "dp")
    name = json_obj.get("name", None)
    if name is None:
        return make_response(jsonify({"Missing fields": "name"}), 400)

    app.logger.debug("Connector test request: {}".format(name))
    reply = custom_response_connector_test(json_obj, name, run_on)
    app.logger.debug("Connector test reply: {}".format(reply.response))
    return reply

@app.route("/api/1.0/playbook_action", methods=["POST"])
def Playbook_action_create():
    json_obj = request.json
    app.logger.debug("Post playbook action request, json_obj keys: {}".format(json_obj.keys()))

    is_valid, response = validate_action_request(json_obj)
    if not is_valid:
        return response

    reply = playbook_action_create(json_obj)
    app.logger.debug("Post playbook action reply: {}".format(reply.response))
    return reply

@app.route("/api/1.0/custom_response_action", methods=["POST"])
def Custom_response_action_create():
    json_obj = request.json
    app.logger.debug("Post custom response action request: {}".format(json_obj))

    is_valid, response = validate_action_request(json_obj)
    if not is_valid:
        return response

    reply = custom_response_action_create(json_obj)
    app.logger.debug("Post custom response action reply: {}".format(reply.response))
    return reply

@app.route("/api/1.0/custom_response_action", methods=["PUT"])
def Custom_response_action_modify():
    json_obj = request.json
    app.logger.debug("Put custom response action request: {}".format(json_obj))

    is_valid, response = validate_action_put_delete_request(json_obj)
    if not is_valid:
        return response

    reply = custom_response_action_modify(json_obj)
    app.logger.debug("Put custom response action reply: {}".format(reply.response))
    return reply

@app.route("/api/1.0/custom_response_action_revert", methods=["PUT"])
def Custom_response_action_revert():
    json_obj = request.json
    app.logger.debug("Put revert custom response action request: {}".format(json_obj))

    is_valid, response = validate_action_put_delete_request(json_obj)
    if not is_valid:
        return response

    reply = custom_response_action_revert(json_obj)
    app.logger.debug("Put revert custom response action reply: {}".format(reply.response))
    return reply

@app.route("/api/1.0/custom_response_action", methods=["DELETE"])
def Custom_response_action_delete(**kwargs):
    app.logger.debug("Delete custom response action request: {}".format(request.json))
    is_valid, response = validate_action_put_delete_request(request.json)
    if not is_valid:
        return response

    reply = custom_response_action_delete(request.json)
    app.logger.debug("Delete custom response action reply: {}".format(reply.response))
    return reply

@app.route("/api/1.0/custom_response_action/<action>", methods=["GET"])
def Custom_response_action_get_all(**kwargs):
    is_valid, response = validate_json_input(request.args)
    if not is_valid:
        return response

    app.logger.debug("Get all custom response action request: {}".format(request.args))
    cust_id = request.args.get("cust_id")
    cust_id = process_cust_id_csv(cust_id)
    action_name = kwargs.get("action", None)
    if action_name is None or action_name == "all":
        actions = "all"
    else:
        actions = action_name.split(",")
    size = request.args.get("size", None)
    start = request.args.get("from", None)
    end = request.args.get("to", None)
    if size is not None and size.isdigit():
        size = int(size)
        sort = [("timestamp", pymongo.DESCENDING)]
    else:
        size = 0
        sort = []

    conditions = []
    if actions != "all":
        conditions.append({"action_name": {"$in": actions}})
    timestamp_obj = {}
    if start is not None:
        try:
            start = int(start)/1000
            timestamp_obj["$gte"] = str(start)
        except:
            pass
    if end is not None:
        try:
            end = int(end)/1000
            timestamp_obj["$lte"] = str(end)
        except:
            pass
    if timestamp_obj:
        conditions.append({"timestamp": timestamp_obj})

    if conditions:
        row_obj = {"$and": conditions}
    else:
        row_obj = {}

    reply = get_all_data_by_json_obj(
            custom_response_action_table, row_obj, cust_id=cust_id,
            sort=sort, size=size)
    app.logger.debug("Get all custom response action reply: {}".format(reply.response))
    return reply

@app.route("/api/1.0/custom_response_action/getone/<component>", methods=["GET"])
def Custom_response_action_get(**kwargs):
    is_valid, response = validate_json_input(request.args)
    if not is_valid:
        return response

    timestamp = request.args.get("timestamp")
    action_name = request.args.get("action_name")
    cust_id = request.args.get("cust_id")
    cust_id = process_cust_id_csv(cust_id)
    component_name = kwargs.get("component", None)
    if not component_name:
        return make_response(jsonify({"Missing fields": "component"}), 400)

    row_obj = {"component_name": component_name, "cust_id": cust_id}
    if timestamp:
        row_obj["timestamp"] = timestamp
    if action_name:
        row_obj["action_name"] = action_name
    for key in request.args:
        if key == "cust_id" or key == "timestamp" or key == "action_name":
            continue
        row_obj["unique_key.{}".format(key)] = request.args.get(key)

    app.logger.debug("Get one {} custom response action request: {}".format(
        component_name, row_obj))
    reply = get_data_by_json_obj(custom_response_action_table, row_obj)
    app.logger.debug("Get one {} custom response action reply: {}".format(
        component_name, reply.response))
    return reply

### Rest API ###
def custom_response_create(json_obj):
    missing_fields = []
    cust_id = json_obj.get("cust_id", None)
    name = json_obj.get("name", None)
    category = json_obj.get("category", None)
    module_name = json_obj.get("type", None)
    extra_conf = json_obj.get("conf", None)
    run_on = json_obj.get("run_on", "dp")

    if name is None:
        missing_fields.append("name")
    if category is None:
        missing_fields.append("category")
    if module_name is None:
        missing_fields.append("type")
    if extra_conf is None:
        missing_fields.append("conf")

    if len(missing_fields) > 0:
        app.logger.debug("Missing fields {}".format(missing_fields))
        return make_response(jsonify({"Missing fields": missing_fields}), 400)

    row_data = {"cust_id": cust_id, "name": name, "category": category,
            "type": module_name, "conf": extra_conf, "run_on": run_on}

    try:
        insert_res = custom_response_table.insert_one(row_data)
    except pymongo.errors.DuplicateKeyError:
        return make_response(utils.DUPLICATE_ENTRY_MSG, 400)
    except:
        return make_response(utils.DEFAULT_MONGO_ERROR_MSG, 400)

    return get_data_by_key(custom_response_table, "name", name, cust_id=cust_id)

def custom_response_modify(name, category, json_obj):
    cust_id = json_obj.get("cust_id", None)
    get_res = custom_response_table.find_one({"name": name,
        "category": category, "cust_id": cust_id})
    if get_res is None:
        return make_response(utils.NOT_FOUND_MSG, 400)

    category = get_res.get("category")
    module_name = get_res.get("type")
    extra_conf = get_res.get("conf")
    row_data = {}
    if json_obj.get("name") != name:
        return make_response("name field cannot be changed\n", 400)
    if json_obj.get("category") != category:
        return make_response("category field cannot be changed\n", 400)
    if json_obj.get("type") != module_name:
        return make_response("type field cannot be changed\n", 400)
    if json_obj.get("conf") is not None:
        new_extra_conf = json_obj.get("conf")
        if new_extra_conf != extra_conf:
            row_data["conf"] = new_extra_conf
    run_on = json_obj.get("run_on", None)
    if run_on is not None:
        row_data["run_on"] = run_on
    if len(row_data) == 0:
        return get_data_by_key(custom_response_table, "name", name, cust_id=cust_id)

    try:
        update_res = custom_response_table.update_one({"name":name,
            "cust_id":cust_id}, {"$set": row_data}, upsert=False)
    except:
        return make_response(utils.DEFAULT_MONGO_ERROR_MSG, 400)
    return get_data_by_key(custom_response_table, "name", name, cust_id=cust_id)

def custom_response_delete(name, category, cust_id):
    get_res = custom_response_table.find_one({"name": name,
        "category": category, "cust_id": cust_id})
    if get_res is None:
        return make_response(utils.NOT_FOUND_MSG, 400)

    try:
        delete_res = custom_response_table.delete_one({"name": name,
            "category": category, "cust_id": cust_id})
    except:
        return make_response(utils.DEFAULT_MONGO_ERROR_MSG, 400)

    return make_response(utils.OK_MSG, 200)

def custom_response_connection_test(name, category, cust_id, run_on):
    component_config = custom_response_table.find_one({"name": name,
        "category": category, "cust_id": cust_id})
    return custom_response_connector_test(component_config, name, run_on)

def custom_response_connector_test(component_config, name, run_on):
    if component_config is None:
        return make_response(utils.NOT_FOUND_MSG, 400)

    try:
        connection_test_name = utils.get_connection_test_name(component_config)
        if not connection_test_name:
            return make_response("Missing connector test function\n", 400)

        test_params = {"run_on": run_on, "name": name}

        try:
            result = getattr(utils.get_module_instance(component_config, logger=app.logger),
                connection_test_name)(**test_params)
            if result:
                return make_response("{}\n".format(result), 200)
            else:
                return make_response("{}\n".format(result), 400)
        except:
            return make_response("{}\n".format(result), 400)
    except Exception as e:
        app.logger.error("Connector test exception for {}: {}".format(
            name, str(e)))
        return make_response(utils.DEFAULT_EXCEPTION_MSG + ":" +str(e), 400)

def playbook_action_create(json_obj):
    cust_id = json_obj.get("cust_id")
    component_name = json_obj.get("component_name")
    component_category = json_obj.get("component_category")
    # Add component config to api call due to race condition between ovsdb syncs
    backup_component_config = json_obj.get("component_config")
    action_name = json_obj.get("action_name")
    action_settings = json_obj.get("settings", None)
    context = json_obj.get("context", {})
    duration = json_obj.get("duration", "")
    revert_action_name = ""

    component_config = custom_response_table.find_one({
        "name": component_name, "category": component_category,
        "cust_id": cust_id})
    if not component_config:
        if not backup_component_config:
            return make_response(
                "Response object {} does not exist. Please specify component config\n".format(component_name), 400)
        component_config = backup_component_config
    if duration != "":
        revert_action_name = utils.get_inverse_action(
                action_name, component_config)

    try:
        action_params = utils.get_action_params(component_config,
                action_name, action_settings, context)
    except Exception as e:
        app.logger.error("Couldn't get action params for {}.{}: {}".format(
            component_name, action_name, str(e)))
        return make_response("Response object {} returned an error during " \
                "preparation".format(component_name), 400)
    try:
        unique_keys = utils.get_many_unique_keys(component_config,
                action_name, action_params)
    except Exception as e:
        app.logger.error("Couldn't get unique keys from action params for " \
                "{}.{}: {}".format(component_name, action_name, str(e)))
        return make_response("Response object {} returned a key error".format(
            component_name), 400)

    num_success = 0
    num_fail = 0
    num_noop = 0
    for i in range(len(action_params)):
        curr_action_params = action_params[i]
        curr_unique_keys = unique_keys[i]
        row_data = {"component_name": component_name, "action_name": action_name,
                "cust_id": cust_id, "unique_key": curr_unique_keys,
                "status": {"$in": utils.PENDING_STATES}}

        get_res = custom_response_action_table.find_one(row_data)
        if get_res:
            num_noop += 1
            continue

        row_data["component_category"] = component_category
        row_data["status"] = utils.WAITING
        row_data["timestamp"] = str(int(time.time()))
        row_data["revert_action_name"] = revert_action_name
        row_data["duration"] = duration
        row_data["params"] = curr_action_params

        try:
            insert_res = custom_response_action_table.insert_one(row_data)
            num_success += 1
        except pymongo.errors.DuplicateKeyError:
            num_noop += 1
        except:
            num_fail += 1
    result = {"success": num_success, "fail": num_fail,
            "noop": num_noop, "total": len(action_params)}
    return make_response(jsonify(result), 200)

def custom_response_action_create(json_obj):
    cust_id = json_obj.get("cust_id")
    component_name = json_obj.get("component_name")
    component_category = json_obj.get("component_category")
    # Add component config to api call due to race condition between ovsdb syncs
    backup_component_config = json_obj.get("component_config")
    action_name = json_obj.get("action_name")
    action_params = json_obj.get("action_params", {})
    duration = json_obj.get("duration", "")
    revert_action_name = ""
    force = json_obj.get("force", False)

    component_config = custom_response_table.find_one({
        "name": component_name, "category": component_category,
        "cust_id": cust_id})
    if not component_config:
        if not backup_component_config:
            return make_response("Response object {} does not exist. Please specify component config\n".format(
                component_name), 400)
        component_config = backup_component_config
    run_on = component_config.get("run_on", "")
    revert_action_name = utils.get_inverse_action(
            action_name, component_config)
    action_query = {"$in": [action_name, revert_action_name]}

    try:
        key_list = utils.get_unique_key_list_from_config(
                component_config, action_name)
        unique_keys = utils.get_unique_keys(key_list, action_params)
    except Exception as e:
        app.logger.error("Couldn't get unique keys from action params for" \
                "{}.{}: {}".format(component_name, action_name, str(e)))
        return make_response("Response object {} returned a key error".format(
            component_name), 400)

    row_data = {"component_name": component_name, "action_name": action_query,
            "cust_id": cust_id, "unique_key": unique_keys,
            "status": {"$in": utils.PENDING_STATES}}

    get_res = custom_response_action_table.find_one(row_data)
    if get_res:
        return make_response("An identical action is still pending (status: {})\n".format(
            get_res.get("status")), 400)

    row_data["component_category"] = component_category
    row_data["status"] = utils.WAITING
    row_data["timestamp"] = str(int(time.time()))

    action_params["component_name"] = component_name
    action_params["run_on"] = run_on

    row_data["action_name"] = action_name
    row_data["revert_action_name"] = revert_action_name
    row_data["duration"] = duration
    row_data["params"] = action_params

    try:
        insert_res = custom_response_action_table.insert_one(row_data)
    except pymongo.errors.DuplicateKeyError:
        return make_response(utils.DUPLICATE_ENTRY_MSG, 400)
    except:
        return make_response(utils.DEFAULT_MONGO_ERROR_MSG, 400)

    return get_data_by_json_obj(custom_response_action_table, {
        "component_name": component_name, "action_name": action_name,
        "unique_key": unique_keys, "cust_id": cust_id, "timestamp": row_data["timestamp"]})

def custom_response_action_modify(json_obj):
    cust_id = json_obj.get("cust_id")
    timestamp = json_obj.get("timestamp")
    component_name = json_obj.get("component_name")
    category = json_obj.get("category")
    action_name = json_obj.get("action_name")
    unique_key = json_obj.get("unique_key")
    duration = json_obj.get("duration", "")
    revert_action_name = ""

    component_config = custom_response_table.find_one({
        "name": component_name, "category": category, "cust_id": cust_id})
    if not component_config:
        return make_response("Response object {} does not exist\n".format(
            component_name), 400)
    revert_action_name = utils.get_inverse_action(
            action_name, component_config)
    action_query = {"$in": [action_name, revert_action_name]}

    search_row_data = {"component_name": component_name, "action_name": action_query,
            "cust_id": cust_id, "unique_key": unique_key, "timestamp": timestamp}

    get_res = custom_response_action_table.find_one(search_row_data)
    if not get_res:
        return make_response(utils.NOT_FOUND_MSG, 400)

    existing_action = get_res.get("action_name")
    existing_status = get_res.get("status")

    if action_name == existing_action and existing_status not in utils.DONE_STATES:
        return make_response("Action is already pending\n", 400)

    new_row_data = {}
    if action_name != existing_action:
        get_res.pop("_id", None)
        new_row_data = get_res
        custom_response_action_table.delete_one(get_res)
    new_row_data.update({"action_name": action_name, "duration": duration,
            "component_category": category,
            "revert_action_name": revert_action_name})
    update_action_row_data(new_row_data, json_obj)

    try:
        new_row_data.pop("error_msg", None)
        update_res = custom_response_action_table.update_one(search_row_data,
                {"$set": new_row_data, "$unset": {"error_msg": ""}}, upsert=True)
    except:
        return make_response(utils.DEFAULT_MONGO_ERROR_MSG, 400)

    return get_data_by_json_obj(custom_response_action_table, search_row_data)

def custom_response_action_revert(json_obj):
    cust_id = json_obj.get("cust_id")
    timestamp = json_obj.get("timestamp")
    component_name = json_obj.get("component_name")
    category = json_obj.get("component_category")
    action_name = json_obj.get("action_name")
    unique_key = json_obj.get("unique_key")
    action_params = json_obj.get("params")

    component_config = custom_response_table.find_one({
        "name": component_name, "category": category, "cust_id": cust_id})
    if not component_config:
        return make_response("Response object {} does not exist\n".format(
            component_name), 400)
    revert_action_name = utils.get_inverse_action(
            action_name, component_config)
    if not revert_action_name:
        return make_response("Action type cannot be reverted\n", 400)

    row_data = {"component_name": component_name, "action_name": action_name,
            "cust_id": cust_id, "unique_key": unique_key, "timestamp": timestamp}
    get_res = custom_response_action_table.find_one(row_data)
    if not get_res:
        return make_response(utils.NOT_FOUND_MSG, 400)
    if get_res.get("status") == utils.REVERTED:
        return make_response("Action has already been reverted\n", 400)
    elif get_res.get("status") in utils.PENDING_STATES:
        return make_response("Please wait until the action has completed before reverting\n", 400)
    elif get_res.get("status") == utils.EXPIRED:
        return make_response("Cannot revert an action that has already expired\n", 400)
    elif get_res.get("status") == utils.FAILURE:
        return make_response("Cannot revert a failed action\n", 400)
    new_row_data = {"cust_id": cust_id, "component_name": component_name,
            "component_category": category, "action_name": revert_action_name,
            "action_params": action_params}
    custom_response_action_table.update_one(row_data, {"$set": {"status": utils.REVERTED}})
    return custom_response_action_create(new_row_data)

def custom_response_action_delete(json_obj):
    cust_id = json_obj.get("cust_id")
    timestamp = json_obj.get("timestamp")
    component_name = json_obj.get("component_name")
    category = json_obj.get("category")
    action_name = json_obj.get("action_name")
    unique_key = json_obj.get("unique_key")
    search_obj = {"cust_id": cust_id, "component_name": component_name,
            "action_name": action_name, "unique_key": unique_key,
            "timestamp": timestamp}
    get_res = custom_response_action_table.find_one(search_obj)
    if get_res is None:
        component_config = custom_response_table.find_one(
                {"name": component_name, "category": category, "cust_id": cust_id})
        if component_config is None:
            return make_response(utils.NOT_FOUND_MSG, 400)
        inverse_action = utils.get_inverse_action(action_name, component_config)
        search_obj["action_name"] = inverse_action
        get_res = custom_response_action_table.find_one(search_obj)
        if get_res is None:
            return make_response(utils.NOT_FOUND_MSG, 400)

    try:
        get_res.pop("_id", None)
        delete_res = custom_response_action_table.delete_one(get_res)
    except:
        return make_response(utils.DEFAULT_MONGO_ERROR_MSG, 400)

    return make_response(utils.OK_MSG, 200)

def get_data_by_key(table, key, val, cust_id=None):
    assert key is not None and val is not None
    if cust_id == "all" or cust_id is None:
        result = list(table.find({key: val}))
    else:
        result = list(table.find({key: val, "cust_id": cust_id}))

    if len(result) == 0:
        return make_response(utils.NOT_FOUND_MSG, 400)
    if len(result) > 1:
        return make_response(utils.MULTIPLE_FOUND_MSG, 400)

    item = result[0]
    item.pop("_id", None)
    return make_response(jsonify(item), 200)

def get_data_by_json_obj(table, json_obj):
    cust_id = json_obj.get("cust_id")
    if cust_id is not None:
        if cust_id == "all":
            json_obj.pop("cust_id")
        elif type(cust_id) is list:
            json_obj["cust_id"] = {"$in": cust_id}
    result = list(table.find(json_obj))
    if len(result) == 0:
        return make_response(utils.NOT_FOUND_MSG, 400)
    if len(result) > 1:
        return make_response(utils.MULTIPLE_FOUND_MSG, 400)

    item = result[0]
    item.pop("_id", None)
    return make_response(jsonify(item), 200)

def get_all_data(table, cust_id=None, sort=[], size=0):
    if cust_id == "all" or cust_id is None:
        result = list(table.find(sort=sort, limit=size))
    elif type(cust_id) is list:
        result = list(table.find({"cust_id": {"$in": cust_id}}, sort=sort, limit=size))
    else:
        result = list(table.find({"cust_id": cust_id}, sort=sort, limit=size))

    for item in result:
        item.pop("_id", None)
    return make_response(jsonify(result), 200)

def get_all_data_by_json_obj(table, json_obj, cust_id=None, sort=[], size=0):
    if type(cust_id) is list:
        json_obj["cust_id"] = {"$in": cust_id}
    elif cust_id != "all" and cust_id != None:
        json_obj["cust_id"] = cust_id
    result = list(table.find(json_obj, sort=sort, limit=size))

    for item in result:
        item.pop("_id", None)
    return make_response(jsonify(result), 200)

### Misc ###
def process_cust_id_csv(cust_id_csv):
    if cust_id_csv == "all":
        return cust_id_csv
    cust_id_list = cust_id_csv.split(",")
    if len(cust_id_list) == 1:
        return cust_id_list[0]
    return cust_id_list

def update_action_row_data(target, src):
    if "status" not in src:
        target["status"] = utils.WAITING
    else:
        target["status"] = src["status"]
    if "timestamp" not in src:
        target["timestamp"] = str(int(time.time()))
    else:
        target["timestamp"] = src["timestamp"]
    if "execution_start" in src:
        target["execution_start"] = src["execution_start"]
    if "execution_end" in src:
        target["execution_end"] = src["execution_end"]

def validate_json_input(json_obj):
    if json_obj is None:
        return False, make_response(utils.MISSING_JSON_DATA_MSG, 400)

    if json_obj.get("cust_id", None) is None:
        return False, make_response(jsonify({"Missing fields": "cust_id"}), 400)
    return True, None

def validate_action_request(json_obj):
    if json_obj is None:
        return False, make_response(utils.MISSING_JSON_DATA_MSG, 400)

    missing_fields = []
    if json_obj.get("cust_id", None) is None:
        missing_fields.append("cust_id")
    if json_obj.get("component_name", None) is None:
        missing_fields.append("component_name")
    if json_obj.get("action_name", None) is None:
        missing_fields.append("action_name")
    if json_obj.get("component_category", None) is None:
        missing_fields.append("component_category")
    if len(missing_fields) > 0:
        return False, make_response(jsonify({"Missing fields": missing_fields}), 400)
    return True, None

def validate_action_put_delete_request(json_obj):
    if json_obj is None:
        return False, make_response(utils.MISSING_JSON_DATA_MSG, 400)

    missing_fields = []
    if json_obj.get("cust_id", None) is None:
        missing_fields.append("cust_id")
    if json_obj.get("component_name", None) is None:
        missing_fields.append("component_name")
    if json_obj.get("action_name", None) is None:
        missing_fields.append("action_name")
    if json_obj.get("unique_key", None) is None:
        missing_fields.append("unique_key")
    if json_obj.get("timestamp", None) is None:
        missing_fields.append("timestamp")
    if len(missing_fields) > 0:
        return False, make_response(jsonify({"Missing fields": missing_fields}), 400)
    return True, None

if __name__ == "__main__":
    app.run(host="0.0.0.0")
