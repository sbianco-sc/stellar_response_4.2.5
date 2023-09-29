#!/usr/bin/env python

from multiprocessing import Pool, TimeoutError
import os
import pymongo
from pymongo import MongoClient
import signal
import time

import utils

component_map = {}

def execute_all_actions():
    try:
        update_component_map()
        execute_waiting_actions()
        execute_waiting_batched_actions()
        revert_expired_actions()
        revert_expired_batched_actions()
    except Exception as e:
        logger.error("Failed to execute actions: {}".format(str(e)))

def update_component_map():
    global component_map
    for connector in custom_response_table.find():
        name = connector.get("name")
        category = connector.get("category")
        if not name or not category:
            continue
        component_map[(name, category)] = connector

def enrich_action(action, revert, batch_id):
    component_name = action.get("component_name")
    category = action.get("component_category")
    action["component_config"] = {}
    if (component_name, category) in component_map:
        try:
            update_obj = {}
            action["component_config"] = component_map[(component_name, category)]
            if revert and not is_expired(action):
                return action
            update_obj = update_action_start_in_db(
                    action, run_on=action["component_config"].get("run_on", ""),
                    revert=revert, batch_id=batch_id, update_obj=update_obj)
            if batch_id:
                update_bulk_action_by_json_obj(action, update_obj, batch_id)
            else:
                update_action_by_json_obj(action, update_obj)
        except Exception as e:
            logger.error("Failed to start action {}: {}".format(action, str(e)))
    return action

def update_pool_res_to_db(res):
    while True:
        try:
            curr = res.next(0.05)
            if not curr:
                continue
            action, update_obj, batch_id = curr
            if batch_id:
                update_bulk_action_by_json_obj(action, update_obj, batch_id)
            else:
                update_action_by_json_obj(action, update_obj)
        except StopIteration:
            break
        except TimeoutError:
            continue

def execute_waiting_actions():
    waiting_action_cursor = custom_response_action_table.find(
            {"status": utils.WAITING, "params.batch_id": {"$exists": False}})
    waiting_action_cursor = map(lambda action: enrich_action(action, False, None), waiting_action_cursor)
    res = pool.imap(execute_single_action, waiting_action_cursor)
    update_pool_res_to_db(res)

def execute_waiting_batched_actions():
    batches = {}
    actions = []
    waiting_batched_action_cursor = custom_response_action_table.find(
            {"status": utils.WAITING, "params.batch_id": {"$exists": True}})
    for action in waiting_batched_action_cursor:
        batch_id = action["params"]["batch_id"]
        if batch_id not in batches:
            batches[batch_id] = action
            batches[batch_id]["params"] = [batches[batch_id]["params"]]
        else:
            batches[batch_id]["params"].append(action["params"])
    for batch_id in batches:
        actions.append(batches[batch_id])
    actions = map(lambda action: enrich_action(action, False, get_batch_id_from_action(action)), actions)
    res = pool.imap(execute_single_bulk_action, actions)
    update_pool_res_to_db(res)

def revert_expired_actions():
    potential_expired_action_cursor = custom_response_action_table.find({
        "status": utils.SUCCESS, "duration": {"$exists": "true", "$ne": ""},
        "params.batch_id": {"$exists": False}})
    potential_expired_action_cursor = map(lambda action: enrich_action(action, True, None), potential_expired_action_cursor)
    res = pool.imap(revert_single_action_if_expired,
            potential_expired_action_cursor)
    update_pool_res_to_db(res)

def revert_expired_batched_actions():
    batches = {}
    actions = []
    potential_expired_batched_action_cursor = custom_response_action_table.find({
        "status": utils.SUCCESS, "duration": {"$exists": "true", "$ne": ""},
        "params.batch_id": {"$exists": True}})
    for action in potential_expired_batched_action_cursor:
        batch_id = action["params"]["batch_id"]
        if batch_id not in batches:
            batches[batch_id] = action
            batches[batch_id]["params"] = [batches[batch_id]["params"]]
        else:
            batches[batch_id]["params"].append(action["params"])
    for batch_id in batches:
        actions.append(batches[batch_id])
    actions = map(lambda action: enrich_action(action, True, get_batch_id_from_action(action)), actions)
    res = pool.imap(revert_single_bulk_action_if_expired, actions)
    update_pool_res_to_db(res)

def revert_single_action_if_expired(action):
    if is_expired(action):
        return execute_single_action(action, revert=True)

def revert_single_bulk_action_if_expired(action):
    if is_expired(action):
        batch_id = get_batch_id_from_action(action)
        return execute_single_action(action, revert=True, batch_id=batch_id)

def execute_single_bulk_action(action):
    batch_id = get_batch_id_from_action(action)
    return execute_single_action(action, batch_id=batch_id)

def get_batch_id_from_action(action):
    if type(action["params"]) is list:
        return action["params"][0]["batch_id"]
    return action["params"]["batch_id"]

def execute_single_action(action, revert=False, batch_id=None):
    update_obj = {}
    description = "bulk action" if batch_id else "action"
    if revert:
        logger.info("Reverting {}: {}".format(description, action))
    else:
        logger.info("Executing {}: {}".format(description, action))
    component_name = action.get("component_name")
    category = action.get("component_category")
    component_config = action.pop("component_config", None)
    if not component_config:
        logger.error("Could not find {} component {}. Skipping action {}".format(
            category, component_name, action))
        update_action_fail_in_db(
                action, batch_id=batch_id, update_obj=update_obj,
                err_msg="Could not find component config")
        return action, update_obj, batch_id
    run_on = component_config.get("run_on", "")
    utils.update_module_map(module=component_config.get("type"))

    try:
        update_action_start_in_db(
                action, run_on=run_on, revert=revert,
                batch_id=batch_id, update_obj=update_obj)
    except Exception as e:
        logger.error("Action {} start failed to update in db: {}".format(
            action, str(e)))
        update_action_fail_in_db(
                action, batch_id=batch_id, update_obj=update_obj,
                err_msg="Updating DB with action start failed")
        return action, update_obj, batch_id

    try:
        module_instance = utils.get_module_instance(
                component_config, logger=logger)
    except Exception as e:
        logger.error("Module initialization failed: {}".format(str(e)))
        update_action_fail_in_db(
                action, batch_id=batch_id, update_obj=update_obj,
                err_msg="Module initialization failed")
        return action, update_obj, batch_id

    try:
        if batch_id:
            preprocess_batch_params(module_instance, action)
        result_params = call_action_function(
                module_instance, action, run_on, revert=revert)
    except Exception as e:
        logger.error("Action {} execution failed: {}".format(
            action, str(e)))
        update_action_fail_in_db(
                action, update_obj=update_obj,
                err_msg=str(e), batch_id=batch_id)
        return action, update_obj, batch_id

    if not is_result_valid(result_params):
        logger.error("Action {} returned invalid results: {}".format(
            action, result_params))
        update_action_fail_in_db(
                action, batch_id=batch_id, update_obj=update_obj,
                err_msg="Invalid results returned")
        return action, update_obj, batch_id

    try:
        update_action_end_in_db(
                action, result_params, revert=revert,
                batch_id=batch_id, update_obj=update_obj)
        return action, update_obj, batch_id
    except Exception as e:
        logger.error("Action {} end failed to update in db: {}".format(
            action, str(e)))
        update_action_fail_in_db(
                action, batch_id=batch_id, update_obj=update_obj,
                err_msg="Updating DB with action end failed")
        return action, update_obj, batch_id

def update_action_start_in_db(action, run_on="dp", revert=False, batch_id=None, update_obj=None):
    if update_obj is None:
        update_obj = {}
    if revert:
        update_obj["status"] = utils.EXPIRING
    else:
        update_obj["status"] = utils.IN_PROGRESS
        update_obj["execution_start"] = str(int(time.time()))
        action_params = action.get("params", {})
        if "run_on" not in action_params:
            update_obj["params.run_on"] = run_on
    return update_obj

def update_action_end_in_db(action, result, revert=False, batch_id=None, update_obj=None):
    if update_obj is None:
        update_obj = {}
    if revert:
        update_obj["status"] = utils.EXPIRED
    else:
        update_obj["status"] = utils.SUCCESS
        update_obj["error_msg"] = ""
        update_obj["execution_end"] = str(int(time.time()))
    update_obj.update(result)
    return update_obj

def update_action_fail_in_db(action, err_msg=None, batch_id=None, update_obj=None):
    try:
        if update_obj is None:
            update_obj = {}
        update_obj["status"] = utils.FAILURE
        update_obj["result_msg"] = ""
        update_obj["execution_end"] = str(int(time.time()))
        if err_msg:
            update_obj["error_msg"] = err_msg
        return update_obj
    except Exception as e:
        logger.error("Exception occurred in update_action_fail_in_db: {}".format(str(e)))

def update_action_by_json_obj(action, update_obj):
    component_name = action.get("component_name")
    action_name = action.get("action_name")
    cust_id = action.get("cust_id")
    unique_key = action.get("unique_key")
    timestamp = action.get("timestamp")
    if type(unique_key) is dict:
        unique_keys = {"unique_key." + k: v for k,v in unique_key.items()}
        filters = {"component_name": component_name, "action_name": action_name,
            "cust_id": cust_id, "timestamp": timestamp} 
        filters.update(unique_keys)
        action = custom_response_action_table.update_one(filters,
            {"$set": update_obj}, upsert=False)
    else:
        update_res = custom_response_action_table.update_one({
            "component_name": component_name, "action_name": action_name,
            "cust_id": cust_id, "unique_key": unique_key, "timestamp": timestamp},
            {"$set": update_obj}, upsert=False)

def update_bulk_action_by_json_obj(action, update_obj, batch_id):
    component_name = action.get("component_name")
    action_name = action.get("action_name")
    cust_id = action.get("cust_id")
    custom_response_action_table.update_many({
        "component_name": component_name, "action_name": action_name,
        "cust_id": cust_id, "params.batch_id": batch_id},
        {"$set": update_obj}, upsert=False)

def preprocess_batch_params(module_instance, action):
    getattr(module_instance, "batch_process")(action)

def call_action_function(module_instance, action, run_on, revert=False):
    action_name = action.get("action_name")
    if revert:
        action_name = action.get("revert_action_name")
        if not action_name:
            return {"result_msg": "automatically expiring the action {} ".format(action.get("action_name"))}
    action_params = action.get("params")
    if "run_on" not in action_params:
        action_params["run_on"] = run_on
    action_result = getattr(module_instance, action_name)(**action_params)
    return action_result

def is_expired(action):
    duration = action.get("duration")
    execution_end_time = action.get("execution_end")
    if execution_end_time is None:
        logger.warning("Action {} is missing execution_end time".format(
            action))
        return False
    if not is_duration_valid(duration):
        logger.warning("Action {} has invalid duration {}".format(
            action, duration))
        return False
    fields = duration.split()
    num = int(fields[0])
    unit = fields[1].lower()
    if unit == "days":
        num = num * 24 * 3600
    elif unit == "hours":
        num = num * 3600
    elif unit == "minutes":
        num = num * 60
    if time.time() - int(execution_end_time) >= num:
        return True

def is_duration_valid(duration):
    fields = duration.split()
    if len(fields) != 2:
        return False
    try:
        num = int(fields[0])
    except:
        return False
    unit = fields[1].lower()
    if unit not in ["days", "hours", "minutes"]:
        return False
    return True

def is_result_valid(result):
    if type(result) is not dict:
        return False
    for key in result.keys():
        if key in utils.RESERVED_KEYS:
            return False
    return True

def fail_all_pending_actions():
    try:
        custom_response_action_table.update_many(
                {"status": utils.IN_PROGRESS},
                {"$set": {"status": utils.FAILURE, "result_msg": "",
                    "error_msg": "Interrupted by container restart"}})
    except Exception as e:
        logger.error("Failed to mark pending actions as failed: {}".format(str(e)))

def signal_handler(signal, frame):
    print "Received SIGINT, Exit"
    os._exit(1)

if __name__ == "__main__":
    logger = utils.action_agent_logger

    signal.signal(signal.SIGINT, signal_handler)

    mongo_db_connected = False
    while not mongo_db_connected:
        try:
            db_client = MongoClient(utils.MONGODB_URL)
            mongo_db_connected = True
        except pymongo.errors.ConnectionFailure, e:
            logger.error("Failed to connect to MongoDB: {}, {}".format(
                utils.MONGODB_URL, str(e)))
            time.sleep(5)

    custom_response_table = db_client[utils.DB_NAME][
            utils.CUSTOM_RESPONSE_TABLE_NAME]
    custom_response_action_table = db_client[utils.DB_NAME][
            utils.CUSTOM_RESPONSE_ACTION_TABLE_NAME]

    pool = Pool(12)
    fail_all_pending_actions()

    while True:
        execute_all_actions()
        time.sleep(15)
