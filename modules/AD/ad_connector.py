#!/usr/bin/python
'''
LDAP library for querying user profiles from domain controller's Active Directory

Features:
    - set up ldap connection
    - disable and enable users


Prerequisites:
    - pip install ldap3 as dependency

'''
import argparse
import sys
import logging
import base64
import json
import logging
import logging.handlers
import ldap3
import sys
import ssl
import utils

#The LDAP to DC connection timeout value
TIMEOUT=300

#The Disable User bit in the userAccountControl attribute. Bit #2
DISABLEUSERBIT=2

logger = logging.getLogger(__name__)

COLLECTOR_CONFIG_DIR = "/etc/aella/log-collector/rules"

LOG_FILENAME = "/var/log/aella/ad_user_action.log"

COLLECTOR_SECRET = 'Configure Collector'

def aella_decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(str(enc))
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

class AdConnector:

    def __init__(self, server_addr, username, password, ad_domain, protocol_type="", **kwargs):
        '''
        :param server_addr: str: server domain name or IP: such as dc.x.com
        :param username: str: the DC administrator account username
        :param password: str: the DC administrator account password
        :param ad_domain: str: Active Directory Domain: such as eng.x.com
        '''
        self.server_addr = server_addr
        self.username = self.append_domain_if_needed(ad_domain, username)
        self.password = aella_decode(COLLECTOR_SECRET, password)
        self.ad_domain = ad_domain
        self.protocol = protocol_type
        self.conn = None

    def append_domain_if_needed(self, domain, username):
        if "\\" not in username and "@" not in username:
            username = "{}\\{}".format(domain, username)
        return username

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
        if action_name == "disable_ad_user_by_sid" or \
                action_name == "enable_ad_user_by_sid":
            ad_name = settings.get("component_name", "")
            hits = source["ctx"]["payload"]["filtered"]
            for hit in hits:
                fields = settings.get("field_list", [])
                for field in fields:
                    user_sid = utils.get_value(hit["_source"], field)
                    if user_sid:
                        current_param = {"sid": user_sid, "ad_name": ad_name}
                        params.append(current_param)
                    else:
                        logger.error("value of field: {} not found".format(field))
        return params

    def test_connection(self, **kwargs):
        """
        Function used by Stellar Cyber for configuration validation
        :return: str: 'succeeded' if the connection test passes
            otherwise, a custom message to show to user
        """
        run_on = kwargs.get("run_on", "")
        if run_on != "" and run_on != "dp":
            name = kwargs.get("name")
            return self.notify_ds_to_test_connection(name, run_on)
        if self.init_ldap_connection():
            return utils.create_response("AD", 200, "")
        return utils.create_response("AD", 400, "Could not connect to LDAP server")

    def notify_ds_to_test_connection(self, name, run_on):
        """
        Notify DS to perform the connection test
        :param name: str: the name of the AD connector
        :param run_on: str: the engid of sensor to run the test
        :return: str: the test results
        """
        import utils
        ad_script_path = "/opt/aelladata/connector/modules/AD/ad_connector.py"
        command = "export PYTHONPATH={}; python {} -a test -u dummy -c \"{}\"".format(utils.PYTHONPATH, ad_script_path, name)
        status_code, error_msg = utils.execute_action_on_ds(run_on, command, retry_count=1)
        if status_code > 0:
            return utils.create_response("AD", 400, error_msg)
        return utils.create_response("AD", 200, "")

    def get_connection(self):
        if self.protocol == "LDAPS":
            tls = ldap3.Tls(validate=ssl.CERT_REQUIRED, version=ssl.PROTOCOL_TLSv1_2)
            server = ldap3.Server(self.server_addr, connect_timeout=TIMEOUT,
                                get_info=ldap3.ALL, port=636, use_ssl=True, tls=tls)
        elif self.protocol == "LDAPS (certificate validation disabled)":
            tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
            server = ldap3.Server(self.server_addr, connect_timeout=TIMEOUT,
                                get_info=ldap3.ALL, port=636, use_ssl=True, tls=tls)
        else:
            server = ldap3.Server(self.server_addr, connect_timeout=TIMEOUT,
                                get_info=ldap3.ALL)
        conn = ldap3.Connection(server, user=self.username,
                                    password=self.password,
                                    authentication=ldap3.NTLM, raise_exceptions=True)
        return conn

    def test_connection_on_ds(self):
        """
        This function will only be called on DS
        """
        try:
            self.conn = self.get_connection()
            if not self.conn.bind():
                raise Exception("Error in LDAP/LDAPS connection bind:%s" % self.conn.result)
            return "succeeded"
        except Exception as e:
            raise Exception("Set up LDAP/LDAPS connection failed: {}".format(str(e)))

    def init_ldap_connection(self):
        '''
        initLDAPconnection: set up the connection to Domain Control Active Directory through NTLM v2 protocol
        :return: bool: true if LDAP connection is successful, otherwise false
        '''
        try:
            if self.protocol == "LDAPS":
                tls = ldap3.Tls(validate=ssl.CERT_REQUIRED, version=ssl.PROTOCOL_TLSv1_2)
                server = ldap3.Server(self.server_addr, connect_timeout=TIMEOUT,
                                    get_info=ldap3.ALL, port=636, use_ssl=True, tls=tls)
            elif self.protocol == "LDAPS (certificate validation disabled)":
                tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
                server = ldap3.Server(self.server_addr, connect_timeout=TIMEOUT,
                                    get_info=ldap3.ALL, port=636, use_ssl=True, tls=tls)
            else:
                server = ldap3.Server(self.server_addr, connect_timeout=TIMEOUT,
                                    get_info=ldap3.ALL)
            self.conn = ldap3.Connection(server, user=self.username,
                                         password=self.password,
                                         authentication=ldap3.NTLM, raise_exceptions=True)
            if not self.conn.bind():
                logger.error("Error in LDAP connection bind:%s" % self.conn.result)
                return False
            return True
        except Exception as e:
            logger.error("Failed to establish connection: {}".format(e))
            return False

    def disable_ad_user_by_sid(self, sid, **kwargs):
        '''
        Given the LDAP connection conn and sid of user, change user's userAccountControl
        to disable the user account on Active Directory
        :param sid: str: Windows Security ID: SID
        :return: bool: true if successfully find the user and disabled, return false if not find the users,
            raise exception if find the user but cannot disable the user
            if not successful, error message will be print, and an exception will be raised.
        LIMITATION: current the exception usually said bad connection, but usually are other privilege problems.
        '''
        run_on = kwargs.get("run_on", "dp")
        ad_name = kwargs.get("ad_name", "")
        sid = sid.encode('utf-8')
        if run_on.lower() != "dp" and run_on != "":
            return self.run_user_action_on_ds(sid, "disable", run_on, ad_name)
        if not self.init_ldap_connection():
            raise Exception("Failed to establish ldap connection")
        userDn = self.get_general_dn()
        isUserExist = self.conn.search(userDn, '(&(objectSid=%s)(objectclass=user))' % sid, attributes='userAccountControl')  # type: Boolean
        if not isUserExist or not self.conn.entries:
            isUserExist = self.conn.search(userDn, "(&(sAMAccountName={})(objectclass=user))".format(sid), attributes='userAccountControl')
            if not isUserExist or not self.conn.entries:
                raise Exception("User {} does not exist".format(sid))

        if isUserExist:
            dn = self.conn.entries[0].entry_dn
            dn = dn.encode('utf-8')
            oldValue = self.conn.entries[0]["userAccountControl"].value
            newValue = oldValue | DISABLEUSERBIT # userAccountControl is a bitmap, enable distableUserBit will disable the user
            try:
                result = self.conn.modify(dn, {'userAccountControl': [(ldap3.MODIFY_REPLACE, [newValue])]})
                if not result:
                    raise Exception(self.conn.result.get("description", ""))
            except Exception as e:
                isDisable = False
                #logger.error("Fail to disableADUser, errors in LDAP modify for %s (%s)" % (sid, dn))
                #logger.debug("The raw exception message might not be the root cause")
                raise Exception("Failed to disable user: {}".format(str(e)))
        return {"result_msg": "User {} disabled".format(dn)}


    def enable_ad_user_by_sid(self, sid, **kwargs):
        '''
        Given the LDAP connection conn and sid of user, change user's userAccountControl
        to enable the user account on Active Directory.
        :param sid: str: Windows Security ID: SID
        :return: bool: true if successfully find the user and disabled, return false if not find the users,
            raise exception if find the user but cannot enable the user
            if not successful, error message will be print, and an exception will be raised.
        LIMITATION: current the exception usually said bad connection, but usually are other privilege problems.
        '''
        run_on = kwargs.get("run_on", "dp")
        ad_name = kwargs.get("ad_name", "")
        sid = sid.encode('utf-8')
        if run_on.lower() != "dp" and run_on != "":
            return self.run_user_action_on_ds(sid, "enable", run_on, ad_name)
        if not self.init_ldap_connection():
            raise Exception("Failed to establish ldap connection")
        userDn = self.get_general_dn()
        isUserExist = self.conn.search(userDn, '(&(objectSid=%s)(objectclass=user))' % sid, attributes='userAccountControl')  # type: Boolean
        if not isUserExist or not self.conn.entries:
            isUserExist = self.conn.search(userDn, "(&(sAMAccountName={})(objectclass=user))".format(sid), attributes='userAccountControl')
            if not isUserExist or not self.conn.entries:
                raise Exception("User {} does not exist".format(sid))

        if isUserExist:
            dn = self.conn.entries[0].entry_dn
            dn = dn.encode('utf-8')
            oldValue = self.conn.entries[0]["userAccountControl"].value
            newValue = oldValue ^ DISABLEUSERBIT # userAccountControl is a bitmap, clear distableUserBit will enable the user
            try:
                result = self.conn.modify(dn, {'userAccountControl': [(ldap3.MODIFY_REPLACE, [newValue])]})
                if not result:
                    raise Exception(self.conn.result.get("description", ""))
            except:
                isEnable = False
                #logger.error("Fail to enableADUser, errors in LDAP modify for %s" % sid)
                #logger.debug("The raw exception message might not be the root cause")
                raise Exception("Failed to enable user: {}".format(str(e)))
        return {"result_msg": "User {} enabled".format(dn)}


    def run_user_action_on_ds(self, sid, action, run_on, ad_name, timeout=300):
        """
        Notify DS to execute the user action
        :param sid: str: user identifier
        :param run_on: str: sensor ID
        :param ad_name: str: AD connector name
        """
        import utils
        ad_script_path = "/opt/aelladata/connector/modules/AD/ad_connector.py"
        command = "export PYTHONPATH={}; python {} -a {} -u \"{}\" -c \"{}\"".format(utils.PYTHONPATH, ad_script_path, action, sid, ad_name)
        status_code, error_msg = utils.execute_action_on_ds(run_on, command)
        if status_code > 0:
            raise Exception("User action fail with status code {}: {}".format(status_code, error_msg))
        return {"result_msg": "User {} {}d".format(sid, action)}

    def get_dn_domain_string(self):
        '''
        Get domain string in DN: ",DC=eng,DC=x,DC=com"
        :return: str: the domain string used in DN
        '''
        levels = self.ad_domain.strip().split(".")
        dn = ""
        for l in levels:
            dcdnSegment = ",DC=%s" % l
            dn += dcdnSegment
        return dn

    def get_users_dn(self):
        '''
        Get the DN represent all the users
        :return: str: the UsersDN string represents all the users 
        '''
        return "CN=Users" + self.get_dn_domain_string()

    def get_general_dn(self):
        '''
        Get the DN represent all the users
        :return: str: the DN string that covers the general DN space
        '''
        return self.get_dn_domain_string()[1:]

if __name__ == '__main__':
    FORMAT = "%(asctime)-15s|%(name)s|%(levelname)s|%(message)s"
    logger = logging.getLogger("ad_user")
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter(FORMAT)
    handler = logging.handlers.WatchedFileHandler(LOG_FILENAME)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--action', action='store', dest='action', required=True,
        help='The action to take, can be enable user or disable user')
    parser.add_argument('-u', '--usersid', action='store', dest='sid', required=True,
        help='The user identify, can be usersid or username')
    parser.add_argument('-c', '--connector', action='store', dest='connector', required=True,
        help='The connector use to connector to AD')

    results = parser.parse_args()
    if not results.action:
        logger.error("Must specify an action")
        sys.stderr.write("Missing action in parameter\n")
        sys.exit(1)
    if not results.sid:
        logger.error("Must specify sid")
        sys.stderr.write("Missing usersid in parameter\n")
        sys.exit(1)
    if not results.connector:
        logger.error("Must specify connector")
        sys.stderr.write("Missing connector name in parameter\n")
        sys.exit(1)

    config_file = "/etc/aella/log_collector.conf"

    config = {}

    try:
        f = open(config_file)
        lc_config = json.load(f)
        f.close()
        if lc_config is None:
            sys.stderr.write("Cannot get connector configuration\n")
            sys.exit(1)
        sources = lc_config.get("sources", [])
        for connector in sources:
            connector_type = connector.get("type", "")
            connector_name = connector.get("name", "")
            if connector_type == "ad" and connector_name == results.connector:
                config = json.loads(connector.get("conf", "{}"))
        if not config:
            sys.stderr.write("Cannot get connector configuration\n")
            sys.exit(1)
    except:
        sys.stderr.write("Cannot get connector configuration\n")
        sys.exit(1)


    server_addr = config.get("server_addr", "")
    ad_domain = config.get("ad_domain", "")
    username = config.get("username", "")
    protocol = config.get("protocol_type", "")
    if "\\" not in username and "@" not in username:
        username = "{}\\{}".format(ad_domain, username)

    ad_connector = AdConnector(server_addr, username, config.get("password"), ad_domain, protocol)

    if results.action == "test":
        try:
            res = ad_connector.test_connection_on_ds()
        except Exception as e:
            sys.stderr.write("Connection test failed: {}\n".format(str(e)))
            sys.exit(1)
        print res
        sys.exit()

    if not ad_connector.init_ldap_connection():
        sys.stderr.write("Cannot connect to AD\n")
        sys.exit(1)
    if results.action == "enable":
        try:
            sid = results.sid.decode('utf-8')
            res = ad_connector.enable_ad_user_by_sid(sid)
        except Exception as e:
            sys.stderr.write("Failed to enable user: {} \n".format(str(e)))
            sys.exit(1)
    elif results.action == "disable":
        try:
            sid = results.sid.decode('utf-8')
            res = ad_connector.disable_ad_user_by_sid(sid)
        except Exception as e:
            sys.stderr.write("Failed to disable user: {}\n".format(str(e)))
            sys.exit(1)
    print res
