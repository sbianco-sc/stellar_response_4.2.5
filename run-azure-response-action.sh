#!/bin/bash
thisdir=$(dirname $(readlink -f $0))
log=$thisdir/run.log
ts=$(date '+%Y-%m-%d %T')" "

# Application (client) ID: 20e0cf42-14d5-448d-9bfd-be18e7280d54
# Directory (tenant) ID: a289e960-a538-4db3-adf0-845b57e616cf
# Client Secret Value: 12~8Q~dx1PoCiSo9wfEEJUytdL2WVqa29UMBkb_0
# encoded:  dKHsnrrl2eqWcLKy1b_UnOvVt4i5w9_dy8GkvHa00J6lurC22tSinw==

# -o
tenant_id="3b8c9244-81cd-42d0-8456-b1b770fe5dc2"

# -u
client_id="c2ce62db-6987-4934-9039-917bae9fabc1"

# -p
pass="qbWcrK3Uyue5mJ3dtLbW4aHF6Jbtn6fN0KjIsnF5ua-l4w=="

# -i
# for confirm_compromise or dismiss_risk, the sid is the user's guid
# sid="f09b2235-8575-4332-ae1e-5b9bd59e2389"
# for disable/enable user - the sid is the userPrincipalName under the azure_ad stanza
# azure_ad.userPrincipalName: "liz.gonzalez@datawarden.com.mx"
sid="$2"

# VALID_ACTIONS = ["disable_user", "enable_user", "confirm_compromise", "dismiss_risk", "list_risky_users", "list_risky_user"]

# -a
action="$1"
if [ "$action" == "list_risky_users" ]
then
	echo "$ts    listing risky users"
	echo
	/usr/bin/python3 $thisdir/azure_ad_responder.py -o "$tenant_id" -u "$client_id" -p "$pass" -i "blah" -a "$action"

elif [[ ( "$action" == "confirm_compromise" || "$action" == "dismiss_risk" || "$action" == "disable_user" || "$action" == "enable_user" ) && ( "$sid" ) ]]
then
	echo "$ts    performing action: [$action] on [$sid]" | tee -a $log
	/usr/bin/python3 $thisdir/azure_ad_responder.py -o "$tenant_id" -u "$client_id" -p "$pass" -i "$sid" -a "$action" | tee -a $log
else
	echo
	echo "USAGE: $0 <action> <user_sid>"
	echo "valid actions: confirm_compromise, dismiss_risk, list_risky_users, disable_user, enable_user"
	echo
	exit 1
fi