#!/bin/bash
export PYTHONPATH="/opt/aelladata/connector:/opt/aelladata/connector/modules:/opt/aelladata/connector/common:/opt/aelladata/connector/connector"
thisdir=$(dirname $(readlink -f $0))
log=$thisdir/run.log
server="hexmzd572-hx-webui-1.hex01.helix.apps.fireeye.com"
user="david.white@wipro.com"
pass="@zU0&9D0rny&RRtj"
action="$1"
hx_id="$2"

echo "running fireeye HX response: [$action] hxid: [$hx_id]" | tee -a $log
if [ "$hx_id" ]
then
	/usr/bin/python $thisdir/fireeye_trellix_responder.py -s "$server" -u "$user" -p "$pass" -a "$action" -i "$hx_id" 2>&1 | tee -a $log
	ec=$?
else
	ec=1
fi
echo "exiting with ec: $ec" | tee -a $log
exit $ec