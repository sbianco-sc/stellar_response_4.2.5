#!/bin/sh -x

# Logrotate requires syslog group
grep ^syslog: /etc/group
if [ $? -ne 0 ]; then
    groupadd syslog
fi

cp -Rp /version .

/usr/bin/supervisord -n
