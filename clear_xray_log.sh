#!/usr/bin/env bash

access_log_path="/var/log/xray/access.log"

while true; do
	echo "" > ${access_log_path}
	sleep 15
done

