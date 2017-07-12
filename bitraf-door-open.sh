#!/bin/bash

LOGIN_NAME=$1
DOOR=$2
DURATION=$3

# Sanity checks
case "$DOOR" in
  frontdoor) ;;
  2floor) ;;
  4floor) ;;
  3office) ;;
  3floor) ;;
  *)
    echo "Unsupported door value \"$DOOR\""
    exit 1
esac

source ./bitraf-door-credentials.sh

# Trigger unlocking
mosquitto_pub -h $MQTT_BROKER -u $MQTT_USERNAME -P $MQTT_PASSWORD -t "/bitraf/door/$DOOR/open" -m "$DURATION"

# Notify that member logged in
mosquitto_pub -h $MQTT_BROKER -t /bitraf/doorweb/memberlogin -m "$LOGIN_NAME"
