#!/bin/bash

UPLOAD_DIR=/android-uploads
DIR=/var/www/observatory
TOOL=$DIR/observatory/apk_info.py
DB=$DIR/observatory.db
LOGFILE=$DIR/app_log.txt

APP_TOKEN="PUSHOVER APP TOKEN HERE"
KEYS=( PUSHOVER_CLIENT_KEY_1 PUSHOVER_CLIENT_KEY_2 PUSHOVER_CLIENT_KEY_N )

#You -must- have the platform tools on the path before running the import tool
#as it relies on the aapt binary from platform-tools
export PATH=$PATH:/android-sdk/platform-tools

function sendMessage() {
  for USER in "${KEYS[@]}"
  do
    echo "Pushing to $USER" >> $LOGFILE;
    curl -s -F "token=$APP_TOKEN" -F "user=$USER" -F "title=$2" -F "sound=incoming" -F "message=$1" -F "url=$3" -F "url_title=App Info" https://api.pushover.net/1/messages.json >> /dev/null
  done;
}

cd $DIR

inotifywait -m --format '%w%f' -e create $UPLOAD_DIR | while read FILE
do
  f=$(basename $FILE)
  e=${f##*.}

  echo "New file: $f. Extension $e" >> $LOGFILE

  #Only import apk files
  if [ "$e" = "apk" ]
  then

    hash=$(sha1sum $FILE | awk '{print $1}' | tr '[:lower:]' '[:upper:'])
    echo "hash: $hash" >> $LOGFILE
    sendMessage "New APK uploaded: $f" "New Observatory Upload" "http://www.androidobservatory.org/apk/$hash"

    echo "Importing $f" >> $LOGFILE
    /usr/bin/python $TOOL -vd $DB $FILE >> $LOGFILE
  fi

  #Don't remove the file, currently breaks the web app since it expects the file to be
  #there after an upload, and this script will delete it out from under it without notice
  #We'll have to manually clean up for now
  #
  #rm $FILE
done
