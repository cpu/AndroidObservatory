#!/bin/bash

# Where do uploads end up?
UPLOAD_DIR=/android-uploads

#Where is the base directory of the observatory code?
DIR=/var/www/observatory

#The import script, database, and log file are relative to $DIR
TOOL=$DIR/observatory/apk_info.py
DB=$DIR/observatory.db
LOGFILE=$DIR/app_log.txt

#Pushover (https://pushover.net/) is used for upload notifications
APP_TOKEN="PUSHOVER APP TOKEN HERE"
KEYS=( PUSHOVER_CLIENT_KEY_1 PUSHOVER_CLIENT_KEY_2 PUSHOVER_CLIENT_KEY_N )

#You -must- have the platform tools on the path before running the import tool
#as it relies on the aapt binary from platform-tools
export PATH=$PATH:/android-sdk/platform-tools

#Send a message using the Pushover API to each of the device keys from $KEYS
function sendMessage() {
  for USER in "${KEYS[@]}"
  do
    echo "Pushing to $USER" >> $LOGFILE;
    curl -s -F "token=$APP_TOKEN" -F "user=$USER" -F "title=$2" -F "sound=incoming" -F "message=$1" -F "url=$3" -F "url_title=App Info" https://api.pushover.net/1/messages.json >> /dev/null
  done;
}

cd $DIR

#inotifywait is used to watch the upload directory for new file creation events
inotifywait -m --format '%w%f' -e create $UPLOAD_DIR | while read FILE
do
  #From the newly created $FILE we want the base filename and the extension
  f=$(basename $FILE)
  e=${f##*.}

  echo "New file: $f. Extension $e" >> $LOGFILE

  #Only attempt to import files with an APK extension
  if [ "$e" = "apk" ]
  then

    #Compute the SHA1 hash of the file and lower case the hex digits to match the rest of the system
    hash=$(sha1sum $FILE | awk '{print $1}' | tr '[:lower:]' '[:upper:'])
    echo "hash: $hash" >> $LOGFILE

    #Uncomment the following sendMessage line to enable pushover support. You
    #must also set up an APP_TOKEN and one or more $KEYS
    #
    #sendMessage "New APK uploaded: $f" "New Observatory Upload" "http://www.androidobservatory.org/apk/$hash"
    #

    echo "Importing $f" >> $LOGFILE

    #Invoke the import tool to grab the apk
    /usr/bin/python $TOOL -vd $DB $FILE >> $LOGFILE
  fi

  #Don't remove the file, currently breaks the web app since it expects the file to be
  #there after an upload, and this script will delete it out from under it without notice
  #We'll have to manually clean up for now
  #rm $FILE
done
