# Android Observatory

This repository contains the source code for the 
[Android Observatory](https://androidobservatory.org).

This code is **not supported** by the authors. It is offered **as is** without
much in the way of documentation.

Produced in 2012. See "Understanding and Improving App Installation Security
Mechanisms through Empirical Analysis of Android"
([PDF](https://www.ccsl.carleton.ca/~dbarrera/files/spsm12-barrera.pdf)) for
more information.

This is initial (extremely rough) release of the Android Observatory
server code.


## Setup

1. Install the Android SDK. Note the location you install the SDK
   https://developer.android.com/sdk/index.html?hl=sk
2. Ensure the SDK location is on the system $PATH
3. Set up a virtualenv for the observatory code/dependencies. If you
   don't have virtualenv, but already have pip setup, run 'pip install
   virtualenv'
4. From the directory you cloned the observatory code run:
```console
$  virtualenv ./
$ source bin/activate      # Activate the venv
$ python setup.py install  # Install the Observatory dependencies
# Configure site-specific settings
$ cp observatory/default_settings.py ./site_settings.py
$ export OBS_SETTINGS=PATH_TO/site_settings.py
$ python run.py  # Test the installation with the debug server
```

5. Then open a browser on localhost and connect to
   <http://localhost:5000>

If you're planning on running a publicly accessible instance of the
Observatory you will want to investigate a WSGI deployment. To aid in
this process an example WSGI file is provided in
'observatory.wsgi.sample'. You will need to change
'/var/www/observatory'/ to the directory you installed the observatory
code to. Further details on WSGI (i.e. Apache integration) can be
found here: https://code.google.com/p/modwsgi/


## APK Upload Support

Presently in order to allow user uploads you will have to manually
configure a few files. This sucks. I know it sucks.

1. Edit the example watch_uploads.sh script
2. Change UPLOAD_DIR to the directory you set in site_settings.py for
   uploads to be placed
3. Change DIR to the directory you've installed the observatory source
   code
4. Optionally: add a Pushover API key and one or more device keys and
   uncomment the sendmessage line for pushover upload notifications
5. Make sure that watch_uploads.sh runs on machine start
6. If you're using a Ubuntu based system there is an example upstart
   script in observatory_watch.conf
7. You'll have to set UPLOAD_DIR, OBS_USER, and WATCH_SCRIPT before
   installing to /etc/init
