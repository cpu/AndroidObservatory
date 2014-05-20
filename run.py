#
# Boot a local single-threaded instance of the app in debug mode.
# Only useful for testing. Deploy as a proper Apache mod_wsgi app
# for anything more.
#
# !!!! WARNING !!!! WARNING !!!! WARNING !!!! WARNING !!!! !!!! WARNING !!!!
# Make sure you *never* run the app in Debug when accessible by untrusted
# clients as it allows arbitrary python code execution by design.
# !!!! WARNING !!!! WARNING !!!! WARNING !!!! WARNING !!!! !!!! WARNING !!!!
#
from observatory import app

# To bind the debug instance on all interfaces (i.e. to access from another
# machine) use the app.run line that specifies a host of 0.0.0.0
#app.run(host='0.0.0.0', debug=True)

# To bind the debug instance only to localhost, use the following app.run
app.run(debug=True)
