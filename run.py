#
# Boot a local single-threaded instance of the app in debug mode.
# Only useful for testing. Deploy as a proper Apache mod_wsgi app
# for anything more.
#
# Make sure you *never* run the app in Debug when publically accessible
# as it allows arbitrary python code execution by design.
#
from observatory import app
app.run(debug=True)
