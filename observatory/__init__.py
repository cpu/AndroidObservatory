from os    import urandom
from flask import Flask
from flask import render_template
from flask import g
from flask import request
from flask import flash
from flask import redirect
from flask import url_for
from flask import json
from flask import jsonify

import hashlib

from flaskext.uploads import (UploadSet, configure_uploads, UploadNotAllowed,
                              patch_request_class)

app = Flask(__name__)
app.config.from_object('observatory.default_settings')
app.config.from_envvar('OBS_SETTINGS', silent=True)

userApks = UploadSet('apks', ('apk'))
configure_uploads(app, userApks)
patch_request_class(app)

from persistance      import *
from template_filters import *

@app.route('/', methods=['GET', 'POST'])
def app_search():
  q,s           = None,'name'
  apps          = []
  search_types  = {'name':"name", 'pkg':"package name", 'binhash':"APK hash",
                    'certhash':"cert. fingerprint", 'suid':"shared UID"}

  rndApps = query_db("SELECT * FROM apps ORDER BY RANDOM() LIMIT 10")
  newApps = query_db("SELECT * FROM apps ORDER BY timestamp DESC LIMIT 10")
  sources = query_db('SELECT source, COUNT(id) AS count FROM apps GROUP BY source')

  if request.method == 'POST':
    data = request.form
  else:
    data = request.args.to_dict(True)

  if data:
    s = data.get('searchby','name')
    q = data.get('q','').strip()

    if s == "pkg":
      pkgName = u"%{0}%".format(q)
      apps = query_db("SELECT * FROM apps WHERE pkgname LIKE ?",
                        [pkgName])
    elif s == "binhash":
      apps = query_db("SELECT * FROM apps WHERE binhash = ?",
                        [q.upper()])

    elif s == "certhash":
      q = q.replace(':','')
      apps = query_db("SELECT * FROM apps LEFT JOIN certs ON (apps.uappid = certs.uappid) WHERE certs.fingerprint = ?", [q.upper()])

    elif s == "suid":
      apps = query_db("SELECT * FROM apps WHERE shareduserid = ?", [q])

    else:
      appName = u"%{0}%".format(q)
      apps = query_db('SELECT * FROM apps WHERE appname LIKE ?',
                        [appName])

  if request.headers.get('Content-Type') == 'application/json':
    resp = { 'results': apps }
    return jsonify(resp)
  else:
    return render_template('app_search.html',
                            apps=apps,
                            query=q,
                            searchBy=s,
                            sources=sources,
                            rndApps=rndApps,
                            newApps=newApps,
                            searchTypes=search_types)

@app.route('/cert/<string:cert_id>')
def cert_details(cert_id):
  if cert_id:
    cert_id = cert_id.replace(':','').strip()

  cert   = query_db("SELECT * FROM certs WHERE fingerprint = ? ORDER BY fingerprint ASC", [cert_id], True)

  if cert:
    apps   = query_db("SELECT * FROM apps LEFT JOIN certs ON (apps.uappid = certs.uappid) WHERE certs.fingerprint = ? ORDER BY apps.versioncode DESC", [cert_id])
    pubkey = query_db("SELECT * FROM pubkeys WHERE id = ?", [cert['pubkeyID']], True)
  else:
    apps = [None]
    pubkey = [None]

  if request.headers.get('Content-Type') == 'application/json':
    resp = { 'cert': cert, 'pubkey': pubkey, 'associatedApps': apps }
    return jsonify(resp)
  else:
    return render_template('cert_detail.html', cert=cert, apps=apps, pubkey=pubkey)

@app.route('/app/<string:app_id>')
def app_details(app_id):
  app   = query_db("SELECT * FROM apps WHERE id = ?", [app_id], True)
  perms = []
  certs = []
  flagged = False
  otherRepo = None

  if app:
    perms = query_db("SELECT name FROM permissions LEFT JOIN app_permissions ON (permissions.id = app_permissions.perm_id) WHERE app_permissions.app_id = ? ORDER BY name ASC", [app['id']])
    certs = query_db("SELECT * FROM certs WHERE uappid = ? ORDER BY fingerprint ASC", [app['uappid']])
    otherRepo = query_db("SELECT * FROM apps WHERE uappid = ? AND source <> ?", [app['uappid'], app['source']])

    for c in certs:
      badApps = query_db("SELECT * FROM apps LEFT JOIN certs ON (apps.uappid = certs.uappid) WHERE certs.fingerprint = ? AND (apps.source = 3 OR apps.source = 9)", [c['fingerprint']])

      if badApps:
        flagged = True

  if request.headers.get('Content-Type') == 'application/json':
    resp = { 'app': app, 'permisisons': perms, 'certs': certs, 'otherInstances': otherRepo }
    return jsonify(resp)
  else:
    return render_template('app_detail.html', app=app, permissions=perms, certs=certs, otherRepo=otherRepo, flagged=flagged)

@app.route('/apk/<string:sha1>')
def app_hash(sha1):
  if sha1:
    app = query_db("SELECT * FROM apps WHERE binhash = ?", [sha1.upper()], True)

    if app:
      return redirect(url_for('app_details', app_id=app['id']))

  flash("No APK found in database with SHA1 hash \"{0}\".".format(sha1))
  return redirect(url_for('app_search'))

@app.route('/upload', methods=['GET', 'POST'])
def upload():

  if request.method == 'POST' and 'apk' in request.files:
    try:
      filename = userApks.save(request.files['apk'])
    except UploadNotAllowed:
      flash("You may only upload files ending with '.apk'")
    except:
      flash("Invalid/corrupt upload.")
    else:
      sha1    = hashlib.sha1()
      apkPath = "{0}/{1}".format(UPLOADED_APKS_DEST, filename)

      with open(apkPath, 'rb') as f:
        for chunk in iter(lambda: f.read(128 * sha1.block_size), b''):
          sha1.update(chunk)

      binhash = sha1.hexdigest().upper()
      dupe   = query_db("SELECT * FROM apps WHERE binhash = ?", [binhash], True)

      if dupe:
        flash("Uploaded APK was already present in database.")
        return redirect(url_for('app_details', app_id=dupe['id']))

      flash("Your application has been uploaded and will be <a href='{0}'>available here</a> within the next hour".format(url_for('app_hash', sha1=binhash)))
      return redirect(url_for('app_search'))

  return render_template('upload.html')

@app.route('/stats')
def stats():
  distinct_apks_by_binhash = get_count("SELECT COUNT(DISTINCT binhash) AS count FROM apps")
  distinct_apps_by_pkgname = get_count("SELECT COUNT(DISTINCT pkgname) AS count FROM apps")
  distinct_certs_by_print = get_count("SELECT COUNT(DISTINCT fingerprint) AS count FROM certs")

  import locale
  locale.setlocale(locale.LC_ALL, 'en_US.utf8')

  commafy = lambda i : locale.format("%d", i, grouping=True)

  count_stats = [
    {'name':"distinct APKs by binhash", 'count': commafy(distinct_apks_by_binhash)},
    {'name':"distinct apps by package name", 'count': commafy(distinct_apps_by_pkgname)},
    {'name':"distinct code signing certs by fingerprint", 'count': commafy(distinct_certs_by_print)}]

  top_10_perms = query_db("SELECT p.name, COUNT(ap.app_id) AS count " + 
                          "FROM app_permissions AS ap " +
                          "LEFT JOIN permissions AS p ON ap.perm_id = p.id " +
                          "GROUP BY ap.perm_id " +
                          "ORDER BY count(ap.app_id) DESC " +
                          "LIMIT 10;")

  key_stats = query_db("SELECT COUNT(DISTINCT fingerprint) AS certcount, algo, keybits FROM pubkeys, certs WHERE pubkeys.id = certs.pubkeyid GROUP by algo, keybits HAVING certcount > 25 ORDER By certcount DESC LIMIT 4;")

  other_keys = distinct_certs_by_print - sum([ x['certcount'] for x in key_stats ])

  return render_template('stats.html', countStats=count_stats, top10Perms=top_10_perms, keyStats=key_stats, otherKeys=other_keys)

@app.route('/about')
def about():
  return render_template('about.html')

@app.route('/faq')
def faq():
  return render_template('faq.html')
