#!/usr/bin/env python

import os, sys, sqlite3, time

import apk_info
from utils import *

verbose = False

def p(message):
  if verbose:
    print("[+] {0}".format(message))

def e(message):
  print("[!] {0}".format(message))

def connectDB(dbFile):
  conn = sqlite3.connect(dbFile)
  conn.row_factory = sqlite3.Row
  return conn

def queryAppDetails(conn, app):
  existingApp = conn.execute('SELECT * FROM apps WHERE id = ?;', (app.getID(),))
  return existingApp.fetchone()

def queryPerm(conn, perm):
  existingPerm = conn.execute("SELECT id,name FROM permissions WHERE name = ? LIMIT 1;", (perm,))
  return existingPerm.fetchone()

def insertPerms(conn, app, appID):

  for pname in app.perms:

    p('insertPerms({0}, {1}, {2})'.format(conn,app,appID))
    perm = queryPerm(conn, pname)

    if perm:
      p("Found existing perm")
      permID = perm['id']
      p("Perm ID: {0}".format(permID))
    else:
      p("Inserting new perm. name: {0}".format(pname))
      insertPerm = conn.execute("INSERT INTO permissions (name) VALUES (?);", (pname,))

      if insertPerm.rowcount < 1:
        e("Error inserting permission to DB")
        return False

      permID = insertPerm.lastrowid
      p("Added with perm ID: {0}".format(permID))
      conn.commit()

    permAssoc = conn.execute("SELECT * FROM app_permissions WHERE perm_id = ? AND app_id = ?;",
        (permID, appID))
    foundPerm = permAssoc.fetchone()

    p("Found Perm Assoc: {0}".format(foundPerm))

    if not foundPerm:
      p("Inserting perm app association")
      insertAppPerm = conn.execute("INSERT INTO app_permissions (perm_id, app_id) VALUES (?,?);",
                      (permID, appID))

      if insertAppPerm.rowcount < 1:
        e("Error inserting app<->perm association to DB")
        return False

      p("Added app<->perm association to DB")
    else:
      p("Perm already associated with app")

  conn.commit()

def insertApp(conn, app):
  existingApp = queryAppDetails(conn, app)

  if existingApp:
    p("App already exists in DB. Skipping")
    return

  saveCerts(conn, app)

  addApp = conn.execute('INSERT INTO apps (id, uappid, pkgname, appname, binhash, dexhash, reshash, manifesthash, source, versionCode, timestamp, shareduserid, apkpath, version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);',
       (app.getID(), app.uappID(), unicode(app.package, 'utf8'), unicode(app.appName, 'utf8'), app.binHash, app.dexHash, app.resHash, app.manifestHash, app.sourceType, app.versionCode, app.parsedOn, unicode(app.sharedUserID, 'utf8'), unicode(app.sourceFile, 'utf8'), unicode(app.version, 'utf8')))

  if addApp.rowcount < 1:
    e("Error inserting app to DB")
    return False
  else:
    p("Added app to DB")

  conn.commit()
  insertPerms(conn, app, app.getID())

def saveCerts(conn, app):
  for c in app.certs:
    existingCert = conn.execute('SELECT * FROM certs WHERE fingerprint = ? AND uappid = ?;',
                                (c.fingerprint, app.uappID()))

    if existingCert.fetchone():
      p("Certificate {0} already in DB. Skipping".format(c))
      continue

    p("Saving Cert Pubkey to DB")
    pubkey = c.pubkey

    p(pubkey.algo)

    if pubkey.algo is "RSA":
      addPubkey = conn.execute('INSERT INTO pubkeys (algo, keybits, modulus, exponent) VALUES (?, ?, ?, ?);',
                              (pubkey.algo, pubkey.bits, pubkey.modulus, pubkey.exponent))
    elif pubkey.algo is "DSA":
      addPubkey = conn.execute('INSERT INTO pubkeys (algo, keybits, groupbits, pub, p, q, g) VALUES (?, ?, ?, ?, ?, ?, ?);',
                                (pubkey.algo, pubkey.keybits, pubkey.groupbits, pubkey.pub, pubkey.p, pubkey.q, pubkey.g))

    if addPubkey.rowcount < 1:
      e("Error inserting pubkey to DB")
      return False

    pubkeyID = addPubkey.lastrowid
    p("Added pubkey to DB with ID {0}".format(pubkeyID))

    formatTime = lambda t : time.mktime(time.strptime(t, '%b %d %H:%M:%S %Y %Z'))

    addCert = conn.execute('INSERT INTO certs (fingerprint, uappid, serial, issuer, subject, notBefore, notAfter, pubkeyID) VALUES (?, ?, ?, ?, ?, ?, ?, ?);',
                           (c.fingerprint, app.uappID(), c.serial, c.issuer, c.subject, formatTime(c.not_before), formatTime(c.not_after), pubkeyID))

    if addCert.rowcount < 1:
      e("Error inserting cert to DB")
      return False

    p("Added cert to DB")
    conn.commit()

if __name__ == '__main__':
  import argparse, sys

  parser = argparse.ArgumentParser()
  parser.add_argument('path',     help='Path to apk file(s) to import & save to the DB')
  parser.add_argument('-v', '--verbose', help='Increase output verbosity',
                      action='store_true')
  parser.add_argument('-d', '--database', help='SQLite3 Database file. Default: ./observatory.db',
                      default='observatory.db')
  args = parser.parse_args()

  if args.verbose:
    verbose = True
    apk_info.verbose = True

  p("Connecting to SQLite3 database {0}".format(args.database))
  conn = connectDB(args.database)

  path = args.path
  inputFiles = []

  if os.path.exists(path) and os.path.isfile(path):
    p("Processing {0} as single file.".format(path))
    inputFiles = [ path ]

  elif os.path.exists(path) and os.path.isdir(path):
    p("Processing {0} as a dir.".format(path))

    inputFiles = findAPKFiles(path)
    if len(inputFiles) < 1:
      sys.exit("No .APK or .apk files found in {0}".format(path))
  else:
      sys.exit("{0} doesn't exist or is not a regular file/directory".format(path))

  p("Processing {0} inputfiles.".format(len(inputFiles)))

  for i in inputFiles:
    try:
      app = apk_info.ObservatoryApp(i)
    except:
      e("Unable to create ObservatoryApp")
      continue

    insertApp(conn, app)
