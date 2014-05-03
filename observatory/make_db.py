#!/usr/bin/env python

import sqlite3

appsTable = """
CREATE TABLE IF NOT EXISTS apps (
  id TEXT PRIMARY KEY,
  uappid TEXT,
  pkgname TEXT,
  appname TEXT,
  binhash TEXT,
  dexhash TEXT,
  reshash TEXT,
  manifesthash TEXT,
  source INTEGER,
  versionCode INTEGER,
  timestamp INTEGER,
  shareduserid TEXT DEFAULT '',
  apkpath TEXT,
  version TEXT
);
"""

permsTable = """
CREATE TABLE IF NOT EXISTS permissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE
);
"""

permsJoinTable = """
CREATE TABLE IF NOT EXISTS app_permissions(
  perm_id INTEGER,
  app_id TEXT,
  PRIMARY KEY(perm_id, app_id),
  FOREIGN KEY(perm_id) REFERENCES permissions(id),
  FOREIGN KEY(app_id) REFERENCES apps(id)
);
"""

certsTable = """
CREATE TABLE IF NOT EXISTS certs (
  fingerprint TEXT,
  uappid TEXT,
  serial TEXT,
  issuer TEXT,
  subject TEXT,
  notBefore INTEGER,
  notAfter INTEGER,
  pubkeyID INTEGER,
  PRIMARY KEY(fingerprint, uappid),
  FOREIGN KEY(pubkeyID) REFERENCES pubkeys(id)
);
"""

pubkeyTable = """
CREATE TABLE IF NOT EXISTS pubkeys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  algo TEXT,
  keybits TEXT,
  groupbits TEXT,
  modulus TEXT,
  exponent TEXT,
  pub TEXT,
  p TEXT,
  q TEXT,
  g TEXT
);
"""

fullTable = """
CREATE VIEW IF NOT EXISTS full AS select * FROM apps,certs WHERE apps.uappid=certs.uappid;
"""

permFullTable = """
CREATE VIEW IF NOT EXISTS perm_full AS SELECT apps.pkgname AS app, permissions.name AS p_name
FROM permissions, app_permissions, apps
WHERE app_permissions.perm_id = permissions.id AND app_permissions.app_id = apps.id;
"""

def p(message):
  print("[+] {0}".format(message))

def e(message):
  print("[!] {0}".format(message))

def connectDB(dbFile):
  conn = sqlite3.connect(dbFile)
  conn.row_factory = sqlite3.Row
  return conn

if __name__ == '__main__':
  import argparse, sys

  parser = argparse.ArgumentParser()
  parser.add_argument('-d', '--database', help='SQLite3 Database file to create. Default: ./observatory.db',
                      default='observatory.db')
  args = parser.parse_args()

  p("Connecting to SQLite3 database {0}".format(args.database))
  conn = connectDB(args.database)
  c    = conn.cursor()

  c.execute(permsTable)
  c.execute(pubkeyTable)
  c.execute(certsTable)
  c.execute(appsTable)
  c.execute(permsJoinTable)
  c.execute(fullTable)
  c.execute(permFullTable)
