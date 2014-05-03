#!/usr/bin/env python

import re, os, fnmatch, sys, hashlib, time
from subprocess import check_output, check_call

import cert_info, newzip
from utils import *

verbose = False

class ObservatoryApp:

  def __init__(self, apkFile=None, sourceType=6):
    self.binHash      = None
    self.dexHash      = None
    self.resHash      = None
    self.manifestHash = None
    self.certs        = []
    self.package      = ''
    self.appName      = ''
    self.versionCode  = None
    self.version      = ''
    self.sharedUserID = ''
    self.perms        = []
    self.sourceType   = None
    self.sourceFile   = None
    self.parsedOn     = None
    self.sourceType   = sourceType

    if apkFile:
      self.parsedOn = int(time.time())
      self.loadFromAPK(apkFile)

  def getID(self):
    appIDParts = [ self.binHash, str(self.sourceType) ]
    return hash(" ".join(appIDParts))

  def uappID(self):
    uappIDParts = [ self.package ]

    for c in self.certs:
      uappIDParts.append(c.fingerprint)

    return hash(" ".join(uappIDParts))

  def loadFromAPK(self, path):
    p("Testing {0} for zippy-ness".format(path))

    if not newzip.is_zipfile(path):
      e("{0} is not a valid zip|apk file".format(path))
      raise Exception('Invalid zip file')

    self.sourceFile = path
    self.parsedOn = os.path.getmtime(self.sourceFile)

    with open(path, 'rb') as apkStream:
      self.binHash = hash(apkStream.read())

    p("APK hash: {0}".format(self.binHash))

    p("Opening zipfile")

    try:
      z = newzip.ZipFile(path, 'r')
      self.dexHash = hash(z.read('classes.dex'))
      p("DEX hash: {0}".format(self.dexHash))

      try:
        self.resHash = hash(z.read('resources.arsc'))
        p("RES hash: {0}".format(self.resHash))
      except KeyError:
        self.resHash = ''
        p("No resources.arsc in this APK")

      self.manifestHash = hash(z.read('AndroidManifest.xml'))
      p("Manifest hash: {0}".format(self.manifestHash))
      z.close()
    except newzip.BadZipfile, (Number, Message):
      e(Message)

    #p(zipfile.error)

    self.certs   = cert_info.fromAPKFile(path)

    if not self.certs or len(self.certs) < 1:
      e("No valid signing certificate found in APK")
      raise Exception('No valid signing certificate')

    p("Signed with {0} Certificates".format(len(self.certs)))
    for c in self.certs:
      p("Certificate: {0}".format(c))
      p("Public Key: {0}".format(c.pubkey))

    p("Dumping badging info")

    try:
      badgingText = check_output(["aapt", "dump", "badging", path])
    except:
      e("Unable to dump badging (likely no AndroidManifest.xml). Skipping APK")
      raise Exception('No valid AndroidManifest.xml')

    p("Dumping AndroidManifest xmltree info")

    try:
      manifestText = check_output(["aapt", "dump", "xmltree", path, "AndroidManifest.xml"])
    except:
      e("Unable to dump xmltree (likely no AndroidManifest.xml). Skipping APK")
      raise Exception('No valid AndroidManifest.xml')

    packageParse = re.search("^package: name='(.*)' versionCode='([0-9]+)' versionName='(.+)'$", badgingText, re.MULTILINE)
    appNameParse = re.search("^application-label(?:-en)?:'(.*)'$", badgingText, re.MULTILINE)

    sharedIDParse = re.search('^\\s*A: android:sharedUserId\\(0x0101000b\\)=\"(.+)\" \\(Raw: \"(?:.+)\"\\)$', manifestText, re.MULTILINE)

    if packageParse:
      self.package     = packageParse.group(1)
      self.versionCode = packageParse.group(2)
      self.version     = packageParse.group(3)
      p("Package: {0} Version: {1} VersionName: {2}".format(self.package,self.versionCode,self.version))
    else:
      e("Unable to parse package details from the aapt badging output")
      raise Exception("Bad package details in aapt badging")

    if appNameParse:
      self.appName = appNameParse.group(1)
      p("App Name: {0}".format(self.appName))
    else:
      e("Unable to parse application name from the aapt badging output")
      raise Exception("Bad application name/label in aapt badging")

    if sharedIDParse:
      self.sharedUserID = sharedIDParse.group(1)
      p("Shared User ID: {0}".format(self.sharedUserID))

    self.perms = []
    permLines = filter(lambda s : s.startswith('uses-permission:'), badgingText.split())
    for l in permLines:
      self.perms.append(l[l.find(':') + 1:].replace('\'', ''))

    p("App Permissions:\n\t{0}".format('\n\t'.join(self.perms)))

  def __str__(self):
    return "[{0}] ID: {1} UAppID: {2}".format(self.package, self.getID(), self.uappID())

def p(message):
  if verbose:
    print("[+] {0}".format(message))

def e(message):
  print("[!] {0}".format(message))

if __name__ == '__main__':
  import argparse, sys
  import apk_save

  parser = argparse.ArgumentParser()
  parser.add_argument('path',     help='Path to APKs to process')
  parser.add_argument('-v', '--verbose', help='Increase output verbosity',
                      action='store_true')
  parser.add_argument('-d', '--database', help='SQLite3 Database file to create. Default: ./observatory.db',
                      default='observatory.db')
  args = parser.parse_args()

  if args.verbose:
    verbose = True

  apk_save.verbose = verbose
  conn = apk_save.connectDB(args.database)

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

  invalid = 0
  for i in inputFiles:
    try:
      app = ObservatoryApp(i)
      apk_save.insertApp(conn, app)

    except:
      invalid = invalid + 1
      e("SKIPPED BAD APK: {0}".format(i))

  if invalid > 0:
    e("SKIPPED {0} APKS".format(str(invalid)))
