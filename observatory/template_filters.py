from observatory import app
from datetime import datetime

#The observatory database uses a numeric index for the source
#This module provides functions for mapping the index to a name
#or a hex colour for a legend.
sources = [
    "Google Play", #0
    "Amazon",      #1
    "P2P",         #2
    "Contagio",    #3
    "Forum",       #4
    "FDroid",      #5
    "User",        #6
    "Aproov",      #7
    "Mikandi",     #8
    "Genome",      #9
    "VirusShare",  #10
    "ApkStore",    #11
  ]

sourceColours = [
    "#A4C639",
    "#E47911",
    "#000000",
    "#90C",
    "#039",
    "#9CF",
    "#006600",
    "#a05d56",
    "#FF007F",
    "#FF3030",
    "#6b486b",
    "#00FFFF",
  ]

# Thx to this awesome colour gradient generator:
# http://www.herethere.net/~samson/php/color_gradient/
# Used for top 10 permissions on stats page
perm_gradient = [
  '5D51CF', 
  '5961C9', 
  '5571C3', 
  '5181BD', 
  '4E91B7', 
  '4AA1B2', 
  '46B1AC', 
  '43C1A6', 
  '3FD1A0', 
  '3BE19A', 
]

# Used for top 5 signing keys on stats page
key_gradient = [
  '5D51CF', 
  '5571C3', 
  '4E91B7', 
  '46B1AC', 
  '3FD1A0', 
]

@app.template_filter('index2permgradient')
def index_to_perm_gradient(i):
  return "#" + perm_gradient[i]

@app.template_filter('index2keygradient')
def index_to_key_gradient(i):
  return "#" + key_gradient[i]

@app.template_filter('trim')
def trim_str(s, maxlen=22):
  if len(s) > maxlen:
    return s[0:maxlen] + '...'
  else:
    return s

@app.template_filter('todate')
def app_date(t):
  """
    Convert a time stamp from the database to a date string.
  """
  d = datetime.fromtimestamp(t)
  return str(d)

@app.template_filter('src2str')
def src_to_string(s):
  """
    Convert a source ID # from the database to a string name.
  """
  try:
    return sources[s]
  except IndexError:
    return "User"

@app.template_filter('src2colour')
def src_to_colour(s):
  """
    Convert a source ID # from the database to a hex colour code string.
  """
  try:
    return sourceColours[s]
  except IndexError:
    return "#006600"

@app.template_filter("colonhex")
def colon_hex(s):
  return ':'.join([ s[i] + s[i+1] for i in xrange(0, len(s), 2) ])

@app.template_filter('formatPermissionStr')
def format_permission_string(s):
  return s.split(".")[-1].lower()

