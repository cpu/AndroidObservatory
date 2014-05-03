import sqlite3

from contextlib  import closing
from flask       import g
from observatory import app

@app.before_request
def before_request():
  g.db = connect_db()

@app.teardown_request
def teardown_request(exception):
  if hasattr(g, 'db'):
    g.db.close()

def connect_db():
  return sqlite3.connect(app.config['DATABASE'])

def query_db(query, args=(), one=False):
  cur = g.db.execute(query, args)
  rv = [ dict((cur.description[idx][0], value)
           for idx, value in enumerate(row)) for row in cur.fetchall() ]
  return (rv[0] if rv else None) if one else rv

def get_count(query, args=()):
  return g.db.execute(query, args).fetchone()[0]
