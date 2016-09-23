#!/usr/bin/env python

#
# threat_note v3.0                                      #
# Developed By: Brian Warehime                          #
# Defense Point Security (defpoint.com)                 #
# October 26, 2015                                      #
#

import argparse
import os.path
from app import app


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-H', '--host', default="127.0.0.1", help="Specify the host IP address")
    parser.add_argument('-p', '--port', default=8888, help="Specify port to listen on")
    parser.add_argument('-d', '--debug', default=False, help="Run in debug mode", action="store_true")
    parser.add_argument('-b', '--database', default="threatnote.db", help="Path to sqlite database - Not Implemented")
    args = parser.parse_args()

    database = 'test.db'

    if args.database:
        database = args.database
    path = os.path.join(os.getcwd(), 'tmp', database)
    if os.path.isfile(path):
        from app import db
        print 'Initializing database'
        db.create_all()

    app.run(host=args.host, port=args.port, debug=args.debug)
