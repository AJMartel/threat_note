#!/usr/bin/env python

#
# threat_note v4.0                                      #
# Developed By: Brian Warehime                          #
# Defense Point Security (defpoint.com)                 #
# October 26, 2015                                      #
#

import argparse
import os.path
from app import app


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-H', '--host', default='127.0.0.1', help='Specify the host IP address')
    parser.add_argument('-p', '--port', default=8888, help='Specify port to listen on')
    parser.add_argument('-d', '--debug', default=False, help='Run in debug mode', action='store_true')
    parser.add_argument('-D', '--database', default='threatnote.db', help='Path and name of SQLite database')
    args = parser.parse_args()

    if args.database == 'threatnote.db':
        path = os.path.join(os.getcwd(), args.database)
    else:
        path = os.path.join(args.database)

    print path
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + path

    if not os.path.isfile(path):
        from app import db
        print 'Initializing database'
        db.create_all()

    app.run(host=args.host, port=args.port, debug=args.debug)
