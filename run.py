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
    parser.add_argument('-db', '--database', help="Path to sqlite database - Not Implemented")
    args = parser.parse_args()

    if not os.path.isfile(os.path.join(os.getcwd(), 'tmp', 'test.db')):
        from app import db
        db.create_all()

    app.run(host=args.host, port=args.port, debug=args.debug)