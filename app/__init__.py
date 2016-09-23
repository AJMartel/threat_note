from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
#from libs.API import tn_api
import os


#
# Configuration #
#

app = Flask(__name__)
app.config['SECRET_KEY'] = 'yek_terces'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.getcwd(), 'tmp', 'test.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.debug = True
app.template_debug = True

db = SQLAlchemy(app)

lm = LoginManager()
lm.init_app(app)
lm.login_view = 'login'

#app.register_blueprint(tn_api)

from app import views, models
