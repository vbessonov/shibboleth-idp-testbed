import logging
import os

from flask import Flask

import db
from saml import metadata
from blueprints import auth, saml, home


def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)

    logging.basicConfig(level=logging.INFO)

    app.config.from_object('config.Config')

    if os.getenv('APPLICATION_SETTINGS'):
        app.config.from_envvar('APPLICATION_SETTINGS')

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    db.init_app(app)
    metadata.init_app(app)

    app.register_blueprint(home.blueprint)
    print('Home')
    app.register_blueprint(auth.blueprint)
    app.register_blueprint(saml.blueprint)

    return app
