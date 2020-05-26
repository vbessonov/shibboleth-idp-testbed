import logging
import os

from flask import Flask

from flaskr.blueprints import feed


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)

    logging.basicConfig(level=logging.INFO)

    app.config.from_object('flaskr.config.Config')

    if os.getenv('APPLICATION_SETTINGS'):
        app.config.from_envvar('APPLICATION_SETTINGS')

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    app.register_blueprint(feed.blueprint)

    return app
