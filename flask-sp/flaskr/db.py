import click
import sqlalchemy
from defusedxml.lxml import fromstring, tostring
from flask import current_app, g
from flask.cli import with_appcontext
from flask_sqlalchemy import SQLAlchemy
from lxml import etree as _etree

_db = SQLAlchemy()


class XMLType(sqlalchemy.types.UserDefinedType):
    def get_col_spec(self):
        return 'XML'

    def bind_processor(self, dialect):
        def process(value):
            if value is not None:
                if isinstance(value, str):
                    return value
                else:
                    return tostring(value)
            else:
                return None
        return process

    def result_processor(self, dialect, coltype):
        parser = _etree.XMLParser(encoding='utf-8', recover=True)

        def process(value):
            if value is not None:
                value = fromstring(value, parser=parser, forbid_dtd=True)
                return value

        return process


class IdentityProviderMetadata(_db.Model):
    __tablename__ = 'idps'

    id = _db.Column(_db.Integer, primary_key=True)
    entity_id = _db.Column(_db.String(255), unique=True, nullable=False)
    display_name = _db.Column(_db.String(255), nullable=False)
    dom = _db.Column(XMLType, nullable=False)

    def __init__(self, entity_id, display_name, dom):
        self.entity_id = entity_id
        self.display_name = display_name
        self.dom = dom

    def __repr__(self):
        return '<IdP %r>' % self.entity_id


@click.command('recreate-tables')
@with_appcontext
def recreate_tables_command():
    """Clears the existing data and creates new tables"""

    _db.drop_all()
    _db.create_all()

    click.echo('Initialized the database')


def get_db():
    if 'db' not in g:
        _db.init_app(current_app)
        g.db = _db

    return g.db


def close_db(e=None):
    # current_db = g.pop('db', None)
    #
    # if current_db is not None:
    #     current_db.close()
    pass


def init_app(app):
    _db.init_app(app)
    app.teardown_appcontext(close_db)
    app.cli.add_command(recreate_tables_command)
