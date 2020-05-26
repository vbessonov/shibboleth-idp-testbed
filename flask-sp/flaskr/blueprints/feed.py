from flask import Blueprint, render_template, make_response

blueprint = Blueprint('feed', __name__, url_prefix='/feed')


@blueprint.route('/', methods=('GET',))
def index():
    response = make_response(render_template('feed/index.xml'), 200)
    response.headers['Content-Type'] = 'application/atom+xml'

    return response
