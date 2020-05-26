from flask import Blueprint, redirect, request, url_for

from flaskr.saml.auth import AuthenticationManager

blueprint = Blueprint('books', __name__, url_prefix='/books')


@blueprint.route('/<book>', methods=('GET',))
def index(book):
    auth_manager = AuthenticationManager('http://idp.hilbertteam.net/idp/shibboleth')

    if not auth_manager.get_active_user():
        return redirect(auth_manager.start_authentication(request.url))
    else:
        return redirect(url_for('static', filename='books/' + book, _external=True))
