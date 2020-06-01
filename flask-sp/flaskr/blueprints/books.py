import urlparse

from flask import Blueprint, redirect, request, url_for

from flaskr.saml.auth import AuthenticationManager

blueprint = Blueprint('books', __name__, url_prefix='/books')


@blueprint.route('/<book>', methods=('GET',))
def index(book):
    auth_manager = AuthenticationManager('http://idp.hilbertteam.net/idp/shibboleth')

    authentication_manager = AuthenticationManager()

    authenticated = True

    while True:
        if request.referrer:
            parse_result = urlparse.urlparse(request.referrer)

            if 'idp.hilbertteam.net' in parse_result.netloc:
                break

        user = authentication_manager.finish_authentication()

        if user:
            break

        authenticated = False
        break

    if authenticated:
        return redirect(url_for('static', filename='books/' + book, _external=True))

    return redirect(auth_manager.start_authentication(request.url))


