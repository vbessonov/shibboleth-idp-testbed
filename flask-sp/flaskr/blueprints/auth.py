import logging

from flask import (
    Blueprint, render_template,
    request, redirect, url_for, jsonify)

from flaskr.saml.auth import AuthenticationManager

_logger = logging.getLogger(__name__)
blueprint = Blueprint('auth', __name__, url_prefix='/auth')


@blueprint.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'GET':
        return render_template('auth/login.html')
    elif request.method == 'POST':
        idp = request.form.get('idp')
        _logger.info('Started authentication process for IdP {0}'.format(idp))

        auth_manager = AuthenticationManager(idp)

        return redirect(auth_manager.start_authentication(request.host_url))


@blueprint.route('/logout', methods=('GET',))
def logout():
    authentication_manager = AuthenticationManager()

    authentication_manager.set_active_idp(None)
    authentication_manager.set_active_user(None)

    return redirect(url_for('auth.login'))


@blueprint.route('/me', methods=('GET',))
def me():
    return jsonify(AuthenticationManager.get_active_user())