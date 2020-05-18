from flask import Blueprint, redirect, url_for, render_template

from flaskr.saml.auth import AuthenticationManager

blueprint = Blueprint('home', __name__, url_prefix='/')


@blueprint.route('/', methods=('GET',))
def index():
    active_user = AuthenticationManager.get_active_user()

    if not active_user:
        return redirect(url_for('auth.login'))
    else:
        return render_template('home/index.html', active_user=active_user)
