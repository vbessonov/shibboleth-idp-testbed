import os
from urlparse import urlparse

from flask import (
    Flask,
    request,
    render_template,
    redirect,
    session,
    make_response,
    jsonify,
)


from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils

app = Flask(__name__)
app.config["SECRET_KEY"] = "onelogindemopytoolkit"
app.config["SAML_PATH"] = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "saml"
)


def init_saml_auth(req):
    auth = OneLogin_Saml2_Auth(req, custom_base_path=app.config["SAML_PATH"])
    return auth


def prepare_flask_request(request):
    # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
    url_data = urlparse(request.url)
    return {
        "https": "on" if request.scheme == "https" else "off",
        "http_host": request.host,
        "server_port": url_data.port,
        "script_name": request.path,
        "get_data": request.args.copy(),
        # Uncomment if using ADFS as IdP, https://github.com/onelogin/python-saml/pull/144
        # 'lowercase_urlencoding': True,
        "post_data": request.form.copy(),
    }


@app.route("/")
def index():
    errors = []
    error_reason = None
    not_auth_warn = False
    success_slo = False
    attributes = False
    paint_logout = False

    return render_template(
        "index.html",
        errors=errors,
        error_reason=error_reason,
        not_auth_warn=not_auth_warn,
        success_slo=success_slo,
        attributes=attributes,
        paint_logout=paint_logout,
    )


@app.route("/login/<provider_id>")
def saml_login(provider_id):
    # for now there is only one provider so we log you in with that
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    return redirect(auth.login(request.host_url))


users_map = {}


def set_user(auth):
    name = auth.get_attributes()['urn:oid:0.9.2342.19200300.100.1.1'][0]
    total_users = len(users_map.keys())
    user = {
        "number": total_users + 1,
        "name": name,
        "token": name,
        "attributes": auth.get_attributes(),
        "samlData": {
            "nameId": auth.get_nameid(),
            "nameIdFormat": auth.get_nameid_format(),
            "nameIdNameQualifier": auth.get_nameid_nq(),
            "nameIdSPNameQualifier": auth.get_nameid_spnq(),
            "sessionIndex": auth.get_session_index(),
        },
    }
    users_map[name] = user


def get_user(name):
    return users_map.get(name)


def delete_user(name):
    return users_map.pop(name, None)


def get_all_users():
    return users_map


@app.route("/saml-acs", methods=["POST"])
def saml_acs():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    request_id = None
    if "AuthNRequestID" in session:
        request_id = session["AuthNRequestID"]
    auth.process_response(request_id=request_id)
    errors = auth.get_errors()
    not_auth_warn = not auth.is_authenticated()
    if not_auth_warn:
        return "You are not authenticated", 401
    if len(errors) == 0:
        if "AuthNRequestID" in session:
            del session["AuthNRequestID"]

        # set the user. This is where we would normally create a
        # JWT for the user and save that in memory
        set_user(auth)

        # send success message with the auth token in header
        auth_token = get_user(auth.get_attributes()['urn:oid:0.9.2342.19200300.100.1.1'][0])["token"]

        self_url = OneLogin_Saml2_Utils.get_self_url(req)
        redirect_path = "/"
        if "RelayState" in request.form and self_url != request.form["RelayState"]:
            redirect_path = request.form["RelayState"]

        # we either redirect to the passed url, or to the home page
        # either way with the token in a query param
        redirect_url = auth.redirect_to(redirect_path, {"token": auth_token})
        return redirect(redirect_url)

    elif auth.get_settings().is_debug_active():
        error_reason = auth.get_last_error_reason()
        print("ERROR REASON")
        print(error_reason)

    return "Auth error", 401


def unauthorized():
    resp = {
        "message": "Unauthorized",
        "data": {
            "providers": [{"id": "test-provider", "name": "Test Identity Provider"}]
        },
    }
    return make_response(jsonify(resp), 401)


@app.route("/me")
def protected_route():
    bearer = request.headers.get("Authorization")
    if not bearer:
        return unauthorized()
    token = bearer.split(" ")[1]
    if not token:
        return unauthorized()
    user = get_user(token)
    if not user:
        return unauthorized()
    # otherwise you're authenticated, return the user
    return jsonify(user)


@app.route("/users")
def users():
    return jsonify(get_all_users())


@app.route("/metadata/")
def metadata():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    settings = auth.get_settings()
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)

    if len(errors) == 0:
        resp = make_response(metadata, 200)
        resp.headers["Content-Type"] = "text/xml"
    else:
        resp = make_response(", ".join(errors), 500)
    return resp


def logout_fail():
    return (
        jsonify({"status": "Error", "message": "Provide a valid token to log out",}),
        400,
    )


# simply delete the user from the users_map
# and return a success message
@app.route("/logout", methods=["POST"])
def single_logout_handler():
    data = request.get_json()
    if not data:
        return logout_fail()
    token = data.get("token")
    user = get_user(token)
    if not token or not user:
        return logout_fail()
    delete_user(token)

    return (
        jsonify({"status": "Success", "message": "You've successfully logged out"}),
        200,
    )


if __name__ == "__main__":
    app.config["ENV"] = "development"
    app.config["SAML_PATH"] = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "saml"
    )
    app.run(host="0.0.0.0", port=8000, debug=True)