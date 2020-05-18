from flask import Blueprint, request, jsonify, redirect, make_response

from flaskr.db import IdentityProviderMetadata
from flaskr.saml.auth import AuthenticationManager

blueprint = Blueprint('saml', __name__, url_prefix='/SAML2')


@blueprint.route("/metadata/")
def metadata():
    authentication_manager = AuthenticationManager()
    metadata = authentication_manager.get_metadata()
    response = make_response(metadata, 200)
    response.headers["Content-Type"] = "text/xml"

    return response


@blueprint.route('/idps', methods=['GET'])
def fetch_idps():
    query = request.args.get('q')

    if query:
        query = '%{0}%'.format(query)
        identity_providers = IdentityProviderMetadata.query.filter(IdentityProviderMetadata.display_name.ilike(query))
    else:
        identity_providers = IdentityProviderMetadata.query.all()

    response = map(
        lambda identity_provider: {'value': identity_provider.entity_id, 'text': identity_provider.display_name},
        identity_providers
    )

    return jsonify(response)


@blueprint.route('/POST', methods=('POST',))
def acs_post():
    authentication_manager = AuthenticationManager()

    user = authentication_manager.finish_authentication()

    if not user:
        return 'You are not authenticated', 401

    return redirect(authentication_manager.redirect())

#
#
# @blueprint.route("/logout", methods=["POST"])
# def single_logout_handler():
#     data = request.get_json()
#     if not data:
#         return logout_fail()
#     token = data.get("token")
#     user = get_user(token)
#     if not token or not user:
#         return logout_fail()
#     delete_user(token)
#
#     return (
#         jsonify({"status": "Success", "message": "You've successfully logged out"}),
#         200,
#     )
