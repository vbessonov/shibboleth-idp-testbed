import logging
from urlparse import urlparse

from flask import current_app, abort, session, request, url_for
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils

from flaskr.db import IdentityProviderMetadata


class AuthenticationManager(object):
    ACTIVE_IDP_ENTITY_ID_SESSION_KEY = 'ACTIVE_IDP_ENTITY_ID'
    ACTIVE_USER_SESSION_KEY = 'ACTIVE_USER'

    FIRST_NAME_ATTRIBUTE = 'urn:oid:2.5.4.42'
    LAST_NAME_ATTRIBUTE = 'urn:oid:2.5.4.4'
    MAIL_ATTRIBUTE = 'urn:oid:0.9.2342.19200300.100.1.3'
    UID_ATTRIBUTE = 'urn:oid:0.9.2342.19200300.100.1.1'

    def __init__(self, idp_entity_id=None):
        self._logger = logging.getLogger(__name__)

        self._idp_entity_id = idp_entity_id
        self._auth_object = None

    def _parse(
            self,
            dom,
            required_sso_binding=OneLogin_Saml2_Constants.BINDING_HTTP_REDIRECT,
            required_slo_binding=OneLogin_Saml2_Constants.BINDING_HTTP_REDIRECT,
            entity_id=None):
        data = {}
        idp_entity_id = want_authn_requests_signed = idp_name_id_format = idp_sso_url = idp_slo_url = certs = None
        entity_descriptor_node = dom

        idp_descriptor_nodes = OneLogin_Saml2_Utils.query(entity_descriptor_node, './md:IDPSSODescriptor')
        if len(idp_descriptor_nodes) > 0:
            idp_descriptor_node = idp_descriptor_nodes[0]

            idp_entity_id = entity_descriptor_node.get('entityID', None)

            want_authn_requests_signed = entity_descriptor_node.get('WantAuthnRequestsSigned', None)

            name_id_format_nodes = OneLogin_Saml2_Utils.query(idp_descriptor_node, './md:NameIDFormat')
            if len(name_id_format_nodes) > 0:
                idp_name_id_format = OneLogin_Saml2_Utils.element_text(name_id_format_nodes[0])

            sso_nodes = OneLogin_Saml2_Utils.query(
                idp_descriptor_node,
                "./md:SingleSignOnService[@Binding='%s']" % required_sso_binding
            )

            if len(sso_nodes) > 0:
                idp_sso_url = sso_nodes[0].get('Location', None)

            slo_nodes = OneLogin_Saml2_Utils.query(
                idp_descriptor_node,
                "./md:SingleLogoutService[@Binding='%s']" % required_slo_binding
            )
            if len(slo_nodes) > 0:
                idp_slo_url = slo_nodes[0].get('Location', None)

            signing_nodes = OneLogin_Saml2_Utils.query(
                idp_descriptor_node,
                "./md:KeyDescriptor[not(contains(@use, 'encryption'))]/ds:KeyInfo/ds:X509Data/ds:X509Certificate")
            encryption_nodes = OneLogin_Saml2_Utils.query(
                idp_descriptor_node,
                "./md:KeyDescriptor[not(contains(@use, 'signing'))]/ds:KeyInfo/ds:X509Data/ds:X509Certificate")

            if len(signing_nodes) > 0 or len(encryption_nodes) > 0:
                certs = {}
                if len(signing_nodes) > 0:
                    certs['signing'] = []
                    for cert_node in signing_nodes:
                        certs['signing'].append(''.join(OneLogin_Saml2_Utils.element_text(cert_node).split()))
                if len(encryption_nodes) > 0:
                    certs['encryption'] = []
                    for cert_node in encryption_nodes:
                        certs['encryption'].append(''.join(OneLogin_Saml2_Utils.element_text(cert_node).split()))

            data['idp'] = {}

            if idp_entity_id is not None:
                data['idp']['entityId'] = idp_entity_id

            if idp_sso_url is not None:
                data['idp']['singleSignOnService'] = {}
                data['idp']['singleSignOnService']['url'] = idp_sso_url
                data['idp']['singleSignOnService']['binding'] = required_sso_binding

            if idp_slo_url is not None:
                data['idp']['singleLogoutService'] = {}
                data['idp']['singleLogoutService']['url'] = idp_slo_url
                data['idp']['singleLogoutService']['binding'] = required_slo_binding

            if certs is not None:
                if (len(certs) == 1 and
                    (('signing' in certs and len(certs['signing']) == 1) or
                     ('encryption' in certs and len(certs['encryption']) == 1))) or \
                        (('signing' in certs and len(certs['signing']) == 1) and
                         ('encryption' in certs and len(certs['encryption']) == 1 and
                          certs['signing'][0] == certs['encryption'][0])):
                    if 'signing' in certs:
                        data['idp']['x509cert'] = certs['signing'][0]
                    else:
                        data['idp']['x509cert'] = certs['encryption'][0]
                else:
                    data['idp']['x509certMulti'] = certs

            if want_authn_requests_signed is not None:
                data['security'] = {}
                data['security']['authnRequestsSigned'] = want_authn_requests_signed

            if idp_name_id_format:
                data['sp'] = {}
                data['sp']['NameIDFormat'] = idp_name_id_format
        return data

    def _get_idp(self):
        if self._idp_entity_id:
            return self.get_idp(self._idp_entity_id)

        idp = self.get_active_idp()

        return idp

    def _get_settings(self):
        settings = OneLogin_Saml2_Settings(
            custom_base_path=current_app.config["SAML_PATH"],
            sp_validation_only=True
        )
        idp = self._get_idp()

        if idp:
            idp_settings = self._parse(idp.dom)
            common_settings = {
                'sp': settings.get_sp_data(),
                'idp': idp_settings['idp']
            }

            return common_settings
        else:
            return {
                'sp': settings.get_sp_data()
            }

    def _create_auth_object(self):
        request_data = self.get_request_data()
        settings = self._get_settings()
        auth = OneLogin_Saml2_Auth(request_data, old_settings=settings)

        return auth

    def _get_auth_object(self):
        if not self._auth_object:
            self._auth_object = self._create_auth_object()

        return self._auth_object

    def start_authentication(self, return_to):
        auth = self._create_auth_object()
        idp = self._get_idp()

        self.set_active_idp(idp)

        return auth.login(return_to)

    def finish_authentication(self):
        idp = self._get_idp()

        if not idp:
            return False

        request_data = self.get_request_data()

        if 'post_data' not in request_data or 'SAMLResponse' not in request_data['post_data']:
            return False

        auth = self._create_auth_object()
        auth.process_response()

        authenticated = auth.is_authenticated()

        if authenticated:
            attributes = auth.get_attributes()
            user = {
                'uid': attributes[self.UID_ATTRIBUTE][0],
                'first_name': attributes[self.FIRST_NAME_ATTRIBUTE][0],
                'last_name': attributes[self.LAST_NAME_ATTRIBUTE][0],
                'mail': attributes[self.MAIL_ATTRIBUTE][0]
            }

            self.set_active_user(user)

            return user

        return None

    def start_logout(self):
        auth_object = self._create_auth_object()
        url = auth_object.logout(url_for('auth.login'))

        return url

    def redirect(self):
        auth_object = self._create_auth_object()
        request_data = self.get_request_data()
        self_url = OneLogin_Saml2_Utils.get_self_url(request_data)
        redirect_path = "/"

        if "RelayState" in request.form and self_url != request.form["RelayState"]:
            redirect_path = request.form["RelayState"]

        return auth_object.redirect_to(redirect_path)

    def get_metadata(self):
        settings = OneLogin_Saml2_Settings(
            custom_base_path=current_app.config["SAML_PATH"],
            sp_validation_only=True
        )

        return settings.get_sp_metadata()


    @staticmethod
    def get_request_data():
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

    @staticmethod
    def get_idp(idp_entity_id):
        idp = IdentityProviderMetadata.query.filter(IdentityProviderMetadata.entity_id == idp_entity_id).one()

        if not idp:
            abort(404)

        return idp

    @staticmethod
    def get_active_idp():
        idp_entity_id = session.get(AuthenticationManager.ACTIVE_IDP_ENTITY_ID_SESSION_KEY)

        if not idp_entity_id:
            return None

        idp = AuthenticationManager.get_idp(idp_entity_id)

        return idp

    @staticmethod
    def set_active_idp(idp):
        if idp:
            session[AuthenticationManager.ACTIVE_IDP_ENTITY_ID_SESSION_KEY] = idp.entity_id
        else:
            del session[AuthenticationManager.ACTIVE_IDP_ENTITY_ID_SESSION_KEY]

    @staticmethod
    def get_active_user():
        return session.get(AuthenticationManager.ACTIVE_USER_SESSION_KEY, None)

    @staticmethod
    def set_active_user(user):
        if user:
            session[AuthenticationManager.ACTIVE_USER_SESSION_KEY] = user
        else:
            del session[AuthenticationManager.ACTIVE_USER_SESSION_KEY]
