import logging
import os

import click
from defusedxml.lxml import fromstring
from flask.cli import with_appcontext
from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser
from onelogin.saml2.utils import OneLogin_Saml2_Utils

from db import IdentityProviderMetadata, get_db


class MetadataManager(object):
    IN_COMMON_METADATA_SERVICE_URL = 'http://md.incommon.org/InCommon/InCommon-metadata-idp-only.xml'
    ENTITY_DESCRIPTOR_XPATH = '//md:EntityDescriptor'
    IDP_DESCRIPTOR_XPATH = './md:IDPSSODescriptor'
    ENTITY_ID_ATTRIBUTE = 'entityID'
    DISPLAY_NAME_XPATH = './md:Extensions/mdui:UIInfo/mdui:DisplayName'

    def __init__(self):
        self._logger = logging.getLogger(__name__)

        OneLogin_Saml2_Constants.NS_PREFIX_MDUI = 'mdui'
        OneLogin_Saml2_Constants.NS_MDUI = 'urn:oasis:names:tc:SAML:metadata:ui'
        OneLogin_Saml2_Constants.NSMAP[OneLogin_Saml2_Constants.NS_PREFIX_MDUI] = OneLogin_Saml2_Constants.NS_MDUI

    def _fetch_metadata(self):
        self._logger.info('Started fetching metadata from InCommon Metadata service')

        metadata = OneLogin_Saml2_IdPMetadataParser.get_metadata(self.IN_COMMON_METADATA_SERVICE_URL)

        self._logger.info('Finished fetching metadata from InCommon Metadata service')

        return metadata

    def _convert_string_to_xml_dom(self, metadata):
        self._logger.info('Started converting string containing IdP metadata into XML DOM')

        metadata_dom = fromstring(metadata, forbid_dtd=True)

        self._logger.info('Finished converting string containing IdP metadata into XML DOM')

        return metadata_dom

    def _parse_metadata_dom(self, metadata_dom):
        entity_descriptor_nodes = OneLogin_Saml2_Utils.query(metadata_dom, self.ENTITY_DESCRIPTOR_XPATH)
        idps = []

        for entity_descriptor_node in entity_descriptor_nodes:
            idp_descriptor_nodes = OneLogin_Saml2_Utils.query(entity_descriptor_node, self.IDP_DESCRIPTOR_XPATH)

            for idp_descriptor_node in idp_descriptor_nodes:
                idp_entity_id = entity_descriptor_node.get(self.ENTITY_ID_ATTRIBUTE, None)
                display_name_node = OneLogin_Saml2_Utils.query(idp_descriptor_node, self.DISPLAY_NAME_XPATH)

                if not display_name_node:
                    continue

                display_name = display_name_node[0].text

                idp = IdentityProviderMetadata(idp_entity_id, display_name, entity_descriptor_node)

                idps.append(idp)

        return idps

    def _fetch_test_idps(self):
        test_idp_metadata_file = os.path.abspath(__name__ + '/../../../shibboleth-idp-testbed/shibboleth-idp/opt/shibboleth-idp/metadata/idp-metadata.xml')

        with open(test_idp_metadata_file) as file:
            metadata = file.read()
            metadata_dom = self._convert_string_to_xml_dom(metadata)

            for idp in self._parse_metadata_dom(metadata_dom):
                yield idp

    def fetch_idps(self):
        test_idps = []

        self._logger.info('Started fetching test IdPs')

        try:
            for idp in self._fetch_test_idps():
                test_idps.append(idp)
        except:
            self._logger.exception('An unexpected error occurred during fetching test IdPs')

        self._logger.info('Successfully fetched {0} test IdP'.format(len(test_idps)))

        self._logger.info('Started fetching IdPs from InCommon Metadata Service')

        in_common_idps = []

        try:
            metadata = self._fetch_metadata()
            metadata_dom = self._convert_string_to_xml_dom(metadata)

            for idp in self._parse_metadata_dom(metadata_dom):
                in_common_idps.append(idp)
        except:
            self._logger.exception(
                'An unexpected exception occurred during fetching IdP metadata from InCommon Metadata service')
            raise

        self._logger.info('Successfully fetched {0} IdPs from In Common Metadata Service'.format(len(in_common_idps)))

        idps = test_idps + in_common_idps

        return idps


def init_metadata():
    click.echo('Deleting the existing metadata...')

    db = get_db()

    idps = IdentityProviderMetadata.query.all()

    for idp in idps:
        db.session.delete(idp)

    db.session.commit()

    click.echo('The existing metadata has been deleted')

    metadata_manager = MetadataManager()

    click.echo('Fetching metadata...')

    idps = metadata_manager.fetch_idps()

    click.echo('Fetched {0} IdPs'.format(len(idps)))

    db.session.add_all(idps)
    db.session.commit()

    click.echo('Saved {0} IdPs to the database'.format(len(idps)))


@click.command('init-metadata')
@with_appcontext
def init_metadata_command():
    """Adds metadata to the database"""

    init_metadata()


def init_app(app):
    # app.before_first_request(init_metadata)
    app.cli.add_command(init_metadata_command)
