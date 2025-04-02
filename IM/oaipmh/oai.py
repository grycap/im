#
# IM - Infrastructure Manager
# Copyright (C) 2024 - GRyCAP - Universitat Politecnica de Valencia
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
from lxml import etree  # nosec
from datetime import datetime, timezone
from IM.oaipmh.errors import Errors


class OAI():

    def __init__(self, repo_name, repo_base_url, repo_description,
                 repo_identifier_base_url=None,
                 earliest_datestamp="2000-01-01", datestamp_granularity="YYYY-MM-DD",
                 repo_admin_email="admin@localhost", ):
        self.repository_name = repo_name
        self.repository_base_url = repo_base_url
        self.repository_description = repo_description
        self.earliest_datestamp = earliest_datestamp
        self.datestamp_granularity = datestamp_granularity
        self.repository_admin_email = repo_admin_email
        self.repository_deleted_records = "no"
        self.repository_protocol_version = "2.0"
        self.repository_indentifier_base_url = repo_identifier_base_url

        self.valid_metadata_formats = ['oai_dc', 'oai_openaire', 'oai_datacite']

        self.formats = [
            {
                'metadataPrefix': 'oai_dc',
                'schema': 'http://www.openarchives.org/OAI/2.0/oai_dc.xsd',
                'metadataNamespace': 'http://www.openarchives.org/OAI/2.0/oai_dc/',
            },
            {
                'metadataPrefix': 'oai_openaire',
                'schema': 'https://www.openaire.eu/schema/1.0/oaf-1.0.xsd',
                'metadataNamespace': 'http://namespace.openaire.eu/schema/oaire/',
            },
            {
                'metadataPrefix': 'oai_datacite',
                'schema': 'https://schema.datacite.org/meta/kernel-4.3/metadata.xsd',
                'metadataNamespace': 'http://datacite.org/schema/kernel-4',
            },
        ]

    @staticmethod
    def baseXMLTree():
        root = etree.Element('OAI-PMH')

        # Register the XML namespace for xsi
        etree.register_namespace('xsi', 'http://www.w3.org/2001/XMLSchema-instance')

        # Set the xsi:schemaLocation attribute
        root.set('{http://www.w3.org/2001/XMLSchema-instance}schemaLocation',
                 'http://www.openarchives.org/OAI/2.0/ http://www.openarchives.org/OAI/2.0/OAI-PMH.xsd')

        root.set('xmlns', 'http://www.openarchives.org/OAI/2.0/')

        responseDate = etree.SubElement(root, 'responseDate')
        current_datetime = datetime.now(timezone.utc)
        response_date = current_datetime.strftime("%Y-%m-%dT%H:%M:%SZ")
        responseDate.text = response_date

        return root

    def getRecord(self, root, metadata_dict, verb, identifier, metadata_prefix):
        self.addRequestElement(root, verb=verb, identifier=identifier, metadata_prefix=metadata_prefix)

        if not identifier or not metadata_prefix:
            error_element = Errors.badArgument()
            root.append(error_element)
            return etree.tostring(root, pretty_print=True, encoding='unicode')

        if not self.validMetadataPrefix(metadata_prefix):
            error_element = Errors.cannotDisseminateFormat()
            root.append(error_element)
            return etree.tostring(root, pretty_print=True, encoding='unicode')

        record_data = self.recordByIdentifier(metadata_dict, identifier)
        if not record_data:
            error_element = Errors.idDoesNotExist()
            root.append(error_element)
            return etree.tostring(root, pretty_print=True, encoding='unicode')

        get_record_element = etree.SubElement(root, 'GetRecord')
        record = etree.SubElement(get_record_element, 'record')

        header = etree.SubElement(record, 'header')

        identifier_element = etree.SubElement(header, 'identifier')
        identifier_element.text = identifier
        datestamp_element = etree.SubElement(header, 'datestamp')
        datestamp_element.text = self.earliest_datestamp
        if record_data.get('creation_date'):
            datestamp_element.text = record_data.get('creation_date').strftime("%Y-%m-%d")

        metadata_element = etree.SubElement(record, 'metadata')

        metadata_element.append(self.mapRecord(record_data, metadata_prefix))

        return etree.tostring(root, pretty_print=True, encoding='unicode')

    def identify(self, root, verb):
        self.addRequestElement(root, verb)
        identify_element = etree.SubElement(root, 'Identify')
        self.addIdentifyElements(identify_element)

        return etree.tostring(root, pretty_print=True, encoding='unicode')

    def filterIdentifiers(self, metadata_dict, from_date, until_date):
        if from_date is not None:
            from_date_dt = self.isValidDate(from_date)
        if until_date is not None:
            until_date_dt = self.isValidDate(until_date)

        # Filter identifiers based on the date range specified by from_date and until_date
        filtered_identifiers = list(metadata_dict.keys())

        if from_date is not None or until_date is not None:
            filtered_identifiers = []
            for record_identifier, record_data in metadata_dict.items():
                if record_data.get("creation_date"):
                    record_date = datetime.combine(record_data.get("creation_date"), datetime.min.time())
                else:
                    # Convert the date string to a datetime object
                    record_date = datetime.strptime(self.earliest_datestamp, "%Y-%m-%d")

                if (from_date is None or record_date >= from_date_dt) and \
                        (until_date is None or record_date <= until_date_dt):
                    filtered_identifiers.append(record_identifier)

        return filtered_identifiers

    def listIdentifiers(self, root, metadata_dict, verb, metadata_prefix, from_date=None,
                        until_date=None, set_spec=None, resumption_token=None):
        self.addRequestElement(root, verb, metadata_prefix=metadata_prefix, from_date=from_date,
                               until_date=until_date, set_spec=None, resumption_token=resumption_token)

        if resumption_token is not None:
            error_element = Errors.badResumptionToken()
            root.append(error_element)
            return etree.tostring(root, pretty_print=True, encoding='unicode')

        if set_spec is not None:
            error_element = Errors.noSetHierarchy()
            root.append(error_element)
            return etree.tostring(root, pretty_print=True, encoding='unicode')

        # Check the validity of "from" and "until" parameters
        valid_from_date = from_date is None or self.isValidDate(from_date)
        valid_until_date = until_date is None or self.isValidDate(until_date)

        if not metadata_prefix or not valid_from_date or not valid_until_date:
            error_element = Errors.badArgument()
            root.append(error_element)
            return etree.tostring(root, pretty_print=True, encoding='unicode')

        if not self.validMetadataPrefix(metadata_prefix):
            error_element = Errors.cannotDisseminateFormat()
            root.append(error_element)
            return etree.tostring(root, pretty_print=True, encoding='unicode')

        filtered_identifiers = self.filterIdentifiers(metadata_dict, from_date, until_date)

        # Create the ListIdentifiers element
        list_identifiers_element = etree.Element('ListIdentifiers')

        if not metadata_dict or filtered_identifiers == []:
            # If the metadata_dict is empty, add a noRecordsMatch error
            error_element = Errors.noRecordsMatch()
            root.append(error_element)
            return etree.tostring(root, pretty_print=True, encoding='unicode')
        else:
            for record_identifier in filtered_identifiers:
                header_element = etree.Element('header')
                identifier_element = etree.Element('identifier')
                identifier_element.text = f'{self.repository_indentifier_base_url}{record_identifier}'
                datestamp_element = etree.Element('datestamp')
                datestamp_element.text = self.earliest_datestamp
                if metadata_dict[record_identifier].get('creation_date'):
                    datestamp_element.text = metadata_dict[record_identifier].get('creation_date').strftime("%Y-%m-%d")

                header_element.append(identifier_element)
                header_element.append(datestamp_element)
                list_identifiers_element.append(header_element)

        root.append(list_identifiers_element)

        return etree.tostring(root, pretty_print=True, encoding='unicode')

    def listMetadataFormats(self, root, metadata_dict, verb, identifier=None):
        self.addRequestElement(root, verb, identifier=identifier)

        if identifier:
            record_data = self.recordByIdentifier(metadata_dict, identifier)

            if record_data is None:
                error_element = Errors.idDoesNotExist()
                root.append(error_element)

                return etree.tostring(root, pretty_print=True, encoding='unicode')

        list_metadata_formats_element = etree.SubElement(root, 'ListMetadataFormats')

        metadata_formats = self.formats

        # Iterate through your metadata formats metadata_formats list
        for format_info in metadata_formats:
            metadata_format_element = etree.SubElement(list_metadata_formats_element, 'metadataFormat')

            self.addMetadataFormatElement(metadata_format_element, format_info)

        return etree.tostring(root, pretty_print=True, encoding='unicode')

    def listRecords(self, root, metadata_dict, verb, metadata_prefix, from_date=None,
                    until_date=None, set_spec=None, resumption_token=None):
        self.addRequestElement(root, verb, metadata_prefix=metadata_prefix, from_date=from_date,
                               until_date=until_date, set_spec=set_spec, resumption_token=resumption_token)

        if resumption_token is not None:
            error_element = Errors.badResumptionToken()
            root.append(error_element)
            return etree.tostring(root, pretty_print=True, encoding='unicode')

        if set_spec is not None:
            error_element = Errors.noSetHierarchy()
            root.append(error_element)
            return etree.tostring(root, pretty_print=True, encoding='unicode')

        # Check the validity of "from" and "until" parameters
        valid_from_date = from_date is None or self.isValidDate(from_date)
        valid_until_date = until_date is None or self.isValidDate(until_date)

        if not metadata_prefix or not valid_from_date or not valid_until_date:
            error_element = Errors.badArgument()
            root.append(error_element)
            return etree.tostring(root, pretty_print=True, encoding='unicode')

        if not self.validMetadataPrefix(metadata_prefix):
            error_element = Errors.cannotDisseminateFormat()
            root.append(error_element)
            return etree.tostring(root, pretty_print=True, encoding='unicode')

        filtered_identifiers = self.filterIdentifiers(metadata_dict, from_date, until_date)

        list_records_element = etree.Element('ListRecords')

        if not metadata_dict or filtered_identifiers == []:
            # If the metadata_dict dictionary is empty
            error_element = Errors.noRecordsMatch()
            root.append(error_element)
            return etree.tostring(root, pretty_print=True, encoding='unicode')
        else:
            for record_name in filtered_identifiers:
                record_element = etree.Element('record')

                header_element = etree.Element('header')
                identifier_element = etree.Element('identifier')
                identifier_element.text = f'{self.repository_indentifier_base_url}{record_name}'
                datestamp_element = etree.Element('datestamp')
                datestamp_element.text = 'datestamp'
                if metadata_dict[record_name].get('creation_date'):
                    datestamp_element.text = metadata_dict[record_name].get('creation_date').strftime("%Y-%m-%d")

                metadata_element = etree.Element('metadata')

                # Append the generated XML to the metadata element
                metadata_element.append(self.mapRecord(metadata_dict[record_name], metadata_prefix))

                header_element.append(identifier_element)
                header_element.append(datestamp_element)
                record_element.append(header_element)
                record_element.append(metadata_element)

                list_records_element.append(record_element)

        root.append(list_records_element)

        return etree.tostring(root, pretty_print=True, encoding='unicode')

    def listSets(self, root, verb, set_spec=False, resumption_token=None):
        self.addRequestElement(root, verb)

        error_element = Errors.noSetHierarchy()
        root.append(error_element)

        return etree.tostring(root, pretty_print=True, encoding='unicode')

    def addMetadataFormatElement(self, parent_element, format_info):
        metadata_prefix_element = etree.SubElement(parent_element, 'metadataPrefix')
        metadata_prefix_element.text = format_info['metadataPrefix']

        schema_element = etree.SubElement(parent_element, 'schema')
        schema_element.text = format_info['schema']

        metadata_namespace_element = etree.SubElement(parent_element, 'metadataNamespace')
        metadata_namespace_element.text = format_info['metadataNamespace']

    def addIdentifyElements(self, identify_element):
        repository_name_element = etree.SubElement(identify_element, 'repositoryName')
        repository_name_element.text = self.repository_name

        base_url_element = etree.SubElement(identify_element, 'baseURL')
        base_url_element.text = self.repository_base_url

        protocol_version_element = etree.SubElement(identify_element, 'protocolVersion')
        protocol_version_element.text = self.repository_protocol_version

        earliest_datestamp_element = etree.SubElement(identify_element, 'earliestDatestamp')
        earliest_datestamp_element.text = self.earliest_datestamp

        deleted_record_element = etree.SubElement(identify_element, 'deletedRecord')
        deleted_record_element.text = self.repository_deleted_records

        granularity_element = etree.SubElement(identify_element, 'granularity')
        granularity_element.text = self.datestamp_granularity

        admin_email_element = etree.SubElement(identify_element, 'adminEmail')
        admin_email_element.text = self.repository_admin_email

    def addRequestElement(self, root, verb=None, metadata_prefix=None, identifier=None,
                          from_date=None, until_date=None, set_spec=None, resumption_token=None):
        if verb:
            # Create the request element and add the verb attribute
            request_element = etree.Element('request', verb=verb)

            # Add additional attributes to the request element when necessary
            if metadata_prefix:
                request_element.set('metadataPrefix', metadata_prefix)

            if identifier:
                request_element.set('identifier', identifier)

            if from_date:
                request_element.set('from', from_date)

            if until_date:
                request_element.set('until', until_date)

            if set_spec:
                request_element.set('setSpec', set_spec)

            if resumption_token:
                request_element.set('resumptionToken', resumption_token)

            # Set the text content of the request element
            request_element.text = f"{self.repository_base_url}"

            # Append the request element to the root
            root.append(request_element)

    def validMetadataPrefix(self, metadata_prefix):
        if metadata_prefix in self.valid_metadata_formats:
            return True

    def recordByIdentifier(self, metadata_dict, identifier):
        for record_name, record_metadata in metadata_dict.items():
            if f'{self.repository_indentifier_base_url}{record_name}' == identifier:
                return record_metadata
        return None

    def isValidDate(self, date_str):
        try:
            date = datetime.strptime(date_str, '%Y-%m-%d')
            # Check if the date string exactly matches the expected format
            if date.strftime('%Y-%m-%d') == date_str:
                return date
        except ValueError:
            return None

    def mapRecord(self, metadata_dict, metadata_prefix):
        # Create an XML document
        nsmap = {
            'oai_dc': 'http://www.openarchives.org/OAI/2.0/oai_dc/',
            'dc': 'http://purl.org/dc/elements/1.1/',
            'datacite': 'http://datacite.org/schema/kernel-4',
            'oaire': 'http://namespace.openaire.eu/schema/oaire/',
        }

        if metadata_prefix == 'oai_dc':
            record_root = '{%s}dc' % nsmap[metadata_prefix]
            schema = 'http://www.openarchives.org/OAI/2.0/oai_dc.xsd'
            schema_ns = 'oai_dc'
            elems_ns = 'dc'
            # Remove the namespaces that are not needed for oai_dc
            del nsmap['datacite']
            del nsmap['oaire']
        elif metadata_prefix == 'oai_openaire':
            record_root = '{%s}resource' % nsmap['oaire']
            schema = 'https://www.openaire.eu/schema/1.0/oaf-1.0.xsd'
            schema_ns = 'oaire'
            elems_ns = 'dc'
            # Remove the namespaces that are not needed for oai_openaire
            del nsmap['oai_dc']
        elif metadata_prefix == 'oai_datacite':
            record_root = '{%s}resource' % nsmap['datacite']
            schema = 'https://schema.datacite.org/meta/kernel-4.3/metadata.xsd'
            schema_ns = 'datacite'
            elems_ns = 'datacite'
            # Remove the namespaces that are not needed for oai_datacite
            del nsmap['oai_dc']
            del nsmap['oaire']
        else:
            return None

        root = etree.Element(record_root, nsmap=nsmap)

        # Add xsi:schemaLocation attribute
        root.set('{http://www.w3.org/2001/XMLSchema-instance}schemaLocation',
                 f'{nsmap[schema_ns]} {schema}')

        for key, value in metadata_dict.items():
            if key == 'display_name':
                title_element = etree.Element('{%s}title' % nsmap[elems_ns])
                title_element.text = value
                root.append(title_element)
            elif key == 'template_author':
                if metadata_prefix == 'oai_datacite':
                    creator_element = etree.Element('{%s}creator' % nsmap[elems_ns])
                    creator_name_element = etree.Element('{%s}creatorName' % nsmap[elems_ns])
                    creator_name_element.text = value
                    creator_element.append(creator_name_element)
                    root.append(creator_element)
                else:
                    creator_element = etree.Element('{%s}creator' % nsmap[elems_ns])
                    creator_element.text = value
                    root.append(creator_element)
            elif key == 'creation_date':
                if metadata_prefix == 'oai_datacite':
                    date_element = etree.Element('{%s}date' % nsmap[elems_ns], dateType="Issued")
                else:
                    date_element = etree.Element('{%s}date' % nsmap[elems_ns])
                date_element.text = value.strftime("%Y-%m-%d")
                root.append(date_element)
            elif key == 'resource_type':
                if metadata_prefix == 'oai_datacite':
                    resource_type_element = etree.Element('{http://namespace.openaire.eu/schema/oaire/}resourceType',
                                                          resourceTypeGeneral="software",
                                                          uri="http://purl.org/coar/resource_type/c_5ce6")
                else:
                    resource_type_element = etree.Element('{%s}resourceType' % nsmap[elems_ns])
                resource_type_element.text = value
                root.append(resource_type_element)
            elif key == 'identifier':
                if metadata_prefix == 'oai_datacite':
                    identifier_element = etree.Element('{http://datacite.org/schema/kernel-4}identifier',
                                                       identifierType="URN")
                else:
                    identifier_element = etree.Element('{%s}identifier' % nsmap[elems_ns])
                identifier_element.text = value
                root.append(identifier_element)
            elif key == 'rights':
                if metadata_prefix == 'oai_dc':
                    rights_element = etree.Element('{%s}rights' % nsmap[elems_ns])
                else:
                    rights_element = etree.Element('{http://datacite.org/schema/kernel-4}rights',
                                                   rightsURI="http://purl.org/coar/access_right/c_abf2")
                rights_element.text = value
                root.append(rights_element)
            elif key == 'publisher':
                publisher_element = etree.Element('{http://purl.org/dc/elements/1.1/}publisher')
                publisher_element.text = value
                root.append(publisher_element)
            elif key == 'template_version':
                if metadata_prefix == 'oai_openaire':
                    version_element = etree.Element('{http://namespace.openaire.eu/schema/oaire/}version')
                else:
                    version_element = etree.Element('{http://purl.org/dc/elements/1.1/}version')
                version_element.text = value
                root.append(version_element)
            elif key == 'format':
                format_element = etree.Element('{http://purl.org/dc/elements/1.1/}format')
                format_element.text = value
                root.append(format_element)
            elif key == 'subject':
                if metadata_prefix == 'oai_openaire':
                    subject_element = etree.Element('{http://namespace.openaire.eu/schema/oaire/}subject')
                    subject_element.text = value
                    root.append(subject_element)
            elif key == 'description':
                related_identifier_element = etree.Element('{http://purl.org/dc/elements/1.1/}description')
                related_identifier_element.text = value
                root.append(related_identifier_element)
            elif key == 'related_identifier':
                if metadata_prefix == 'oai_datacite':
                    related_identifier_element = etree.Element('{http://datacite.org/schema/kernel-4}relatedIdentifier',
                                                               relatedIdentifierType="DOI",
                                                               relationType="isContinuedBy")
                    related_identifier_element.text = value
                    root.append(related_identifier_element)
            elif key == 'tag':
                if metadata_prefix == 'oai_dc':
                    subject_element = etree.Element('{http://purl.org/dc/elements/1.1/}subject')
                    subject_element.text = value
                    root.append(subject_element)

        return root

    def addError(self, root, error_type):
        request_element = etree.SubElement(root, 'request')
        request_element.text = f"{self.repository_base_url}"
        error_element = error_type
        root.append(error_element)

    def processRequest(self, request, metadata_dict):
        root = self.baseXMLTree()

        attributes_dict = {
            'verb': 0,
            'identifier': 0,
            'metadataPrefix': 0,
            'from': 0,
            'until': 0,
            'set': 0,
            'resumptionToken': 0,
        }

        verb = request.values.get('verb')

        if not verb:
            self.addError(root, Errors.badVerb())
            return etree.tostring(root, pretty_print=True, encoding='unicode')

        response_xml = None

        for key in list(request.values.keys()):
            if key in attributes_dict:
                attributes_dict[key] += 1
                # Check for duplicate attributes
                if attributes_dict[key] > 1:
                    self.addError(root, Errors.badArgument())
                    return etree.tostring(root, pretty_print=True, encoding='unicode')

        # Check for unknown attributes
        unknown_attributes = [key for key in list(request.values.keys()) if key not in attributes_dict]

        if unknown_attributes:
            self.addError(root, Errors.badArgument())
            response_xml = etree.tostring(root, pretty_print=True, encoding='unicode')

            return response_xml

        metadata_prefix = request.values.get('metadataPrefix')
        identifier = request.values.get('identifier')
        from_date = request.values.get('from')
        until_date = request.values.get('until')
        set_spec = request.values.get('set')
        resumption_token = request.values.get('resumptionToken')

        # Create a dictionary mapping verbs to functions
        verb_handlers = {
            "GetRecord": lambda metadata_dict = metadata_dict: self.getRecord(
                root, metadata_dict, verb, identifier, metadata_prefix
            ),
            "Identify": lambda: self.identify(root, verb),
            "ListIdentifiers": lambda metadata_dict = metadata_dict: self.listIdentifiers(
                root,
                metadata_dict,
                verb,
                metadata_prefix,
                from_date,
                until_date,
                set_spec,
                resumption_token,
            ),
            "ListRecords": lambda metadata_dict = metadata_dict: self.listRecords(
                root,
                metadata_dict,
                verb,
                metadata_prefix,
                from_date,
                until_date,
                set_spec,
                resumption_token,
            ),
            "ListMetadataFormats": lambda metadata_dict = metadata_dict: self.listMetadataFormats(
                root, metadata_dict, verb, identifier
            ),
            "ListSets": lambda: self.listSets(root, verb, resumption_token),
        }

        # Get the handler function for the specified verb
        handler = verb_handlers.get(verb)

        if handler is None:
            self.addError(root, Errors.badVerb())
            response_xml = etree.tostring(root, pretty_print=True, encoding='unicode')
        else:
            response_xml = handler()

        return response_xml
