"""SAML response validation on top of python3-saml, reported as machine error codes."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.errors import OneLogin_Saml2_Error, OneLogin_Saml2_ValidationError
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from onelogin.saml2.xml_utils import OneLogin_Saml2_XML

from apps.authapi.saml.errors import SAMLFlowError

logger = logging.getLogger(__name__)

SAML_ASSERTION_MAX_VALIDITY_SECONDS = 15 * 60
# python3-saml accepts Conditions/@NotOnOrAfter up to this many seconds late (not configurable).
SAML_LIBRARY_CLOCK_DRIFT_SECONDS = int(OneLogin_Saml2_Constants.ALLOWED_CLOCK_DRIFT)
SAML_REPLAY_TTL_MARGIN_SECONDS = 300
SAML_RESPONSE_MAX_BYTES = 512 * 1024

_VE = OneLogin_Saml2_ValidationError

_VALIDATION_ERROR_CODES: dict[int, str] = {
    _VE.UNSUPPORTED_SAML_VERSION: 'saml_response_malformed',
    _VE.MISSING_ID: 'saml_response_malformed',
    _VE.INVALID_XML_FORMAT: 'saml_response_malformed',
    _VE.MISSING_STATUS: 'saml_response_malformed',
    _VE.MISSING_STATUS_CODE: 'saml_response_malformed',
    _VE.DUPLICATED_ATTRIBUTE_NAME_FOUND: 'saml_response_malformed',
    _VE.STATUS_CODE_IS_NOT_SUCCESS: 'saml_idp_status_error',
    _VE.WRONG_NUMBER_OF_ASSERTIONS: 'saml_assertion_count_invalid',
    _VE.WRONG_SIGNED_ELEMENT: 'saml_signature_invalid',
    _VE.ID_NOT_FOUND_IN_SIGNED_ELEMENT: 'saml_signature_invalid',
    _VE.DUPLICATED_ID_IN_SIGNED_ELEMENTS: 'saml_signature_invalid',
    _VE.INVALID_SIGNED_ELEMENT: 'saml_signature_invalid',
    _VE.DUPLICATED_REFERENCE_IN_SIGNED_ELEMENTS: 'saml_signature_invalid',
    _VE.UNEXPECTED_SIGNED_ELEMENTS: 'saml_signature_invalid',
    _VE.WRONG_NUMBER_OF_SIGNATURES_IN_RESPONSE: 'saml_signature_invalid',
    _VE.WRONG_NUMBER_OF_SIGNATURES_IN_ASSERTION: 'saml_signature_invalid',
    _VE.WRONG_NUMBER_OF_SIGNATURES: 'saml_signature_invalid',
    _VE.INVALID_SIGNATURE: 'saml_signature_invalid',
    _VE.NO_SIGNED_MESSAGE: 'saml_signature_missing',
    _VE.NO_SIGNED_ASSERTION: 'saml_signature_missing',
    _VE.NO_SIGNATURE_FOUND: 'saml_signature_missing',
    _VE.DEPRECATED_SIGNATURE_METHOD: 'saml_signature_algorithm_rejected',
    _VE.DEPRECATED_DIGEST_METHOD: 'saml_signature_algorithm_rejected',
    _VE.WRONG_INRESPONSETO: 'saml_in_response_to_mismatch',
    _VE.NO_ENCRYPTED_ASSERTION: 'saml_encryption_unsupported',
    _VE.NO_ENCRYPTED_NAMEID: 'saml_encryption_unsupported',
    _VE.ENCRYPTED_ATTRIBUTES: 'saml_encryption_unsupported',
    _VE.KEYINFO_NOT_FOUND_IN_ENCRYPTED_DATA: 'saml_encryption_unsupported',
    _VE.CHILDREN_NODE_NOT_FOUND_IN_KEYINFO: 'saml_encryption_unsupported',
    _VE.UNSUPPORTED_RETRIEVAL_METHOD: 'saml_encryption_unsupported',
    _VE.MISSING_CONDITIONS: 'saml_conditions_missing',
    _VE.ASSERTION_TOO_EARLY: 'saml_assertion_not_yet_valid',
    _VE.ASSERTION_EXPIRED: 'saml_assertion_expired',
    _VE.SESSION_EXPIRED: 'saml_assertion_expired',
    _VE.RESPONSE_EXPIRED: 'saml_assertion_expired',
    _VE.WRONG_NUMBER_OF_AUTHSTATEMENTS: 'saml_authn_statement_invalid',
    _VE.NO_ATTRIBUTESTATEMENT: 'saml_attribute_statement_missing',
    _VE.WRONG_DESTINATION: 'saml_destination_mismatch',
    _VE.EMPTY_DESTINATION: 'saml_destination_mismatch',
    _VE.WRONG_AUDIENCE: 'saml_audience_mismatch',
    _VE.ISSUER_MULTIPLE_IN_RESPONSE: 'saml_issuer_mismatch',
    _VE.ISSUER_NOT_FOUND_IN_ASSERTION: 'saml_issuer_mismatch',
    _VE.WRONG_ISSUER: 'saml_issuer_mismatch',
    _VE.WRONG_SUBJECTCONFIRMATION: 'saml_subject_confirmation_invalid',
    _VE.NO_NAMEID: 'saml_nameid_missing',
    _VE.EMPTY_NAMEID: 'saml_nameid_missing',
    _VE.SP_NAME_QUALIFIER_NAME_MISMATCH: 'saml_nameid_invalid',
    _VE.AUTHN_CONTEXT_MISMATCH: 'saml_authn_context_mismatch',
}


def saml_error_code_for_validation_error(code: int | None) -> str:
    return _VALIDATION_ERROR_CODES.get(code, 'saml_response_invalid')


class ShellUISAMLAuth(OneLogin_Saml2_Auth):
    """Keeps the validated response and a Shellui error code instead of library error text."""

    def __init__(self, request_data, old_settings=None, custom_base_path=None):
        super().__init__(request_data, old_settings=old_settings, custom_base_path=custom_base_path)
        self.shellui_error_code: str | None = None
        self.validated_response = None

    def _fail(self, error_code: str, reason: str) -> None:
        self._errors = ['invalid_response']
        self._error_reason = reason
        self.shellui_error_code = error_code

    def process_response(self, request_id=None):
        self._errors = []
        self._error_reason = None
        self.shellui_error_code = None
        self.validated_response = None
        post_data = self._request_data.get('post_data') or {}
        raw = post_data.get('SAMLResponse')
        if not raw:
            self._fail('saml_response_missing', 'SAMLResponse missing')
            return
        try:
            response = self.response_class(self._settings, raw)
        except OneLogin_Saml2_Error as exc:
            code = (
                'saml_encryption_unsupported'
                if exc.code == OneLogin_Saml2_Error.PRIVATE_KEY_NOT_FOUND
                else 'saml_response_malformed'
            )
            self._fail(code, str(exc))
            return
        except Exception as exc:  # noqa: BLE001 - base64, XML syntax, DTD and entity rejections
            self._fail('saml_response_malformed', exc.__class__.__name__)
            return
        self._last_response = response.get_xml_document()
        try:
            response.is_valid(self._request_data, request_id, raise_exceptions=True)
            self.store_valid_response(response)
        except OneLogin_Saml2_ValidationError as exc:
            self._fail(saml_error_code_for_validation_error(exc.code), str(exc))
            return
        except Exception as exc:  # noqa: BLE001 - never surface library internals to the client
            self._fail('saml_response_invalid', str(exc))
            return
        self.validated_response = response


@dataclass(frozen=True)
class ValidatedAssertion:
    assertion_id: str
    in_response_to: str | None
    replay_ttl_seconds: int


def _same_url(left: str, right: str) -> bool:
    return OneLogin_Saml2_Utils.normalize_url(url=left.strip()) == OneLogin_Saml2_Utils.normalize_url(url=right.strip())


def _parse_instant(value: str) -> int:
    try:
        return int(OneLogin_Saml2_Utils.parse_SAML_to_time(value))
    except Exception as exc:  # noqa: BLE001
        raise SAMLFlowError('saml_response_malformed') from exc


def check_validated_assertion(response, *, acs_url: str) -> ValidatedAssertion:
    """
    Checks python3-saml leaves loose, applied to the one signature-verified assertion.

    - Destination (when present) and the bearer ``Recipient`` must equal the ACS URL exactly;
      the library only does a prefix and a substring match.
    - The unsigned envelope ``InResponseTo`` must equal the one in the signed ``SubjectConfirmationData``.
    - The acceptance window must end, and not later than ``SAML_ASSERTION_MAX_VALIDITY_SECONDS``
      from now, so the replay cache entry outlives every moment the assertion could be accepted.
    """
    document = response.decrypted_document if response.encrypted else response.document
    assertions = OneLogin_Saml2_XML.query(document, '/samlp:Response/saml:Assertion')
    if len(assertions) != 1:
        raise SAMLFlowError('saml_assertion_count_invalid')
    assertion = assertions[0]
    assertion_id = str(assertion.get('ID') or '').strip()
    if not assertion_id:
        raise SAMLFlowError('saml_response_malformed')

    destination = document.get('Destination')
    if destination is not None and not _same_url(destination, acs_url):
        raise SAMLFlowError('saml_destination_mismatch')

    audiences = OneLogin_Saml2_XML.query(
        assertion, './saml:Conditions/saml:AudienceRestriction/saml:Audience'
    )
    if not audiences:
        raise SAMLFlowError('saml_audience_missing')

    bearer = [
        node
        for node in OneLogin_Saml2_XML.query(assertion, './saml:Subject/saml:SubjectConfirmation')
        if node.get('Method') in (None, OneLogin_Saml2_Constants.CM_BEARER)
    ]
    if len(bearer) != 1:
        raise SAMLFlowError('saml_subject_confirmation_invalid')
    confirmation_data = OneLogin_Saml2_XML.query(bearer[0], './saml:SubjectConfirmationData')
    if len(confirmation_data) != 1:
        raise SAMLFlowError('saml_subject_confirmation_invalid')
    scd = confirmation_data[0]

    recipient = scd.get('Recipient')
    if not recipient or not _same_url(recipient, acs_url):
        raise SAMLFlowError('saml_recipient_mismatch')

    signed_in_response_to = str(scd.get('InResponseTo') or '').strip() or None
    envelope_in_response_to = str(document.get('InResponseTo') or '').strip() or None
    if envelope_in_response_to != signed_in_response_to:
        raise SAMLFlowError('saml_in_response_to_mismatch')

    scd_not_on_or_after = scd.get('NotOnOrAfter')
    if not scd_not_on_or_after:
        raise SAMLFlowError('saml_assertion_lifetime_invalid')
    window_ends = [_parse_instant(scd_not_on_or_after)]
    for conditions in OneLogin_Saml2_XML.query(assertion, './saml:Conditions'):
        raw = conditions.get('NotOnOrAfter')
        if raw:
            window_ends.append(_parse_instant(raw) + SAML_LIBRARY_CLOCK_DRIFT_SECONDS)
    remaining = min(window_ends) - int(OneLogin_Saml2_Utils.now())
    if remaining <= 0:
        raise SAMLFlowError('saml_assertion_expired')
    if remaining > SAML_ASSERTION_MAX_VALIDITY_SECONDS:
        raise SAMLFlowError('saml_assertion_lifetime_invalid')
    return ValidatedAssertion(
        assertion_id=assertion_id,
        in_response_to=signed_in_response_to,
        replay_ttl_seconds=remaining + SAML_REPLAY_TTL_MARGIN_SECONDS,
    )
