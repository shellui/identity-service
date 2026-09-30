"""Runtime IdP key material and signed SAML responses for ACS tests."""

from __future__ import annotations

import base64
import datetime
import uuid
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree
from signxml import XMLSigner
from signxml.algorithms import CanonicalizationMethod, SignatureConstructionMethod


NSMAP = {
    'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
    'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
    'ds': 'http://www.w3.org/2000/09/xmldsig#',
}


@dataclass(frozen=True)
class TestIdPCredentials:
    entity_id: str
    private_key_pem: bytes
    certificate_pem: bytes

    @property
    def x509cert_one_line(self) -> str:
        body = self.certificate_pem.decode('utf-8')
        lines = [line for line in body.splitlines() if 'BEGIN' not in line and 'END' not in line]
        return ''.join(lines)


def generate_test_idp_credentials(*, entity_id: str = 'https://idp.test.example/entity') -> TestIdPCredentials:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'SAML Test IdP')])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    return TestIdPCredentials(
        entity_id=entity_id,
        private_key_pem=key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        certificate_pem=cert.public_bytes(serialization.Encoding.PEM),
    )


def _sign_assertion(assertion: etree._Element, creds: TestIdPCredentials) -> etree._Element:
    signer = XMLSigner(
        method=SignatureConstructionMethod.enveloped,
        signature_algorithm='rsa-sha256',
        c14n_algorithm=CanonicalizationMethod.EXCLUSIVE_XML_CANONICALIZATION_1_0,
    )
    signed = signer.sign(
        assertion,
        key=creds.private_key_pem,
        cert=creds.certificate_pem,
        reference_uri=f'#{assertion.get("ID")}',
    )
    target = signed if signed is not assertion else assertion
    sig = target.find('{http://www.w3.org/2000/09/xmldsig#}Signature')
    if sig is not None:
        target.remove(sig)
        target.insert(1, sig)
    if signed is not assertion and assertion.getparent() is not None:
        assertion.getparent().replace(assertion, target)
    return target


def build_signed_saml_response(
    *,
    creds: TestIdPCredentials,
    sp_entity_id: str,
    acs_url: str,
    name_id: str,
    in_response_to: str | None,
    audience: str | None = None,
    issuer: str | None = None,
    not_on_or_after_offset_seconds: int = 300,
    assertion_id: str | None = None,
    wrap_signature: bool = False,
) -> str:
    """Return base64-encoded SAMLResponse for HTTP-POST binding."""
    now = datetime.datetime.now(datetime.timezone.utc)
    issue_instant = now.strftime('%Y-%m-%dT%H:%M:%SZ')
    not_on_or_after = (now + datetime.timedelta(seconds=not_on_or_after_offset_seconds)).strftime(
        '%Y-%m-%dT%H:%M:%SZ'
    )
    response_id = f'_{uuid.uuid4().hex}'
    assertion_id_value = assertion_id or f'_{uuid.uuid4().hex}'
    issuer_value = issuer or creds.entity_id
    audience_value = audience or sp_entity_id

    response = etree.Element(
        '{urn:oasis:names:tc:SAML:2.0:protocol}Response',
        nsmap={
            'samlp': NSMAP['samlp'],
            'saml': NSMAP['saml'],
            'ds': NSMAP['ds'],
            'xs': 'http://www.w3.org/2001/XMLSchema',
            'xsi': 'http://www.w3.org/2001/XMLSchema-instance',
        },
        ID=response_id,
        Version='2.0',
        IssueInstant=issue_instant,
        Destination=acs_url,
    )
    if in_response_to:
        response.set('InResponseTo', in_response_to)
    etree.SubElement(response, '{urn:oasis:names:tc:SAML:2.0:assertion}Issuer').text = issuer_value

    status = etree.SubElement(response, '{urn:oasis:names:tc:SAML:2.0:protocol}Status')
    etree.SubElement(
        status,
        '{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode',
        Value='urn:oasis:names:tc:SAML:2.0:status:Success',
    )

    assertion = etree.SubElement(
        response,
        '{urn:oasis:names:tc:SAML:2.0:assertion}Assertion',
        ID=assertion_id_value,
        IssueInstant=issue_instant,
        Version='2.0',
    )
    etree.SubElement(assertion, '{urn:oasis:names:tc:SAML:2.0:assertion}Issuer').text = issuer_value
    subject = etree.SubElement(assertion, '{urn:oasis:names:tc:SAML:2.0:assertion}Subject')
    name_id_el = etree.SubElement(
        subject,
        '{urn:oasis:names:tc:SAML:2.0:assertion}NameID',
        Format='urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
    )
    name_id_el.text = name_id
    sub_conf = etree.SubElement(
        subject,
        '{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmation',
        Method='urn:oasis:names:tc:SAML:2.0:cm:bearer',
    )
    scd_attrs = {'NotOnOrAfter': not_on_or_after, 'Recipient': acs_url}
    if in_response_to:
        scd_attrs['InResponseTo'] = in_response_to
    etree.SubElement(
        sub_conf,
        '{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmationData',
        **scd_attrs,
    )
    conditions = etree.SubElement(assertion, '{urn:oasis:names:tc:SAML:2.0:assertion}Conditions')
    conditions.set('NotBefore', issue_instant)
    conditions.set('NotOnOrAfter', not_on_or_after)
    audience_restriction = etree.SubElement(
        conditions,
        '{urn:oasis:names:tc:SAML:2.0:assertion}AudienceRestriction',
    )
    audience_el = etree.SubElement(
        audience_restriction,
        '{urn:oasis:names:tc:SAML:2.0:assertion}Audience',
    )
    audience_el.text = audience_value

    authn_statement = etree.SubElement(
        assertion,
        '{urn:oasis:names:tc:SAML:2.0:assertion}AuthnStatement',
        AuthnInstant=issue_instant,
        SessionIndex=f'_{uuid.uuid4().hex}',
    )
    authn_context = etree.SubElement(
        authn_statement,
        '{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContext',
    )
    etree.SubElement(
        authn_context,
        '{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContextClassRef',
    ).text = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'

    attr_statement = etree.SubElement(assertion, '{urn:oasis:names:tc:SAML:2.0:assertion}AttributeStatement')
    for attr_name, attr_value in (
        ('urn:oid:0.9.2342.19200300.100.1.3', name_id if '@' in name_id else f'{name_id}@example.com'),
        ('urn:oasis:names:tc:SAML:attribute:subject-id', name_id),
    ):
        attr = etree.SubElement(
            attr_statement,
            '{urn:oasis:names:tc:SAML:2.0:assertion}Attribute',
            Name=attr_name,
        )
        av = etree.SubElement(
            attr,
            '{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue',
            attrib={
                '{http://www.w3.org/2001/XMLSchema-instance}type': 'xs:string',
            },
        )
        av.text = attr_value

    if wrap_signature:
        decoy = etree.SubElement(response, '{urn:oasis:names:tc:SAML:2.0:assertion}Assertion', ID=f'_{uuid.uuid4().hex}')
        etree.SubElement(decoy, '{urn:oasis:names:tc:SAML:2.0:assertion}Issuer').text = 'evil'

    _sign_assertion(assertion, creds)
    xml_bytes = etree.tostring(response, xml_declaration=True, encoding='UTF-8')
    return base64.b64encode(xml_bytes).decode('ascii')
