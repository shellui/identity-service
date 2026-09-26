from django.core.exceptions import ValidationError
from django.test import SimpleTestCase

from apps.actions.email_template_substitute import (
    assert_no_django_template_tags,
    substitute_action_email_template,
)


class EmailTemplateSubstituteTests(SimpleTestCase):
    def test_substitute_nested_paths_and_default_filter(self):
        context = {
            'envelope': {'company': {'name': 'Acme'}},
            'data': {'email': '', 'name': 'Ops token', 'token_prefix': 'abc123'},
        }
        subject = '[Shellui] {{ data.name|default:data.token_prefix }}'
        self.assertEqual(
            substitute_action_email_template(subject, context),
            '[Shellui] Ops token',
        )
        context['data']['email'] = 'ada@acme.com'
        body = 'Hello {{ envelope.company.name }} / {{ data.email|default:"user" }}'
        self.assertEqual(
            substitute_action_email_template(body, context),
            'Hello Acme / ada@acme.com',
        )

    def test_rejects_django_block_tags(self):
        with self.assertRaises(ValidationError):
            assert_no_django_template_tags('{% block x %}', field_label='html')
