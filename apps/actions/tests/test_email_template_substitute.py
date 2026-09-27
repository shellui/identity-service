from django.core.exceptions import ValidationError
from django.test import SimpleTestCase

from apps.actions.email_template_substitute import (
    assert_no_django_template_tags,
    sanitize_action_email_url,
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
            substitute_action_email_template(subject, context, mode='plain'),
            '[Shellui] Ops token',
        )
        context['data']['email'] = 'ada@acme.com'
        body = 'Hello {{ envelope.company.name }} / {{ data.email|default:"user" }}'
        self.assertEqual(
            substitute_action_email_template(body, context, mode='html'),
            'Hello Acme / ada@acme.com',
        )

    def test_html_mode_escapes_markup_in_text(self):
        context = {
            'envelope': {'company': {'name': 'Acme <script>'}},
            'data': {
                'display_name': '</strong><a href="https://evil.example">x</a><strong>',
            },
        }
        html = (
            '<p>{{ envelope.company.name }}</p>'
            '<p><strong>{{ data.display_name }}</strong></p>'
        )
        out = substitute_action_email_template(html, context, mode='html')
        self.assertIn('Acme &lt;script&gt;', out)
        self.assertIn('&lt;/strong&gt;&lt;a href=', out)
        self.assertNotIn('<script>', out)
        self.assertNotIn('<a href="https://evil.example">', out)

    def test_html_mode_allows_safe_urls_in_href_and_escapes_ampersand(self):
        context = {
            'data': {
                'magic_link_url': 'https://id.example.com/verify?token=abc&company_id=1',
            },
        }
        html = '<a href="{{ data.magic_link_url }}">Sign in</a>'
        out = substitute_action_email_template(html, context, mode='html')
        self.assertIn(
            'href="https://id.example.com/verify?token=abc&amp;company_id=1"',
            out,
        )

    def test_html_mode_strips_dangerous_url_schemes_in_href(self):
        context = {'data': {'display_name': 'javascript:alert(1)'}}
        html = '<a href="{{ data.display_name }}">Go</a>'
        out = substitute_action_email_template(html, context, mode='html')
        self.assertIn('href=""', out)
        self.assertNotIn('javascript:', out)

        context['data']['display_name'] = 'https://evil.example/phish'
        out = substitute_action_email_template(html, context, mode='html')
        self.assertIn('href="https://evil.example/phish"', out)

    def test_html_mode_url_check_does_not_apply_outside_url_attrs(self):
        # javascript: in body text is escaped, not stripped — it must not become a URL.
        context = {'data': {'note': 'javascript:alert(1)'}}
        out = substitute_action_email_template('<p>{{ data.note }}</p>', context, mode='html')
        self.assertIn('javascript:alert(1)', out)

    def test_plain_mode_strips_newlines_but_keeps_angle_brackets(self):
        context = {'data': {'name': 'Ada\r\nAdmin <ops>'}}
        out = substitute_action_email_template(
            'Hello {{ data.name }}', context, mode='plain'
        )
        self.assertEqual(out, 'Hello Ada  Admin <ops>')

    def test_sanitize_action_email_url(self):
        self.assertEqual(sanitize_action_email_url('https://a.example/x'), 'https://a.example/x')
        self.assertEqual(sanitize_action_email_url('mailto:a@b.com'), 'mailto:a@b.com')
        self.assertEqual(sanitize_action_email_url('#'), '#')
        self.assertEqual(sanitize_action_email_url('javascript:alert(1)'), '')
        self.assertEqual(sanitize_action_email_url('data:text/html,x'), '')
        self.assertEqual(sanitize_action_email_url('/relative'), '')

    def test_rejects_django_block_tags(self):
        with self.assertRaises(ValidationError):
            assert_no_django_template_tags('{% block x %}', field_label='html')
