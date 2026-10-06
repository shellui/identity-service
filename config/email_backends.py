"""Email backends for local development."""

from __future__ import annotations

from django.core.mail.backends.console import EmailBackend as DjangoConsoleEmailBackend


class ConsoleEmailBackend(DjangoConsoleEmailBackend):
    """
    Print the decoded plain-text body instead of the raw MIME message.

    Django's console backend writes the quoted-printable wire format, so URLs copied from
    the terminal contain ``=3D`` and soft line breaks and no longer work.
    """

    def write_message(self, message):
        alternatives = [mimetype for _content, mimetype in getattr(message, 'alternatives', [])]
        lines = [
            f'Subject: {message.subject}',
            f'From: {message.from_email}',
            f'To: {", ".join(message.recipients())}',
        ]
        if alternatives:
            lines.append(f'Alternatives: {", ".join(alternatives)}')
        self.stream.write('\n'.join(lines) + '\n\n')
        self.stream.write(f'{message.body}\n')
        self.stream.write('-' * 79 + '\n')
