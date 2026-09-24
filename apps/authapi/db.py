"""Database connection hooks (SQLite concurrency tuning for single-node deploys)."""

from __future__ import annotations

from django.db.backends.signals import connection_created


def _configure_sqlite_connection(sender, connection, **kwargs) -> None:
    if connection.vendor != 'sqlite':
        return
    with connection.cursor() as cursor:
        # WAL allows concurrent readers while a writer holds the DB lock (default DELETE mode does not).
        cursor.execute('PRAGMA journal_mode=WAL;')


def connect_sqlite_hooks() -> None:
    connection_created.connect(_configure_sqlite_connection)
