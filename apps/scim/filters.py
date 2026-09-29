from django_scim.filters import FilterQuery, GroupFilterQuery, UserFilterQuery

from apps.companies.models import CompanyGroup
from apps.scim.context import get_scim_company


class _TenantScopedFilterQuery(FilterQuery):
    """Wrap parsed SCIM filter SQL so tenant AND clauses cannot bind inside OR expressions."""

    @classmethod
    def get_raw_args(cls, q, request=None):
        sql, params = q.sql, list(q.params)
        if sql and q.where_sql:
            upper = sql.upper()
            where_idx = upper.find(' WHERE ')
            if where_idx != -1:
                prefix = sql[: where_idx + len(' WHERE ')]
                predicate = sql[where_idx + len(' WHERE ') :].rstrip().rstrip(';')
                sql = f'{prefix}({predicate})'
        extra_sql, extra_params = cls.get_extras(q, request)
        if extra_sql:
            if "'%s'" in extra_sql:
                raise ValueError(
                    'Dangerous use of quotes around place holder. Please see '
                    'https://docs.djangoproject.com/en/2.2/ref/models/querysets/#extra '
                    'for more details.'
                )
            sql = sql.rstrip(';') + extra_sql + ';'
            params += extra_params
        return sql, params


class ShellUIUserFilterQuery(_TenantScopedFilterQuery, UserFilterQuery):
    """Company membership is applied via queryset hooks; drop ``active`` from SQL filters."""

    attr_map = {
        key: value
        for key, value in UserFilterQuery.attr_map.items()
        if key != ('active', None, None)
    }

    @classmethod
    def get_extras(cls, q, request=None):
        company = get_scim_company(request)
        if company is None:
            return ' AND 1=0', []
        table = cls.table_name()
        sql = (
            f' AND {table}.id IN ('
            f'SELECT user_id FROM companies_companymembership WHERE company_id = %s)'
        )
        return sql, [company.pk]


class ShellUIGroupFilterQuery(_TenantScopedFilterQuery, GroupFilterQuery):
    attr_map = {
        ('displayName', None, None): 'display_name',
    }

    @classmethod
    def get_extras(cls, q, request=None):
        company = get_scim_company(request)
        if company is None:
            return ' AND 1=0', []
        table = cls.table_name()
        return (
            f' AND {table}.company_id = %s AND {table}.source = %s',
            [company.pk, CompanyGroup.SOURCE_SCIM],
        )
