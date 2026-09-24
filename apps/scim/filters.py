from django_scim.filters import GroupFilterQuery, UserFilterQuery

from apps.companies.models import CompanyGroup
from apps.scim.context import get_scim_company


class ShellUIUserFilterQuery(UserFilterQuery):
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


class ShellUIGroupFilterQuery(GroupFilterQuery):
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
