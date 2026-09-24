from django_scim.filters import GroupFilterQuery, UserFilterQuery


class ShellUIUserFilterQuery(UserFilterQuery):
    """Company membership is applied via queryset hooks; drop ``active`` from SQL filters."""

    attr_map = {
        key: value
        for key, value in UserFilterQuery.attr_map.items()
        if key != ('active', None, None)
    }


class ShellUIGroupFilterQuery(GroupFilterQuery):
    attr_map = {
        ('displayName', None, None): 'display_name',
    }
