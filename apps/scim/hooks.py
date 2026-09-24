from __future__ import annotations

from django.contrib.auth import get_user_model

from apps.scim.context import get_scim_company


def shellui_base_scim_location(request=None, *args, **kwargs):
    if request is None:
        return ''
    company = get_scim_company(request)
    if company is None:
        return ''
    scheme = 'https' if request.is_secure() else 'http'
    host = request.get_host()
    return f'{scheme}://{host}/api/v1/companies/{company.slug}/scim/v2/'


def _user_filter_kwargs_getter():
    def get_extra_filter_kwargs(request, uuid=None, *args, **kwargs):
        company = get_scim_company(request)
        if company is None:
            return {'pk__in': []}
        filters = {'companies': company}
        if uuid:
            filters['pk'] = uuid
        return filters

    return get_extra_filter_kwargs


def _group_filter_kwargs_getter():
    from apps.companies.models import CompanyGroup

    def get_extra_filter_kwargs(request, uuid=None, *args, **kwargs):
        company = get_scim_company(request)
        if company is None:
            return {'pk__in': []}
        filters = {'company': company, 'source': CompanyGroup.SOURCE_SCIM}
        if uuid:
            filters['pk'] = uuid
        return filters

    return get_extra_filter_kwargs


def shellui_model_filter_kwargs_getter(model):
    from django_scim.utils import default_get_extra_model_filter_kwargs_getter

    from apps.companies.models import CompanyGroup

    User = get_user_model()
    if model is User:
        return _user_filter_kwargs_getter()
    if model is CompanyGroup:
        return _group_filter_kwargs_getter()
    return default_get_extra_model_filter_kwargs_getter(model)


def shellui_model_queryset_post_processor_getter(model):
    from apps.companies.models import CompanyGroup

    User = get_user_model()

    def _user_post_processor(request, qs, *args, **kwargs):
        company = get_scim_company(request)
        if company is None:
            return User.objects.none()
        return qs.filter(companies=company).distinct()

    def _group_post_processor(request, qs, *args, **kwargs):
        company = get_scim_company(request)
        if company is None:
            return CompanyGroup.objects.none()
        return qs.filter(company=company, source=CompanyGroup.SOURCE_SCIM)

    if model is User:
        return _user_post_processor
    if model is CompanyGroup:
        return _group_post_processor
    return _user_post_processor


def shellui_model_object_post_processor_getter(model):
    from django_scim.exceptions import NotFoundError

    from apps.companies.models import CompanyGroup

    User = get_user_model()

    def _user_post_processor(request, obj, *args, **kwargs):
        company = get_scim_company(request)
        if company is None or not obj.companies.filter(pk=company.pk).exists():
            raise NotFoundError(str(getattr(getattr(obj, 'scim_attributes', None), 'scim_id', obj.pk)))
        return obj

    def _group_post_processor(request, obj, *args, **kwargs):
        company = get_scim_company(request)
        if (
            company is None
            or obj.company_id != company.pk
            or obj.source != CompanyGroup.SOURCE_SCIM
        ):
            raise NotFoundError(str(obj.pk))
        return obj

    if model is User:
        return _user_post_processor
    if model is CompanyGroup:
        return _group_post_processor
    return _user_post_processor


def shellui_is_scim_authenticated(user):
    return getattr(user, 'is_authenticated', False)
