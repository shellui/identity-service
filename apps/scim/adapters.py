from __future__ import annotations

from typing import Optional, Union
from urllib.parse import urljoin

from django.db import IntegrityError as DjangoIntegrityError
from django.urls import reverse
from django_scim import constants, exceptions
from django.contrib.auth import get_user_model
from django_scim.adapters import SCIMGroup, SCIMUser
from scim2_filter_parser.attr_paths import AttrPath

from apps.companies.access import is_company_access_enabled, set_company_access
from apps.companies.group_display_name import first_display_name_conflict
from apps.companies.group_graph import NestedGroupCycleError, assert_nested_group_link_allowed
from apps.companies.models import CompanyGroup
from apps.scim.context import get_scim_company
from apps.scim.group_members import parse_scim_members
from apps.scim.filters import ShellUIGroupFilterQuery, ShellUIUserFilterQuery
from apps.actions.scim_hooks import (
    emit_group_created,
    emit_group_deleted,
    emit_group_membership_changed,
    emit_group_updated,
    emit_user_deprovisioned,
    emit_user_provisioned,
)
from apps.scim.provisioning_events import OPERATION_CREATE, OPERATION_RENAME, record_group_display_name_conflict
from apps.scim.models import ScimProvisioningEvent
from apps.scim.user_bridge import ScimUserBridge
from django_scim.utils import get_base_scim_location_getter


class _ShellUIResourceTypeMixin:
    @classmethod
    def resource_type_dict(cls, request=None):
        company = get_scim_company(request)
        if company is None:
            raise exceptions.BadRequestError('SCIM company context is missing.')
        id_ = cls.resource_type
        path = reverse(
            'scim:resource-types',
            kwargs={'uuid': id_, 'company_slug': company.slug},
        )
        location = urljoin(get_base_scim_location_getter()(request), path)
        endpoint_name = 'scim:users' if id_ == 'User' else 'scim:groups'
        endpoint = reverse(endpoint_name, kwargs={'company_slug': company.slug})
        schema = constants.SchemaURI.USER if id_ == 'User' else constants.SchemaURI.GROUP
        return {
            'schemas': [constants.SchemaURI.RESOURCE_TYPE],
            'id': id_,
            'name': id_,
            'endpoint': endpoint,
            'description': 'User Account' if id_ == 'User' else 'Group',
            'schema': schema,
            'meta': {
                'location': location,
                'resourceType': 'ResourceType',
            },
        }


class ShellUIScimUser(_ShellUIResourceTypeMixin, SCIMUser):
    """
    Map SCIM User resources to Django users scoped by ``request.scim_company``.

    ``active`` reflects company membership (``CompanyMembership.is_enabled``), not global
    ``User.is_active``. Deprovisioning disables membership; users are not hard-deleted.
    """

    id_field = 'pk'
    ATTR_MAP = ShellUIUserFilterQuery.attr_map

    def __init__(self, obj, request=None):
        if not isinstance(obj, ScimUserBridge):
            obj = ScimUserBridge(obj)
        super().__init__(obj, request=request)
        self._pending_membership_active: bool | None = None

    @property
    def _company(self):
        company = get_scim_company(self.request)
        if company is None:
            raise exceptions.BadRequestError('SCIM company context is missing.')
        return company

    @property
    def path(self):
        company = self._company
        return reverse('scim:users', kwargs={'uuid': self.id, 'company_slug': company.slug})

    @property
    def location(self):
        return urljoin(get_base_scim_location_getter()(self.request), self.path)

    def _membership_active(self) -> bool:
        if self.obj.user.pk is None:
            if self._pending_membership_active is not None:
                return self._pending_membership_active
            return True
        if self._pending_membership_active is not None:
            return self._pending_membership_active
        return is_company_access_enabled(self._company, self.obj.user)

    def to_dict(self):
        d = super().to_dict()
        d['active'] = self._membership_active()
        d['groups'] = self._group_refs()
        return d

    def _group_refs(self) -> list[dict]:
        company = self._company
        user = self.obj.user
        if user.pk is None:
            return []
        groups = CompanyGroup.objects.filter(
            company=company,
            members=user,
            source=CompanyGroup.SOURCE_SCIM,
        ).order_by('display_name')
        refs = []
        for group in groups:
            group_adapter = ShellUIScimGroup(group, request=self.request)
            refs.append(
                {
                    'value': group_adapter.id,
                    '$ref': group_adapter.location,
                    'display': group.display_name,
                    'type': 'direct',
                }
            )
        return refs

    def from_dict(self, d):
        body = dict(d)
        active = body.pop('active', None)
        if active is not None:
            self._pending_membership_active = bool(active)
        super().from_dict(body)

    def _emit_membership_change(self, company, user, *, was_enabled: bool, enabled: bool) -> None:
        if was_enabled == enabled:
            return
        if enabled:
            emit_user_provisioned(company, user)
        else:
            emit_user_deprovisioned(company, user)

    def save(self):
        company = self._company
        user = self.obj.user
        is_new = user.pk is None
        was_enabled = False if is_new else is_company_access_enabled(company, user)
        if is_new:
            if not user.username:
                user.username = (user.email or self.obj.scim_username or '').strip()
            if not user.username:
                raise exceptions.BadRequestError('userName or primary email is required.')
            if not user.has_usable_password():
                user.set_unusable_password()
        self.obj.user.save()
        self.obj.save_scim_fields()
        enabled = True if self._pending_membership_active is None else self._pending_membership_active
        set_company_access(company, user, enabled=enabled)
        if is_new:
            emit_user_provisioned(company, user)
        else:
            self._emit_membership_change(company, user, was_enabled=was_enabled, enabled=enabled)

    def delete(self):
        company = self._company
        user = self.obj.user
        emit_user_deprovisioned(company, user)
        set_company_access(company, user, enabled=False)

    def handle_replace(
        self,
        path: Optional[AttrPath],
        value: Union[str, list, dict],
        operation: dict,
    ):
        if path and path.first_path == ('active', None, None):
            company = self._company
            user = self.obj.user
            was_enabled = is_company_access_enabled(company, user)
            enabled = bool(value)
            set_company_access(company, user, enabled=enabled)
            self._pending_membership_active = enabled
            self._emit_membership_change(company, user, was_enabled=was_enabled, enabled=enabled)
            return
        super().handle_replace(path, value, operation)


UserModel = get_user_model()


class ShellUIScimGroup(_ShellUIResourceTypeMixin, SCIMGroup):
    """Map SCIM Group resources to ``CompanyGroup`` for ``request.scim_company``."""

    id_field = 'pk'
    ATTR_MAP = ShellUIGroupFilterQuery.attr_map

    @property
    def _company(self):
        company = get_scim_company(self.request)
        if company is None:
            raise exceptions.BadRequestError('SCIM company context is missing.')
        return company

    @property
    def display_name(self):
        return self.obj.display_name

    @property
    def path(self):
        company = self._company
        return reverse('scim:groups', kwargs={'uuid': self.id, 'company_slug': company.slug})

    @property
    def location(self):
        return urljoin(get_base_scim_location_getter()(self.request), self.path)

    @property
    def members(self):
        dicts = []
        for user in self.obj.members.filter(companies=self._company).distinct().order_by('pk'):
            scim_user = ShellUIScimUser(user, request=self.request)
            dicts.append(
                {
                    'value': scim_user.id,
                    '$ref': scim_user.location,
                    'display': scim_user.display_name,
                    'type': 'User',
                }
            )
        for nested in self.obj.member_groups.filter(
            company=self._company,
            source=CompanyGroup.SOURCE_SCIM,
        ).order_by('pk'):
            nested_adapter = ShellUIScimGroup(nested, request=self.request)
            dicts.append(
                {
                    'value': nested_adapter.id,
                    '$ref': nested_adapter.location,
                    'display': nested.display_name,
                    'type': 'Group',
                }
            )
        return dicts

    def from_dict(self, d):
        scim_external_id = d.get('externalId')
        if scim_external_id is not None:
            self.obj.scim_external_id = scim_external_id
        display = d.get('displayName')
        if display is not None:
            self.obj.display_name = display or ''
        members = d.get('members')
        if members is not None:
            self._pending_members = members

    def _group_name_operation(self) -> str:
        return OPERATION_RENAME if self.obj.pk is not None else OPERATION_CREATE

    def _raise_display_name_conflict(self, conflict: CompanyGroup) -> None:
        record_group_display_name_conflict(
            company=self._company,
            display_name=self.obj.display_name,
            conflict=conflict,
            channel=ScimProvisioningEvent.CHANNEL_SCIM,
            operation=self._group_name_operation(),
            scim_token=getattr(self.request, 'scim_token', None),
        )
        if conflict.source == CompanyGroup.SOURCE_MANUAL:
            raise exceptions.IntegrityError(
                detail=(
                    'displayName is already used by a Shellui-managed (manual) group '
                    'in this company.'
                ),
            )
        raise exceptions.IntegrityError(
            detail='displayName is already used by another SCIM group in this company.',
        )

    def _assert_scim_display_name_available(self) -> None:
        conflict = first_display_name_conflict(
            self._company,
            self.obj.display_name,
            exclude_pk=self.obj.pk,
        )
        if conflict is not None:
            self._raise_display_name_conflict(conflict)

    def save(self):
        if not (self.obj.display_name or '').strip():
            raise exceptions.BadRequestError('displayName is required.')
        if self.obj.pk is not None and self.obj.company_id != self._company.pk:
            raise exceptions.NotFoundError(str(self.obj.pk))
        is_new = self.obj.pk is None
        previous = None
        if not is_new:
            previous = CompanyGroup.objects.filter(pk=self.obj.pk).first()
        self.obj.company = self._company
        self.obj.source = CompanyGroup.SOURCE_SCIM
        self._assert_scim_display_name_available()
        try:
            self.obj.save(scim_source=True)
        except DjangoIntegrityError as exc:
            conflict = first_display_name_conflict(
                self._company,
                self.obj.display_name,
                exclude_pk=self.obj.pk,
            )
            if conflict is not None:
                self._raise_display_name_conflict(conflict)
            raise exceptions.IntegrityError(
                detail='displayName conflicts with an existing group in this company.',
            ) from exc
        pending = getattr(self, '_pending_members', None)
        if pending is not None:
            self._set_members(pending)
            del self._pending_members
        company = self._company
        if is_new:
            emit_group_created(company, self.obj)
        elif previous is not None:
            changed: list[str] = []
            if previous.display_name != self.obj.display_name:
                changed.append('display_name')
            if previous.scim_external_id != self.obj.scim_external_id:
                changed.append('external_id')
            if changed:
                emit_group_updated(company, self.obj, changed_fields=changed)

    def delete(self):
        company = self._company
        emit_group_deleted(company, self.obj)
        self.obj.delete()

    def _validated_users(self, user_ids: list[int]):
        if not user_ids:
            return UserModel.objects.none()
        users = UserModel.objects.filter(pk__in=user_ids, companies=self._company).distinct()
        if users.count() != len(set(user_ids)):
            raise exceptions.NotFoundError('User member not found in this company.')
        return users

    def _validated_member_groups(self, group_ids: list[int]):
        if not group_ids:
            return CompanyGroup.objects.none()
        groups = CompanyGroup.objects.filter(
            pk__in=group_ids,
            company=self._company,
            source=CompanyGroup.SOURCE_SCIM,
        )
        if groups.count() != len(set(group_ids)):
            raise exceptions.NotFoundError(
                'One or more nested group members were not found in this company.'
            )
        for child in groups:
            try:
                assert_nested_group_link_allowed(self.obj, child)
            except NestedGroupCycleError as exc:
                raise exceptions.BadRequestError(str(exc)) from exc
        return groups

    def _apply_member_parsed(self, parsed, *, replace: bool):
        users = self._validated_users(parsed.user_ids)
        nested = self._validated_member_groups(parsed.group_ids)
        change = 'members_replaced' if replace else 'members_added'
        if replace:
            self.obj.members.set(users)
            self.obj.member_groups.set(nested)
        else:
            for user in users:
                self.obj.members.add(user)
            for group in nested:
                self.obj.member_groups.add(group)
        emit_group_membership_changed(
            self._company,
            self.obj,
            change=change,
            user_ids=parsed.user_ids,
            nested_group_ids=parsed.group_ids,
        )

    def _set_members(self, members):
        self._apply_member_parsed(parse_scim_members(members), replace=True)

    def handle_add(self, path, value, operation):
        if path.first_path == ('members', None, None):
            self._apply_member_parsed(parse_scim_members(value or []), replace=False)
            return
        raise exceptions.NotImplementedError

    def handle_remove(self, path, value, operation):
        if path.first_path == ('members', None, None):
            parsed = parse_scim_members(value or [])
            if parsed.user_ids:
                users = self._validated_users(parsed.user_ids)
                for user in users:
                    self.obj.members.remove(user)
            if parsed.group_ids:
                nested = CompanyGroup.objects.filter(
                    pk__in=parsed.group_ids,
                    company=self._company,
                    source=CompanyGroup.SOURCE_SCIM,
                )
                if nested.count() != len(set(parsed.group_ids)):
                    raise exceptions.NotFoundError('One or more nested group members were not found.')
                for group in nested:
                    self.obj.member_groups.remove(group)
            emit_group_membership_changed(
                self._company,
                self.obj,
                change='members_removed',
                user_ids=parsed.user_ids,
                nested_group_ids=parsed.group_ids,
            )
            return
        raise exceptions.NotImplementedError

    def handle_replace(self, path, value, operation):
        if path and path.first_path == ('displayName', None, None):
            self.obj.display_name = str(value or '')
            self.save()
            return
        if path and path.first_path == ('externalId', None, None):
            self.obj.scim_external_id = value
            self.save()
            return
        if path and path.first_path == ('members', None, None):
            self._set_members(value or [])
            return
        super().handle_replace(path, value, operation)
