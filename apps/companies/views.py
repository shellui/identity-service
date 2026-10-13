from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework import mixins, status, viewsets
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from apps.actions.user_hooks import emit_profile_snapshots, snapshot_profiles_for_ids

from .models import Company
from .serializers import CompanySerializer, CompanyUpdateSerializer


@extend_schema_view(
    list=extend_schema(
        tags=['companies'],
        summary='List user companies',
        description='Return companies where the authenticated user is a member.',
    ),
    retrieve=extend_schema(
        tags=['companies'],
        summary='Get company details',
        description='Return company details only if the authenticated user is a member.',
    ),
    partial_update=extend_schema(
        tags=['companies'],
        summary='Update company settings',
        description=(
            'Company owners can update the name, owners list, and join access '
            '(public / domain / invite). Owners and staff can set '
            'desktop_redirect_schemes. An empty list turns desktop sign-in off.'
        ),
        request=CompanyUpdateSerializer,
    ),
    update=extend_schema(
        tags=['companies'],
        summary='Replace company settings',
        description=(
            'Company owners can update the name, owners list, and join access '
            '(public / domain / invite). Owners and staff can set '
            'desktop_redirect_schemes. An empty list turns desktop sign-in off.'
        ),
        request=CompanyUpdateSerializer,
    ),
)
class CompanyViewSet(
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet,
):
    serializer_class = CompanySerializer
    permission_classes = [IsAuthenticated]
    queryset = Company.objects.none()

    def get_queryset(self):
        return Company.objects.filter(members=self.request.user)

    def update(self, request, *args, **kwargs):
        return self.partial_update(request, *args, **kwargs)

    def partial_update(self, request, *args, **kwargs):
        company = self.get_object()
        is_owner = company.owners.filter(pk=request.user.pk).exists()
        is_staff = bool(getattr(request.user, 'is_staff', False))
        if not is_owner and not is_staff:
            return Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)

        if 'verified_email_domains' in request.data:
            return Response(
                {'error': 'verified_email_domains is managed by Shellui operators, not company admins.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        serializer = CompanyUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated = serializer.validated_data
        if not is_owner and any(
            key in validated for key in ('name', 'owner_ids', 'access_mode', 'allowed_email_domains')
        ):
            return Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)

        if 'owner_ids' in validated and not validated['owner_ids']:
            return Response(
                {
                    'error': 'A company needs at least one owner.',
                    'error_code': 'company_owner_required',
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        update_fields: list[str] = []
        if 'name' in validated:
            company.name = validated['name']
            update_fields.append('name')
        if 'access_mode' in validated:
            company.access_mode = validated['access_mode']
            update_fields.append('access_mode')
        if 'allowed_email_domains' in validated:
            company.allowed_email_domains = validated['allowed_email_domains']
            update_fields.append('allowed_email_domains')
        if 'desktop_redirect_schemes' in validated:
            company.desktop_redirect_schemes = validated['desktop_redirect_schemes']
            update_fields.append('desktop_redirect_schemes')
        if update_fields:
            company.save(update_fields=update_fields)

        if 'owner_ids' in validated:
            owner_ids = validated['owner_ids']
            members_qs = company.members.filter(pk__in=owner_ids)
            if members_qs.count() != len(set(owner_ids)):
                return Response(
                    {'error': 'All owners must be members of this company.'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            before_ids = set(company.owners.values_list('pk', flat=True))
            befores = snapshot_profiles_for_ids(company, before_ids.symmetric_difference(owner_ids))
            company.owners.set(members_qs)
            emit_profile_snapshots(company, befores, source='rest')

        return Response(CompanySerializer(company).data)
