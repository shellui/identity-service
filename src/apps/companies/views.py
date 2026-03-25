from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework import mixins, viewsets
from rest_framework.permissions import IsAuthenticated

from .models import Company
from .serializers import CompanySerializer


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
)
class CompanyViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    serializer_class = CompanySerializer
    permission_classes = [IsAuthenticated]
    lookup_field = 'slug'
    queryset = Company.objects.none()

    def get_queryset(self):
        return Company.objects.filter(members=self.request.user)
