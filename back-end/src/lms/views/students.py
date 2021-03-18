from rest_framework.viewsets import ModelViewSet
from rest_framework.filters import SearchFilter

from django_filters.rest_framework import DjangoFilterBackend

from drf_spectacular.views import extend_schema

from common.constants import MUTATE_ACTIONS

from lms.models.students import Student
from lms.filters.students import StudentFilter
from lms.serializers.students import (
    StudentSerializer,
    StudentMutateSerializer,
)

from auth.permissions import BasicPermission


class StudentPermission(BasicPermission):
    permission_class = 'auth.student'


@extend_schema(tags=['students'])
class StudentViewSet(ModelViewSet):
    queryset = Student.objects.all()

    permission_classes = [StudentPermission]
    filter_backends = [DjangoFilterBackend, SearchFilter]

    filterset_class = StudentFilter
    search_fields = ['surname', 'name', 'patronymic']

    def get_serializer_class(self):
        if self.action in MUTATE_ACTIONS:
            return StudentMutateSerializer
        return StudentSerializer