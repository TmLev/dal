from django.contrib import admin
from django.urls import path, include

from rest_framework import permissions

from drf_yasg import openapi
from drf_yasg.views import get_schema_view

from backend.views import (
    authors,
    delete_document,
    documents,
    get_file,
    get_tags,
    info,
    login,
    logout,
    populate,
    published_places,
    subjects,
    CategoryView,
    SubjectSectionView,
    UploadNirView,
)

from mil_lms_backend.views.populate import lms_populate

SchemaView = get_schema_view(
    openapi.Info(
        title="DMS and LMS REST API",
        default_version="v1",
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    path("admin/", admin.site.urls),
    path("populate/", populate),
    path("api/authors", authors),
    path("api/category", CategoryView.as_view()),
    path("api/delete_document", delete_document),
    path("api/documents", documents),
    path("api/get_file", get_file),
    path("api/get_tags", get_tags),
    path("api/published_places", published_places),
    path("api/subject", SubjectSectionView.as_view()),
    path("api/subjects", subjects),
    path("api/upload", UploadNirView.as_view()),
    path("api/user/info", info),
    path("api/user/login", login),
    path("api/user/logout", logout),
    path("lms_populate/", lms_populate),
    path("api/lms/", include("mil_lms_backend.urls")),
    path("swagger/",
         SchemaView.with_ui("swagger", cache_timeout=0),
         name="schema-swagger-ui"),
]
