from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model

from rest_framework.generics import RetrieveAPIView
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.status import HTTP_200_OK
from rest_framework.decorators import (
    api_view,
    permission_classes,
)
from rest_framework import (
    permissions,
    generics,
)

from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

from drf_spectacular.views import extend_schema

from auth.serializers import (
    ProfileSerializer,
    TokenPairSerializer,
    MyTokenObtainPairSerializer,
)
from auth.models import Profile


@extend_schema(tags=["auth"])
@csrf_exempt
@api_view(["GET"])
@permission_classes([permissions.AllowAny])
def info(request: Request) -> Response:
    data = {
        "roles": ["admin"],
        "avatar": "mock",
        "name": "Mock M. M.",
    }

    return Response(data, status=HTTP_200_OK)


@extend_schema(tags=["auth"])
class ProfileRetrieveAPIView(RetrieveAPIView):
    queryset = Profile.objects.all()
    serializer_class = ProfileSerializer

    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        queryset = self.filter_queryset(self.get_queryset())
        obj = get_object_or_404(queryset, user=self.request.user)
        return obj


@extend_schema(tags=["auth"])
class AuthLink(generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request, email):
        user = get_user_model().objects.get(email=email)
        token = MyTokenObtainPairSerializer.get_token(user)

        print(f"{request.META.get('HTTP_HOST')}"
              f"/auth/password/create?access_token={str(token)}")
        return Response(status=HTTP_200_OK)


TokenObtainPairExtendedView = extend_schema(
    responses={200: TokenPairSerializer},
    tags=["auth"],
)(TokenObtainPairView)

TokenRefreshExtendedView = extend_schema(
    responses={200: TokenPairSerializer},
    tags=["auth"],
)(TokenRefreshView)
