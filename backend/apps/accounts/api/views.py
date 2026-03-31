from django.contrib.auth import get_user_model
from rest_framework import generics, status, viewsets
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from apps.common.permissions import IsAdminRole

from .serializers import (
    AdminUserSerializer,
    CustomTokenObtainPairSerializer,
    ForgotPasswordPlaceholderSerializer,
    ProfileSerializer,
    RegisterSerializer,
)

User = get_user_model()


class RegisterAPIView(generics.CreateAPIView):
    permission_classes = [AllowAny]
    serializer_class = RegisterSerializer


class LoginAPIView(TokenObtainPairView):
    permission_classes = [AllowAny]
    serializer_class = CustomTokenObtainPairSerializer


class RefreshAPIView(TokenRefreshView):
    permission_classes = [AllowAny]


class ProfileAPIView(generics.RetrieveUpdateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ProfileSerializer

    def get_object(self):
        return self.request.user


class ForgotPasswordPlaceholderAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ForgotPasswordPlaceholderSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(
            {
                "detail": "Password reset flow is not wired yet. Configure SMTP and token flow in a later hardening pass.",
                "email": serializer.validated_data["email"],
            },
            status=status.HTTP_202_ACCEPTED,
        )


class LogoutAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        refresh = request.data.get("refresh")
        if not refresh:
            return Response({"detail": "Refresh token is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            RefreshToken(refresh).blacklist()
        except Exception:
            return Response({"detail": "Invalid refresh token."}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"detail": "Logged out successfully."}, status=status.HTTP_200_OK)


class AdminUserViewSet(viewsets.ModelViewSet):
    serializer_class = AdminUserSerializer
    permission_classes = [IsAuthenticated, IsAdminRole]
    search_fields = ("name", "email", "role")
    ordering_fields = ("created_at", "last_login", "name", "email")
    ordering = ("-created_at",)

    def get_queryset(self):
        queryset = User.objects.all()
        role = self.request.query_params.get("role")
        is_active = self.request.query_params.get("is_active")
        if role:
            queryset = queryset.filter(role=role)
        if is_active in {"true", "false"}:
            queryset = queryset.filter(is_active=is_active == "true")
        return queryset
