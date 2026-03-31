from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import (
    AdminUserViewSet,
    ForgotPasswordPlaceholderAPIView,
    LoginAPIView,
    LogoutAPIView,
    ProfileAPIView,
    RefreshAPIView,
    RegisterAPIView,
)

router = DefaultRouter()
router.register("users", AdminUserViewSet, basename="admin-user")

urlpatterns = [
    path("register/", RegisterAPIView.as_view(), name="auth-register"),
    path("login/", LoginAPIView.as_view(), name="auth-login"),
    path("refresh/", RefreshAPIView.as_view(), name="auth-refresh"),
    path("logout/", LogoutAPIView.as_view(), name="auth-logout"),
    path("profile/", ProfileAPIView.as_view(), name="auth-profile"),
    path("forgot-password/", ForgotPasswordPlaceholderAPIView.as_view(), name="auth-forgot-password"),
    path("", include(router.urls)),
]
