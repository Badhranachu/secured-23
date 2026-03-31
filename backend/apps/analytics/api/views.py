from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.common.permissions import IsAdminRole

from ..services.dashboard import DashboardService


class UserDashboardSummaryAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        data = DashboardService().get_user_summary(request.user)
        return Response(data)


class AdminDashboardSummaryAPIView(APIView):
    permission_classes = [IsAuthenticated, IsAdminRole]

    def get(self, request):
        data = DashboardService().get_admin_summary()
        return Response(data)
