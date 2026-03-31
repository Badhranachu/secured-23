from django.db import connection
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView


class HealthCheckAPIView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        database_ok = True
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                cursor.fetchone()
        except Exception:
            database_ok = False

        payload = {
            "service": "AEGIS AI API",
            "status": "ok" if database_ok else "degraded",
            "database": "up" if database_ok else "down",
        }
        return Response(payload)
