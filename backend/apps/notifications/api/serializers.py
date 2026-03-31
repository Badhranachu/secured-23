from rest_framework import serializers


class SendLatestSummarySerializer(serializers.Serializer):
    project_id = serializers.IntegerField()
    attach_pdf = serializers.BooleanField(required=False, default=False)
