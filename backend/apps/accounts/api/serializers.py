from django.contrib.auth import get_user_model
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "name", "email", "role", "is_active", "last_login", "created_at")
        read_only_fields = fields


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)

    class Meta:
        model = User
        fields = ("id", "name", "email", "password", "role")
        read_only_fields = ("id", "role")

    def create(self, validated_data):
        return User.objects.create_user(role=User.Role.USER, **validated_data)


class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "name", "email", "role", "created_at")
        read_only_fields = ("id", "email", "role", "created_at")


class ForgotPasswordPlaceholderSerializer(serializers.Serializer):
    email = serializers.EmailField()


class AdminUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=False, min_length=8)

    class Meta:
        model = User
        fields = (
            "id",
            "name",
            "email",
            "password",
            "role",
            "is_active",
            "is_staff",
            "last_login",
            "created_at",
            "updated_at",
        )
        read_only_fields = ("id", "last_login", "created_at", "updated_at")

    def create(self, validated_data):
        password = validated_data.pop("password", None) or "ChangeMe123!"
        if validated_data.get("role") == User.Role.ADMIN:
            validated_data["is_staff"] = True
        return User.objects.create_user(password=password, **validated_data)

    def update(self, instance, validated_data):
        password = validated_data.pop("password", None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        if instance.role == User.Role.ADMIN:
            instance.is_staff = True
        if password:
            instance.set_password(password)
        instance.save()
        return instance


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token["role"] = user.role
        token["name"] = user.name
        return token

    def validate(self, attrs):
        data = super().validate(attrs)
        data["user"] = UserSerializer(self.user).data
        return data
