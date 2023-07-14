from rest_framework import permissions
from rest_framework.generics import CreateAPIView

from .models import User
from .import serializers


class SingUpView(CreateAPIView):
    queryset = User.objects.all()
    permission_classes = [permissions.AllowAny, ]
    serializer_class = serializers.SignUpSerilaizer
