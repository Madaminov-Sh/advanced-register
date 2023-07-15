import datetime

from rest_framework import exceptions
from rest_framework.response import Response
from rest_framework import permissions
from rest_framework.generics import CreateAPIView
from rest_framework.views import APIView

from .models import User, NEW, CODE_FERIFED, DONE, PHOTO_DONE
from .import serializers


class SingUpView(CreateAPIView):
    queryset = User.objects.all()
    permission_classes = [permissions.AllowAny, ]
    serializer_class = serializers.SignUpSerilaizer


class VerifyAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated,]

    def post(self, request, *args, **kwargs):
        user = request.user
        code = request.data.get('code', None)
        print('request data: ', request.data)

        self.check_verify(user, code)
        return Response(
            data={
                "success": True,
                "auth_status": user.auth_status,
                "access": user.token()['access_token'],
                "refresh": user.token()['refresh_token']
                }
            )

    @staticmethod
    def check_verify(user, code):
        verifies = user.verify_codes.filter(expiration_time__gte=datetime.datetime.now(), code=code, is_comfirmed=False)
        print('verifies ',verifies)
        if not verifies.exists():
            raise exceptions.ValidationError(
                {
                    "success": False,
                    "message": "tasdiqlash ko'dingiz xato"
                }
            )
        verifies.update(is_comfirmed=True)

        if user.auth_status == NEW:
            user.auth_status = CODE_FERIFED
            user.save()
        return True


