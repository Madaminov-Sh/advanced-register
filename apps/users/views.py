import datetime

from django.core.exceptions import ObjectDoesNotExist

from rest_framework import exceptions
from rest_framework.response import Response
from rest_framework import permissions
from rest_framework.generics import CreateAPIView, UpdateAPIView
from rest_framework.views import APIView

from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

from .models import User, NEW, CODE_FERIFED, ALL_DONE
from .import serializers
from apps.shared.utility import send_email, check_emter_email


class SingUpView(CreateAPIView):
    queryset = User.objects.all()
    permission_classes = [permissions.AllowAny, ]
    serializer_class = serializers.SignUpSerilaizer


class VerifyAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated,]

    def post(self, request, *args, **kwargs):
        user = request.user
        code = request.data.get('code', None)
        self.check_verify(user, code)
        return Response(
            data={
                "success": True,
                "auth_status": user.auth_status,
                "access": user.token()['access_token'],
                "refresh": user.token()['refresh_token']
                },status=200
            )

    @staticmethod
    def check_verify(user, code):
        verifies = user.verify_codes.filter(expiration_time__gte=datetime.datetime.now(), code=code, is_comfirmed=False)
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


class GetVerifyAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated,]

    def get(self, request, *args, **kwargs):
        user = request.user
        self.check_verify(user)

        if user.email:
            code = user.create_verify_code(user.email)
            send_email(user.email, code)
        else:
            raise exceptions.ValidationError(
                {
                    "success": False,
                    "message": "emailingizni xato emasligini tekshiring"
                }
            )
        return Response(
            data={
                "success": True,
                "message": "sizga tasdiqlash kodi qaytadan yuborildi"
            }, status=200
        )

    @staticmethod
    def check_verify(user):
        verifies = user.verify_codes.filter(expiration_time__gte=datetime.datetime.now(), is_comfirmed=False)
        if verifies.exists():
            raise exceptions.ValidationError(
                {
                    "success": False,
                    "message": "sizga yuborilgan tasdiqlash kodi, xalicha yaroqli"
                }
            )
        

class ChangeUserPhotoAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated,]

    def put(self, request, *args, **kwargs):
        serializer = serializers.ChangeUserPhotoSerializer(data=request.data)

        if serializer.is_valid():
            user = request.user
            serializer.update(user, serializer.validated_data)
            return Response(
                {
                    "success": True,
                    "message": "Photo muaffaqiyatli o'rnatilindi"
                }, status=200
            )
        return Response(serializer.errors, status=400)


class LoginAPIView(TokenObtainPairView):
    serializer_class = serializers.LoginSerializer


class LoginRefreshAPIView(TokenRefreshView):
    serializer_class = serializers.LoginRefreshSerializer


class LogOutAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated,]

    def post(self, request, *args, **kwargs):
        serializer = serializers.LogOutSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            refresh_token = request.data['refresh']
            token = RefreshToken(refresh_token)
            token.blacklist()
            data = {
                "success": True,
                "message": "LogOut qilindi",
                "user_full_name": request.user.full_name
            }
            return Response(data, status=205)
        except TokenError:
            return Response(status=400)
        
    
class ForgotPasswordAPIView(APIView):
    permission_classes = [permissions.AllowAny,]

    def post(self, request, *args, **kwargs):
        serializer = serializers.ForgotPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data.get('email')
        user = serializer.validated_data.get('user')    
        self.check_verify(user)
        if check_emter_email(email):
            code = user.create_verify_code(email)
            send_email(email, code)

        return Response(
            {
                "success": True,
                "message": "tasdiqlash kodi yuborildi",
                "access": user.token()['access_token'],
                "refresh": user.token()['refresh_token'],
                "auth_status": user.auth_status
            }, status=200
        )
    
    @staticmethod
    def check_verify(user):
        veifies = user.verify_codes.filter(expiration_time__gte=datetime.datetime.now(),is_comfirmed=False)
        if veifies.exists():
            raise exceptions.ValidationError(
                {
                    "success": False,
                    "message": "sizga yuborilgan kod xalicha faol"
                }
            ) 
        
    
class ResetPasswordView(UpdateAPIView):
    serializer_class = serializers.ResetPasswordSerializer
    permission_classes = [permissions.IsAuthenticated,]

    def get_object(self):
        return self.request.user
    
    def update(self, request, *args, **kwargs):
        response = super(ResetPasswordView, self).update(request, *args, **kwargs)
        try:
            user = User.objects.get(id=response.data.get('id'))
        except ObjectDoesNotExist:
            raise exceptions.NotFound(detail="Bunday user mavjud emas")
        
        return Response(
            {
                "success": True,
                "message": "Parolingiz muvafaqiyatli o'zgartirildi",
                "access": user.token()['access_token'],
                "refresh": user.token()['refresh_token'],
                "auth status": user.auth_status
            }
        )