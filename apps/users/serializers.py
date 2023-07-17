from rest_framework import serializers
from rest_framework import exceptions
from rest_framework.generics import get_object_or_404

from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer
from rest_framework_simplejwt.tokens import AccessToken

from django.core.validators import FileExtensionValidator
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.models import update_last_login

from .models import User, UserConfirmation, NEW, CODE_FERIFED, ALL_DONE 
from apps.shared.utility import send_email, check_login_type


class SignUpSerilaizer(serializers.ModelSerializer):
    id = serializers.UUIDField(read_only=True)

    class Meta:
        model = User
        fields = ['id', 'first_name', 
                  'last_name', 'username', 
                  'email', 'password', 
                  'user_status', 'auth_status']   

        extra_kwargs = {
            "user_status": {"read_only": True},
            "auth_status": {"read_only": True}
        }

    def create(self, validated_data):
        user = super(SignUpSerilaizer, self).create(validated_data)
        
        if user.email:
            code = user.create_verify_code(user.email)
            send_email(user.email, code)        
        return user

    def validate(self, attrs):
        username = attrs.get("username", None).lower()
        if username and User.objects.filter(username=username).exists():
            raise exceptions.ValidationError(
                {
                    "success": False,
                    "message": "bu username band qilingan"
                }
            )
        elif len(username) < 5:
            raise exceptions.ValidationError(
                {
                    "success": False,
                    "message": "username kamida 5 ta belgidan iborat bo'lishi shart"
                }
            )
        elif len(username) > 30:
            raise exceptions.ValidationError(
                    {
                    'success': False,
                    'message': "username 30 ta belgidan ko'p bo'lmasligi kerak"
                }
            )       
        elif username[0].isdigit():
            raise exceptions.ValidationError(
                {
                    "success": False,
                    "message": "username'ning birinchi belgisi raqamlardan iborat bo'lishi kerak emas"
                }
            )
        return attrs
    
    def validate_password(self, password):
            if len(password) < 8:
                raise exceptions.ValidationError(
                     {
                        'success': False,
                        'message': "parol 8 ta belgidan kam bo'lmasligi kerak"
                    }
                )
            elif len(password) > 30:
                raise exceptions.ValidationError(
                     {
                        'success': False,
                        'message': "parol 30 ta belgidan ko'p bo'lmasligi kerak"
                    }
                )               
            elif password.isdigit():
                raise exceptions.ValidationError(
                    {
                        'success': False,
                        'message': "parol to'liq raqamlardan iborat bo'lishi mumkin emas"
                    }
                )
            elif self.context['request'].data.get('first_name') in password or self.context['request'].data.get('last_name') in password:
                raise exceptions.ValidationError(
                    {
                        'success': False,
                        'message': "parol ism familia bilan bir xil bo'lishi mumkin emas"
                    }
                )
            return password
    
    def to_representation(self, instance):
        data = super(SignUpSerilaizer, self).to_representation(instance)
        data.update(instance.token())
        return data
    

class ChangeUserPhotoSerializer(serializers.Serializer):
    photo = serializers.ImageField(validators=[FileExtensionValidator(allowed_extensions=[
        'jpg', 'jpeg', 'png', 'heic', 'heif'
    ])])

    def update(self, instance, validated_data):
        photo = validated_data.get('photo', None)
        if photo:
            instance.photo = photo
            instance.auth_status = ALL_DONE
            instance.save()
        return instance


class LoginSerializer(TokenObtainPairSerializer):

    def __init__(self, *args, **kwargs):
        super(LoginSerializer, self).__init__(*args, **kwargs)
        self.fields['userinput'] = serializers.CharField(required=True)
        self.fields['username'] = serializers.CharField(read_only=True, required=False)     

    def auth_validate(self, data):
        user_input = data.get('userinput', None)

        if check_login_type(user_input) == 'email':
            user = self.get_user(email__iexact=user_input)
            username = user.username
        elif check_login_type(user_input) == 'username':
            user = self.get_user(username__iexact=user_input)
            username = user.username
        else:
            raise exceptions.ValidationError(
                {
                    "success": False,
                    "message": f"'{user_input}' yaroqli emas. \nsaitga kirish uchun email yoki usernamedan foydalaning"
                }
            )
        
        authentication_kwargs = {
            self.username_field: username,
            "password": data['password']
        }

        current_user = User.objects.filter(username__iexact=username).first()
        if current_user is not None and current_user.auth_status != ALL_DONE:
            raise exceptions.ValidationError(
                {
                    "success": False,
                    "message": "login qilishingiz uchun ro'yxatdan to'liq o'ting"
                }
            )
        user = authenticate(**authentication_kwargs)

        if user is not None:
            self.user = user
        else:
            raise exceptions.ValidationError(
                {
                    "success": False,
                    "message": "xatolik mavjud. tekshirib qaytadan ruinib ko'ring"
                }
            )

    def validate(self, data):
        self.auth_validate(data)        
        if self.user.auth_status != ALL_DONE:
            raise exceptions.PermissionDenied("saitga kirish uchun, ro'yxatdan to'liq o'ting")
        data = self.user.token()
        data['auth_status'] = self.user.auth_status
        data['full_name'] = self.user.full_name
        return data

    def get_user(self, **kwargs):
        users = User.objects.filter(**kwargs)
        if not users.exists():
            raise exceptions.ValidationError(
                {
                    "success": False,
                    "message": "bunday foydalanuvchi topilmadi"
                }
            )
        return users.first()

        
class LoginRefreshSerializer(TokenRefreshSerializer):

    def validate(self, attrs):
        data = super().validate(attrs)
        access_token_instance = AccessToken(data['access'])
        user_id = access_token_instance['user_id']
        user = get_object_or_404(User, id=user_id)
        update_last_login(None, user)
        return data
    

class LogOutSerializer(serializers.Serializer):
    refresh = serializers.CharField()


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    def validate(self, attrs):
        email = attrs.get('email', None)
        if email is None:
            raise exceptions.ValidationError(
                {
                    "success": False,
                    "message": "maydon bo'sh bo'lishi mumkin emas. \nemail kiritilishi shart"
                }
            )
        user = User.objects.filter(email=email)
        if not user.exists():
            raise exceptions.NotFound("Bunday foydalanuvchi mavjud emas")
        attrs["user"] = user.first()
        return attrs
    

class ResetPasswordSerializer(serializers.ModelSerializer):
    id = serializers.UUIDField(read_only=True)
    password = serializers.CharField(min_length=8, required=True, write_only=True)
    comfirm_password = serializers.CharField(min_length=8, required=True, write_only=True)

    class Meta:
        model = User
        fields = ['id', 'password', 'comfirm_password']

    def validate(self, attrs):
        password = attrs.get('password')
        comfirm_password = attrs.get('comfirm_password')

        if comfirm_password != password:
            raise exceptions.ValidationError(
                {
                    "success": False,
                    "message": "parollaringiz bir xil emas"
                }
            )
        if password:
            validate_password(password)
            validate_password(comfirm_password)
        return attrs

    def update(self, instance, validated_data):
        password = validated_data.pop('password')
        instance.set_password(password)
        return super(ResetPasswordSerializer, self).update(instance, validated_data)

#     {
#     "first_name": "someonefirts",
#     "last_name": "someonelast",
#     "username": "someoneuser",
#     "email": "someone@some.come",
#     "password": "Jidwjidnwd"
# }