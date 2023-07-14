from rest_framework import serializers
from rest_framework import exceptions
from django.contrib.auth.password_validation import validate_password

from .models import User, UserConfirmation
from apps.shared.utility import send_email


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
        # print(f"this is user email: {user.email}")
        # print(f"this is create: {validated_data}")
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