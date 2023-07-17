from django.urls import path

from . import views


urlpatterns = [
    path('login/', views.LoginAPIView.as_view()),
    path('logout/', views.LogOutAPIView.as_view()),
    path('refresh/login/', views.LoginRefreshAPIView.as_view()),
    path('signup/', views.SingUpView.as_view()),
    path('verify/code/', views.VerifyAPIView.as_view()),
    path('get/verify/code/', views.GetVerifyAPIView.as_view()),
    path('change/photo/', views.ChangeUserPhotoAPIView.as_view()),
    path('forgot/password/', views.ForgotPasswordAPIView.as_view()),
    path('reset/password/', views.ResetPasswordView.as_view()),
]