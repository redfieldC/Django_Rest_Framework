from django.urls import path,include
from . import views 
urlpatterns = [
    path('api/send-otp/', views.send_otp, name='send_otp'),
    path('api/verify-otp/', views.verify_otp, name='verify_otp'),
    path('api/register/', views.register_user, name='register'),
    path('api/login/', views.login_user, name='login'),
    path('api/logout/', views.logout_user, name='logout'),
    path('api/reset-password/', views.reset_password, name='reset_password'),

    # path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    # path('api/logout/', views.logout_user, name='logout'),
]
