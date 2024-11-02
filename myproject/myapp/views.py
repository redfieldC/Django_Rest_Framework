from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken,AccessToken
import random
from django.core.mail import send_mail
from django.contrib.auth.tokens import default_token_generator


OTP_STORAGE={}


@api_view(['POST'])
def send_otp(request):
    email = request.data.get('email')
    if not email:
        return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user = User.objects.get(email=email)
        otp = random.randint(100000, 999999)
        OTP_STORAGE[email] = otp  # Store OTP temporarily
        send_mail(
            'Password Reset OTP',
            f'Your OTP is: {otp}',
            'your-email@example.com',
            [email],
            fail_silently=False,
        )
        return Response({'message': 'OTP sent to email'}, status=status.HTTP_200_OK)
    except User.DoesNotExist:
        return Response({'error': 'User with this email does not exist'}, status=status.HTTP_404_NOT_FOUND)
    
@api_view(['POST'])
def verify_otp(request):
    email = request.data.get('email')
    otp = request.data.get('otp')
    if OTP_STORAGE.get(email) == int(otp):
        del OTP_STORAGE[email]  # OTP is valid, remove it
        token = default_token_generator.make_token(User.objects.get(email=email))
        return Response({'message': 'OTP verified', 'token': token}, status=status.HTTP_200_OK)
    return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def reset_password(request):
    email = request.data.get('email')
    token = request.data.get('token')
    new_password = request.data.get('new_password')

    try:
        user = User.objects.get(email=email)
        if default_token_generator.check_token(user, token):
            user.set_password(new_password)
            user.save()
            return Response({'message': 'Password reset successful'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)
    except User.DoesNotExist:
        return Response({'error': 'User with this email does not exist'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['POST'])
def register_user(request):
    username = request.data.get('username')
    password = request.data.get('password')
    email = request.data.get('email')

    if not username or not password or not email:
        return Response(
            {'error': 'Please provide username, password, and email', 'type': 'MISSING_FIELDS'},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Check if username already exists
    if User.objects.filter(username=username).exists():
        return Response(
            {'error': 'Username already exists', 'type': 'USERNAME_TAKEN'},
            status=status.HTTP_400_BAD_REQUEST
        )
    # Check if username already exists
    if User.objects.filter(email=email).exists():
        return Response(
            {'error': 'email already exists', 'type': 'EMAIL_TAKEN'},
            status=status.HTTP_400_BAD_REQUEST
        )

    user = User.objects.create_user(username=username, password=password, email=email)
    user.save()

    return Response({'message': 'User registered successfully'}, status=status.HTTP_201_CREATED)




@api_view(['POST'])
def login_user(request):
    username = request.data.get('username')
    password = request.data.get('password')

    # Authenticate the user
    user = authenticate(username=username, password=password)

    if user is not None:
        # Create access and refresh tokens
        refresh = RefreshToken.for_user(user)
        access = str(refresh.access_token)

        return Response({
            'refresh': str(refresh),
            'access': access,
            'username': user.username,
            'email': user.email,
        }, status=status.HTTP_200_OK)
    else:
        return Response({'error': 'Invalid credentials','type':'INVALID_CREDENTIALS'}, status=status.HTTP_401_UNAUTHORIZED)


@api_view(['POST'])
def logout_user(request):
    try:
        refresh_token = request.data["refresh"]
        token = RefreshToken(refresh_token)
        token.blacklist()
        return Response({'message': 'Logged out successfully'}, status=status.HTTP_205_RESET_CONTENT)
    except Exception as e:
        return Response({'error': 'Bad Request'}, status=status.HTTP_400_BAD_REQUEST)