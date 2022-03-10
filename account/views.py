from http import client
from secrets import choice
from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.contrib.sessions.models import Session
from .serializers import UserSerializer
from .models import User
import string
import random	
import hashlib


def generate_token(user_info):
    hash_object = hashlib.sha1(user_info.encode())
    hex_dig = hash_object.hexdigest()
    return hex_dig

@api_view()
def hello_world(request):
 
    print(Session.objects.all().delete())
    return Response({"message": "Hello, world!"})

@api_view(['POST'])
def oauth_token(request):
    username = request.data['username']
    password = request.data['password']
    client_id = request.data['client_id']
    client_secret = request.data['client_secret']

    response={
                "error":"invalid_request",
                "Error_description":"Username atau password salah!"
        }

    try:
        user = User.objects.filter(username=username).first()
        if user.check_password(password) or user.password==password:
           

            if 'access_token' in request.session:
                return Response({'isLogin':True, 'username':request.session['username']})

            user_info = f"{username}-{client_id}"
            access_token = generate_token(user_info)
            refresh_token = generate_token(user_info[::-1])

            request.session['access_token'] = access_token
            request.session['username'] = username
            request.session['client_id'] = client_id
            request.session.set_expiry(300)

            response={
                "access_token" : access_token,
                "expires_in" : 300,
                "token_type" : "Bearer",
                "scope" : None,
                "refresh_token" : refresh_token
            }
            return Response(response)
        else:
            return Response(response, status=401)
    except:
        return Response(response, status=401)

