from http import client
from os import access
from secrets import choice
from urllib import response
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
    response={
                "error":"invalid_request",
                "Error_description":"ada kesalahan masbro!"
        }

    try:
        username = request.data['username']
        password = request.data['password']
        client_id = request.data['client_id']
        client_secret = request.data['client_secret']

        user = User.objects.get(username=username, client_id=client_id, client_secret=client_secret)
        if user.check_password(password) or user.password==password:
            if 'access_token' in request.session:
                return Response({'isLogin':True, 'username':request.session['username'], 'Token':request.session['access_token']})

            user_info = f"{username}-{client_id}-{client_secret}"
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

@api_view(['POST'])
def resources(request):
    response = {
        "error" : "invalid_token",
        "error_description" : "Token Salah masbro"
    }

    try:
        input_token = request.headers['authorization']
        access_token = request.session['access_token']

        if input_token.split(" ")[1] == access_token:
            client_id = request.session['client_id']
            user_id = request.session['username']
            user = User.objects.get(username=user_id)
            refresh_token = generate_token(f'{client_id}-{user_id}')

            response={
                "access_token" : access_token ,
                "client_id" : client_id,
                "user_id" : user_id,
                "full_name" : user.full_name,
                "npm" : user.npm,
                "expires" : None,
                "refresh_token" : refresh_token

            }
            return Response(response)
        else:
            return Response(response, status=401)
    except:
        return Response(response, status=401)


