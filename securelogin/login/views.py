from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from . import RDH_AES_ECC
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.response import Response
# Create your views here.

def index(request):
    return HttpResponse("Login page")

class ENC(APIView):

    def post(self, request):
        password = request.data['password']
        print (password)
        f = open("Data.txt", "w")
        f.write(password)
        RDH_AES_ECC.start(password)
        return JsonResponse([{'Password' : password}], safe=False)
