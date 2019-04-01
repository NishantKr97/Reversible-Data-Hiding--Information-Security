from django.contrib import admin
from django.conf.urls import url
from . import views

app_name = 'login'

urlpatterns = [
    # /login/
    url(r'^$', views.index, name='index'),

    # /login/encrypt
    url(r'^encrypt/$', views.ENC.as_view(), name='encrypt')
]