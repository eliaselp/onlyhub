"""LinkWolf URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.conf import settings
from django.urls import path
from django.conf.urls.static import static
from App.views import login,register,verificacion,index,forget_pass


urlpatterns = [
    path('admin/', admin.site.urls,name="admin"),
    path('login/',login,name="login"),
    path('',login,name="login"),
    path('register/',register,name="verificacion"),
    path('verificacion/',verificacion,name="verificacion"),
    path('index/',index,name="index"),
    path('forget_pass',forget_pass,name='forget')
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

handler404 = 'App.views.e404'