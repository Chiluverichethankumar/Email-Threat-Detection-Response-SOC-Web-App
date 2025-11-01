from django.urls import path
from . import views

urlpatterns = [
    path('', views.upload_email, name='upload'),
    path('history/', views.history, name='history'),
    path('report/<uuid:pk>/pdf/', views.report_pdf, name='report_pdf'),
]