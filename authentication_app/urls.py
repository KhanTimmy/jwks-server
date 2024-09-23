from django.urls import path
from .views import JWKSView, AuthView

urlpatterns = [
    path('.well-known/jwks.json', JWKSView.as_view(), name='jwks'),
    path('auth', AuthView.as_view(), name='auth'),
]
