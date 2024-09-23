import jwt
import json
import datetime
import base64
from django.shortcuts import render
from django.http import JsonResponse, HttpResponseNotAllowed
from django.views import View
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

KEYS = {}  # A dictionary to store keys

def base64url_encode(data):
    # Helper function to base64url-encode integers
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

@method_decorator(csrf_exempt, name='dispatch')
class JWKSView(View):
    def get(self, request):
        # Serve the JWKS (JSON Web Key Set) with only non-expired keys
        now = datetime.datetime.utcnow()

        # Remove any expired keys from the KEYS dictionary
        expired_keys = [kid for kid, (key, expires_at) in KEYS.items() if expires_at <= now]
        for kid in expired_keys:
            del KEYS[kid]

        # Prepare the JWKS with only valid (non-expired) keys
        keys = [
            {
                "kty": "RSA",
                "kid": kid,
                "use": "sig",
                "alg": "RS256",
                "n": base64url_encode(key.public_key().public_numbers().n.to_bytes((key.public_key().public_numbers().n.bit_length() + 7) // 8, byteorder='big')),
                "e": base64url_encode(key.public_key().public_numbers().e.to_bytes((key.public_key().public_numbers().e.bit_length() + 7) // 8, byteorder='big')),
            }
            for kid, (key, expires_at) in KEYS.items() if expires_at > now
        ]

        # Return the JWKS response containing only valid, non-expired keys
        jwks = {"keys": keys}
        return JsonResponse(jwks)

    def post(self, request):
        # Return a 405 Method Not Allowed for POST requests
        return HttpResponseNotAllowed(['POST'])

    def put(self, request):
        # Return a 405 Method Not Allowed for PUT requests
        return HttpResponseNotAllowed(['PUT'])

    def delete(self, request):
        # Return a 405 Method Not Allowed for DELETE requests
        return HttpResponseNotAllowed(['DELETE'])

@method_decorator(csrf_exempt, name='dispatch')
class AuthView(View):
    def post(self, request):
        # Issue a JWT
        now = datetime.datetime.utcnow()
        expired = request.GET.get("expired") == "true"

        # Remove any expired keys from the KEYS dictionary
        expired_keys = [kid for kid, (key, expires_at) in KEYS.items() if expires_at <= now]
        for kid in expired_keys:
            del KEYS[kid]

        # Check for an expired key if 'expired=true' is passed
        key = None
        kid = None
        if expired:
            # Use a key that is already expired, but still issue an expired JWT
            for kid, (k, expires_at) in KEYS.items():
                if expires_at < now:
                    key = k
                    break
        else:
            # Otherwise use a valid (non-expired) key
            for kid, (k, expires_at) in KEYS.items():
                if expires_at > now:
                    key = k
                    break

        # If no valid key found, generate a new one
        if key is None:
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            kid = str(len(KEYS) + 1)
            expires_at = now + datetime.timedelta(minutes=5)  # Key valid for 5 minutes
            KEYS[kid] = (key, expires_at)

        # Generate the JWT
        private_key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # Handle the 'expired' case by setting the 'exp' claim to a past time
        if expired:
            # Set the expiration 5 minutes in the past to make the token expired
            payload = {
                "sub": "userABC",
                "iat": now,
                "exp": now - datetime.timedelta(minutes=5),  # Set expiration in the past
            }
        else:
            # Set the expiration 5 minutes in the future for a valid token
            payload = {
                "sub": "userABC",
                "iat": now,
                "exp": now + datetime.timedelta(minutes=5),  # Set expiration in the future
            }

        token = jwt.encode(payload, private_key_pem, algorithm="RS256", headers={"kid": kid})

        return JsonResponse({"token": token})