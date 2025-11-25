import json
import jwt
import requests
import os
from functools import lru_cache

# Cloudflare Access Team Domain
TEAM_DOMAIN = "116capital.cloudflareaccess.com"

@lru_cache(maxsize=1)
def get_cloudflare_public_keys():
    """Fetch Cloudflare Access public keys for JWT validation"""
    certs_url = f"https://{TEAM_DOMAIN}/cdn-cgi/access/certs"
    try:
        response = requests.get(certs_url, timeout=5)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Error fetching Cloudflare public keys: {e}")
        return None

def validate_cf_access_jwt(token):
    """Validate Cloudflare Access JWT token"""
    if not token:
        return None

    try:
        # Get public keys
        keys_data = get_cloudflare_public_keys()
        if not keys_data or 'keys' not in keys_data:
            print("Failed to fetch Cloudflare public keys")
            return None

        # Get the key ID from token header
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get('kid')

        # Find matching public key
        public_key = None
        for key in keys_data['keys']:
            if key['kid'] == kid:
                public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
                break

        if not public_key:
            print(f"No matching public key found for kid: {kid}")
            return None

        # Verify and decode JWT
        decoded = jwt.decode(
            token,
            public_key,
            algorithms=['RS256'],
            audience=os.environ.get('CF_ACCESS_AUDIENCE', ''),
            options={'verify_aud': False if not os.environ.get('CF_ACCESS_AUDIENCE') else True}
        )

        return decoded

    except jwt.ExpiredSignatureError:
        print("JWT token has expired")
        return None
    except jwt.InvalidTokenError as e:
        print(f"Invalid JWT token: {e}")
        return None
    except Exception as e:
        print(f"Error validating JWT: {e}")
        return None

def lambda_handler(event, context):
    """
    Info API handler for EC2 Manager.
    Handles API requests routed from manager.116.capital/api/info
    SECURITY: Validates Cloudflare Access JWT token
    """
    # Extract request details
    path = event.get('rawPath', '/')
    method = event.get('requestContext', {}).get('http', {}).get('method', 'GET')
    headers = event.get('headers', {})

    # Response headers
    response_headers = {
        'Content-Type': 'application/json'
    }

    # Get JWT token from Cloudflare Access headers
    # Cloudflare Access automatically adds cf-access-jwt-assertion header
    cf_token = headers.get('cf-access-jwt-assertion') or headers.get('cf-authorization')

    # SECURITY: Validate Cloudflare Access JWT
    jwt_payload = validate_cf_access_jwt(cf_token)
    if not jwt_payload:
        return {
            'statusCode': 403,
            'headers': response_headers,
            'body': json.dumps({
                'error': 'Forbidden',
                'message': 'Access denied. Invalid or missing Cloudflare Access token.'
            })
        }

    # Get authenticated user from JWT payload
    authenticated_user = jwt_payload.get('email', 'unknown')

    # Info endpoint - handles /api/info
    if path == '/api/info' and method == 'GET':
        return {
            'statusCode': 200,
            'headers': response_headers,
            'body': json.dumps({
                'service': 'EC2 Manager Info Service',
                'version': '1.0.0',
                'authenticated_user': authenticated_user,
                'permissions': ['read', 'describe'],
                'region': 'us-east-1'
            })
        }

    # 404 for other paths
    return {
        'statusCode': 404,
        'headers': response_headers,
        'body': json.dumps({
            'error': 'Not found',
            'path': path,
            'method': method
        })
    }
