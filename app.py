import json
import jwt
import requests
import os
import sqlite3

# Cloudflare Access Team Domain
TEAM_DOMAIN = "116capital.cloudflareaccess.com"

# Database path (mounted EFS)
DB_PATH = os.environ.get('DB_PATH', '/mnt/data/manager.db')


def init_db():
    """Initialize SQLite database with required tables"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS counter (
            id INTEGER PRIMARY KEY,
            value INTEGER NOT NULL DEFAULT 0
        )
    ''')
    # Ensure there's a counter row
    cursor.execute('INSERT OR IGNORE INTO counter (id, value) VALUES (1, 0)')
    conn.commit()
    conn.close()


def get_counter():
    """Get current counter value"""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT value FROM counter WHERE id = 1')
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else 0


def increment_counter():
    """Increment counter and return new value"""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('UPDATE counter SET value = value + 1 WHERE id = 1')
    conn.commit()
    cursor.execute('SELECT value FROM counter WHERE id = 1')
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else 0

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
    API handler for EC2 Manager.
    Handles API requests routed from manager.116.capital/api/*
    Same origin = no CORS headers needed!
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

    # Status endpoint - handles /api/status
    if path == '/api/status' and method == 'GET':
        return {
            'statusCode': 200,
            'headers': response_headers,
            'body': json.dumps({
                'status': 'ok',
                'message': 'API is working',
                'authenticated_user': authenticated_user,
                'environment': 'production'
            })
        }

    # Counter GET endpoint - handles /api/counter
    if path == '/api/counter' and method == 'GET':
        try:
            value = get_counter()
            return {
                'statusCode': 200,
                'headers': response_headers,
                'body': json.dumps({
                    'counter': value,
                    'authenticated_user': authenticated_user
                })
            }
        except Exception as e:
            print(f"Error getting counter: {e}")
            return {
                'statusCode': 500,
                'headers': response_headers,
                'body': json.dumps({
                    'error': 'Internal server error',
                    'message': str(e)
                })
            }

    # Counter POST endpoint - handles /api/counter (increment)
    if path == '/api/counter' and method == 'POST':
        try:
            value = increment_counter()
            return {
                'statusCode': 200,
                'headers': response_headers,
                'body': json.dumps({
                    'counter': value,
                    'authenticated_user': authenticated_user,
                    'action': 'incremented'
                })
            }
        except Exception as e:
            print(f"Error incrementing counter: {e}")
            return {
                'statusCode': 500,
                'headers': response_headers,
                'body': json.dumps({
                    'error': 'Internal server error',
                    'message': str(e)
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
