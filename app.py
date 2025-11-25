import json


def lambda_handler(event, context):
    """
    API handler for EC2 Manager.
    Handles API requests from Cloudflare Pages frontend.
    """
    # Extract request details
    path = event.get('rawPath', '/')
    method = event.get('requestContext', {}).get('http', {}).get('method', 'GET')
    headers = event.get('headers', {})

    # Get authenticated user from Cloudflare Access header
    authenticated_user = headers.get('cf-access-authenticated-user-email', 'unknown')

    # Determine origin for CORS
    origin = headers.get('origin', '')
    allowed_origins = [
        'https://manager.116.capital',
        'https://manager-8ea.pages.dev'
    ]
    cors_origin = origin if origin in allowed_origins else 'https://manager.116.capital'

    # CORS headers
    cors_headers = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': cors_origin,
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': '*',
        'Access-Control-Allow-Credentials': 'true',
    }

    # Handle OPTIONS for CORS preflight
    if method == 'OPTIONS':
        return {
            'statusCode': 200,
            'headers': cors_headers,
            'body': ''
        }

    # Status endpoint
    if path == '/status' and method == 'GET':
        return {
            'statusCode': 200,
            'headers': cors_headers,
            'body': json.dumps({
                'status': 'ok',
                'message': 'API is working',
                'authenticated_user': authenticated_user,
                'environment': 'production'
            })
        }

    # 404 for other paths
    return {
        'statusCode': 404,
        'headers': cors_headers,
        'body': json.dumps({
            'error': 'Not found',
            'path': path,
            'method': method
        })
    }
