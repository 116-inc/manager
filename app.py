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

    # CORS headers
    cors_headers = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': 'https://manager.i.116.capital',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': '*',
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
