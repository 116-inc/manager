import json


def lambda_handler(event, context):
    """
    API handler for EC2 Manager.
    Handles API requests routed from manager.116.capital/api/*
    Same origin = no CORS headers needed!
    """
    # Extract request details
    path = event.get('rawPath', '/')
    method = event.get('requestContext', {}).get('http', {}).get('method', 'GET')
    headers = event.get('headers', {})

    # Get authenticated user from Cloudflare Access header
    authenticated_user = headers.get('cf-access-authenticated-user-email', 'unknown')

    # Response headers
    response_headers = {
        'Content-Type': 'application/json'
    }

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
