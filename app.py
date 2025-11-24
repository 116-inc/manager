import json
import base64
from pathlib import Path


def lambda_handler(event, context):
    """
    Simple Lambda handler that serves static HTML and handles API requests.
    """
    path = event.get('rawPath', '/')

    # Serve index.html for root path
    if path == '/' or path == '/index.html':
        html_content = Path('index.html').read_text()
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'text/html',
            },
            'body': html_content
        }

    # API endpoint
    if path == '/api/status':
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
            },
            'body': json.dumps({
                'status': 'ok',
                'message': 'API is working',
                'authenticated_user': event.get('headers', {}).get('cf-access-authenticated-user-email', 'unknown')
            })
        }

    # 404 for other paths
    return {
        'statusCode': 404,
        'headers': {
            'Content-Type': 'application/json',
        },
        'body': json.dumps({'error': 'Not found'})
    }
