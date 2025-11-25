import json
import ipaddress

# Cloudflare IPv4 ranges from https://www.cloudflare.com/ips-v4
CLOUDFLARE_IP_RANGES = [
    ipaddress.ip_network('173.245.48.0/20'),
    ipaddress.ip_network('103.21.244.0/22'),
    ipaddress.ip_network('103.22.200.0/22'),
    ipaddress.ip_network('103.31.4.0/22'),
    ipaddress.ip_network('141.101.64.0/18'),
    ipaddress.ip_network('108.162.192.0/18'),
    ipaddress.ip_network('190.93.240.0/20'),
    ipaddress.ip_network('188.114.96.0/20'),
    ipaddress.ip_network('197.234.240.0/22'),
    ipaddress.ip_network('198.41.128.0/17'),
    ipaddress.ip_network('162.158.0.0/15'),
    ipaddress.ip_network('104.16.0.0/13'),
    ipaddress.ip_network('104.24.0.0/14'),
    ipaddress.ip_network('172.64.0.0/13'),
    ipaddress.ip_network('131.0.72.0/22'),
]

def is_cloudflare_ip(ip_str):
    """Check if the IP address is from Cloudflare's network"""
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in network for network in CLOUDFLARE_IP_RANGES)
    except ValueError:
        return False

def lambda_handler(event, context):
    """
    API handler for EC2 Manager.
    Handles API requests routed from manager.116.capital/api/*
    Same origin = no CORS headers needed!
    SECURITY: Validates source IP is from Cloudflare network
    """
    # Extract request details
    path = event.get('rawPath', '/')
    method = event.get('requestContext', {}).get('http', {}).get('method', 'GET')
    headers = event.get('headers', {})

    # Get source IP
    source_ip = event.get('requestContext', {}).get('http', {}).get('sourceIp')

    # Response headers
    response_headers = {
        'Content-Type': 'application/json'
    }

    # SECURITY: Block requests not from Cloudflare
    if not source_ip or not is_cloudflare_ip(source_ip):
        return {
            'statusCode': 403,
            'headers': response_headers,
            'body': json.dumps({
                'error': 'Forbidden',
                'message': 'Access denied. Requests must come through Cloudflare.'
            })
        }

    # Get authenticated user from Cloudflare Access header
    authenticated_user = headers.get('cf-access-authenticated-user-email', 'unknown')

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
