import json
import jwt
import requests
import os
import sqlite3
import time
import hashlib
import hmac
import boto3
from urllib.parse import urlencode
from fastapi import FastAPI, Request, HTTPException, Depends
from mangum import Mangum

# Cloudflare Access Team Domain
TEAM_DOMAIN = "116capital.cloudflareaccess.com"

# Database path (mounted EFS)
DB_PATH = os.environ.get('DB_PATH', '/mnt/data/manager.db')

app = FastAPI(title="EC2 Manager API")


# --- Database ---

def get_db():
    """Get database connection - must be created per-request for thread safety"""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


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
    cursor.execute('INSERT OR IGNORE INTO counter (id, value) VALUES (1, 0)')
    conn.commit()
    conn.close()


# Initialize on cold start
init_db()


# --- Auth ---

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


def validate_cf_access_jwt(token: str):
    """Validate Cloudflare Access JWT token"""
    if not token:
        return None

    try:
        keys_data = get_cloudflare_public_keys()
        if not keys_data or 'keys' not in keys_data:
            print("Failed to fetch Cloudflare public keys")
            return None

        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get('kid')

        public_key = None
        for key in keys_data['keys']:
            if key['kid'] == kid:
                public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
                break

        if not public_key:
            print(f"No matching public key found for kid: {kid}")
            return None

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


async def get_current_user(request: Request) -> dict:
    """Dependency to get authenticated user from Cloudflare Access JWT"""
    cf_token = request.headers.get('cf-access-jwt-assertion') or request.headers.get('cf-authorization')

    jwt_payload = validate_cf_access_jwt(cf_token)
    if not jwt_payload:
        raise HTTPException(
            status_code=403,
            detail="Access denied. Invalid or missing Cloudflare Access token."
        )

    return {
        "email": jwt_payload.get('email', 'unknown'),
        "payload": jwt_payload
    }


# --- Routes ---

@app.get("/api/status")
async def status(user: dict = Depends(get_current_user)):
    return {
        "status": "ok",
        "message": "API is working",
        "authenticated_user": user["email"],
        "environment": "production"
    }


@app.get("/api/counter")
async def get_counter(user: dict = Depends(get_current_user)):
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('SELECT value FROM counter WHERE id = 1')
        result = cursor.fetchone()
        return {
            "counter": result[0] if result else 0,
            "authenticated_user": user["email"]
        }
    finally:
        db.close()


@app.post("/api/counter")
async def increment_counter(user: dict = Depends(get_current_user)):
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('UPDATE counter SET value = value + 1 WHERE id = 1')
        db.commit()
        cursor.execute('SELECT value FROM counter WHERE id = 1')
        result = cursor.fetchone()
        return {
            "counter": result[0] if result else 0,
            "authenticated_user": user["email"],
            "action": "incremented"
        }
    finally:
        db.close()


# --- AWS Clients ---

lightsail = boto3.client('lightsail', region_name='us-east-1')
secretsmanager = boto3.client('secretsmanager', region_name='us-east-1')

SECRETS_PREFIX = "moontrader/"


@app.get("/api/instances")
async def list_instances(user: dict = Depends(get_current_user)):
    """List all Lightsail instances"""
    try:
        response = lightsail.get_instances()
        instances = []
        for inst in response.get('instances', []):
            instances.append({
                "name": inst['name'],
                "state": inst['state']['name'],
                "publicIp": inst.get('publicIpAddress'),
                "privateIp": inst.get('privateIpAddress'),
                "blueprintId": inst.get('blueprintId'),
                "bundleId": inst.get('bundleId'),
                "region": inst['location']['regionName'],
                "createdAt": inst['createdAt'].isoformat() if inst.get('createdAt') else None
            })
        return {"instances": instances, "provider": "lightsail"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/instances/{name}")
async def get_instance(name: str, user: dict = Depends(get_current_user)):
    """Get a specific Lightsail instance"""
    try:
        response = lightsail.get_instance(instanceName=name)
        inst = response['instance']
        return {
            "name": inst['name'],
            "state": inst['state']['name'],
            "publicIp": inst.get('publicIpAddress'),
            "privateIp": inst.get('privateIpAddress'),
            "blueprintId": inst.get('blueprintId'),
            "bundleId": inst.get('bundleId'),
            "region": inst['location']['regionName'],
            "createdAt": inst['createdAt'].isoformat() if inst.get('createdAt') else None
        }
    except lightsail.exceptions.NotFoundException:
        raise HTTPException(status_code=404, detail=f"Instance '{name}' not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/instances/{name}/start")
async def start_instance(name: str, user: dict = Depends(get_current_user)):
    """Start a Lightsail instance"""
    try:
        lightsail.start_instance(instanceName=name)
        return {"status": "starting", "instance": name, "action_by": user["email"]}
    except lightsail.exceptions.NotFoundException:
        raise HTTPException(status_code=404, detail=f"Instance '{name}' not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/instances/{name}/stop")
async def stop_instance(name: str, user: dict = Depends(get_current_user)):
    """Stop a Lightsail instance"""
    try:
        lightsail.stop_instance(instanceName=name)
        return {"status": "stopping", "instance": name, "action_by": user["email"]}
    except lightsail.exceptions.NotFoundException:
        raise HTTPException(status_code=404, detail=f"Instance '{name}' not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/instances/{name}/reboot")
async def reboot_instance(name: str, user: dict = Depends(get_current_user)):
    """Reboot a Lightsail instance"""
    try:
        lightsail.reboot_instance(instanceName=name)
        return {"status": "rebooting", "instance": name, "action_by": user["email"]}
    except lightsail.exceptions.NotFoundException:
        raise HTTPException(status_code=404, detail=f"Instance '{name}' not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/instances/{name}")
async def delete_instance(name: str, user: dict = Depends(get_current_user)):
    """Delete a Lightsail instance"""
    try:
        lightsail.delete_instance(instanceName=name)
        return {"status": "deleting", "instance": name, "action_by": user["email"]}
    except lightsail.exceptions.NotFoundException:
        raise HTTPException(status_code=404, detail=f"Instance '{name}' not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/blueprints")
async def list_blueprints(user: dict = Depends(get_current_user)):
    """List available Lightsail blueprints (OS images)"""
    try:
        response = lightsail.get_blueprints(includeInactive=False)
        blueprints = []
        for bp in response.get('blueprints', []):
            if bp.get('isActive'):
                blueprints.append({
                    "id": bp['blueprintId'],
                    "name": bp['name'],
                    "group": bp.get('group'),
                    "type": bp['type'],
                    "description": bp.get('description', '')
                })
        return {"blueprints": blueprints}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/bundles")
async def list_bundles(user: dict = Depends(get_current_user)):
    """List available Lightsail bundles (instance sizes)"""
    try:
        response = lightsail.get_bundles(includeInactive=False)
        bundles = []
        for b in response.get('bundles', []):
            if b.get('isActive'):
                bundles.append({
                    "id": b['bundleId'],
                    "name": b['name'],
                    "price": b['price'],
                    "cpuCount": b['cpuCount'],
                    "ramSizeInGb": b['ramSizeInGb'],
                    "diskSizeInGb": b['diskSizeInGb'],
                    "transferPerMonthInGb": b['transferPerMonthInGb']
                })
        return {"bundles": bundles}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/keypairs")
async def list_keypairs(user: dict = Depends(get_current_user)):
    """List available Lightsail key pairs"""
    try:
        response = lightsail.get_key_pairs()
        keypairs = [{"name": kp['name'], "fingerprint": kp.get('fingerprint')}
                    for kp in response.get('keyPairs', [])]
        return {"keypairs": keypairs}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


from pydantic import BaseModel

class CreateInstanceRequest(BaseModel):
    name: str
    bundleId: str
    availabilityZone: str = "us-east-1a"
    keyPairName: str | None = None
    blueprintId: str | None = None
    snapshotName: str | None = None
    subaccount: str | None = None  # Link to subaccount for IP whitelisting


@app.post("/api/instances")
async def create_instance(req: CreateInstanceRequest, user: dict = Depends(get_current_user)):
    """Create a new Lightsail instance from blueprint or snapshot"""
    try:
        # Verify subaccount exists if provided
        subaccount_data = None
        if req.subaccount:
            try:
                secret_name = f"{SECRETS_PREFIX}{req.subaccount}"
                secret_response = secretsmanager.get_secret_value(SecretId=secret_name)
                subaccount_data = json.loads(secret_response['SecretString'])
            except secretsmanager.exceptions.ResourceNotFoundException:
                raise HTTPException(status_code=404, detail=f"Subaccount '{req.subaccount}' not found")

        if req.snapshotName:
            # Create from snapshot
            params = {
                "instanceNames": [req.name],
                "availabilityZone": req.availabilityZone,
                "bundleId": req.bundleId,
                "instanceSnapshotName": req.snapshotName
            }
            if req.keyPairName:
                params["keyPairName"] = req.keyPairName
            lightsail.create_instances_from_snapshot(**params)

            # Store instance-subaccount mapping in database
            if req.subaccount:
                db = get_db()
                try:
                    cursor = db.cursor()
                    cursor.execute('''
                        CREATE TABLE IF NOT EXISTS instance_subaccounts (
                            instance_name TEXT PRIMARY KEY,
                            subaccount_name TEXT NOT NULL,
                            created_at TEXT DEFAULT CURRENT_TIMESTAMP
                        )
                    ''')
                    cursor.execute(
                        'INSERT OR REPLACE INTO instance_subaccounts (instance_name, subaccount_name) VALUES (?, ?)',
                        (req.name, req.subaccount)
                    )
                    db.commit()
                finally:
                    db.close()

            return {
                "status": "creating",
                "instance": req.name,
                "snapshot": req.snapshotName,
                "bundle": req.bundleId,
                "subaccount": req.subaccount,
                "action_by": user["email"],
                "note": "Instance is booting. Check instance details for IP once running."
            }
        elif req.blueprintId:
            # Create from blueprint
            params = {
                "instanceNames": [req.name],
                "availabilityZone": req.availabilityZone,
                "blueprintId": req.blueprintId,
                "bundleId": req.bundleId
            }
            if req.keyPairName:
                params["keyPairName"] = req.keyPairName
            lightsail.create_instances(**params)

            # Store instance-subaccount mapping in database
            if req.subaccount:
                db = get_db()
                try:
                    cursor = db.cursor()
                    cursor.execute('''
                        CREATE TABLE IF NOT EXISTS instance_subaccounts (
                            instance_name TEXT PRIMARY KEY,
                            subaccount_name TEXT NOT NULL,
                            created_at TEXT DEFAULT CURRENT_TIMESTAMP
                        )
                    ''')
                    cursor.execute(
                        'INSERT OR REPLACE INTO instance_subaccounts (instance_name, subaccount_name) VALUES (?, ?)',
                        (req.name, req.subaccount)
                    )
                    db.commit()
                finally:
                    db.close()

            return {
                "status": "creating",
                "instance": req.name,
                "blueprint": req.blueprintId,
                "bundle": req.bundleId,
                "subaccount": req.subaccount,
                "action_by": user["email"],
                "note": "Instance is booting. Check instance details for IP once running."
            }
        else:
            raise HTTPException(status_code=400, detail="Either blueprintId or snapshotName required")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# --- Snapshots ---

@app.get("/api/snapshots")
async def list_snapshots(user: dict = Depends(get_current_user)):
    """List all Lightsail instance snapshots"""
    try:
        response = lightsail.get_instance_snapshots()
        snapshots = []
        for snap in response.get('instanceSnapshots', []):
            snapshots.append({
                "name": snap['name'],
                "state": snap['state'],
                "fromInstanceName": snap.get('fromInstanceName'),
                "sizeInGb": snap.get('sizeInGb'),
                "createdAt": snap['createdAt'].isoformat() if snap.get('createdAt') else None
            })
        return {"snapshots": snapshots}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class CreateSnapshotRequest(BaseModel):
    instanceName: str
    snapshotName: str


@app.post("/api/snapshots")
async def create_snapshot(req: CreateSnapshotRequest, user: dict = Depends(get_current_user)):
    """Create a snapshot from an instance"""
    try:
        lightsail.create_instance_snapshot(
            instanceName=req.instanceName,
            instanceSnapshotName=req.snapshotName
        )
        return {
            "status": "creating",
            "snapshot": req.snapshotName,
            "fromInstance": req.instanceName,
            "action_by": user["email"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/snapshots/{name}")
async def delete_snapshot(name: str, user: dict = Depends(get_current_user)):
    """Delete a snapshot"""
    try:
        lightsail.delete_instance_snapshot(instanceSnapshotName=name)
        return {"status": "deleting", "snapshot": name, "action_by": user["email"]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# --- Subaccounts (Secrets Manager) ---

class SubaccountRequest(BaseModel):
    name: str
    binance_api_key: str
    binance_secret_key: str
    client_token: str
    activation_code: str
    profile_name: str


class SubaccountUpdateRequest(BaseModel):
    binance_api_key: str | None = None
    binance_secret_key: str | None = None
    client_token: str | None = None
    activation_code: str | None = None
    profile_name: str | None = None


@app.get("/api/subaccounts")
async def list_subaccounts(user: dict = Depends(get_current_user)):
    """List all subaccounts (secrets with moontrader/ prefix)"""
    try:
        response = secretsmanager.list_secrets(
            Filters=[{"Key": "name", "Values": [SECRETS_PREFIX]}]
        )
        subaccounts = []
        for secret in response.get('SecretList', []):
            name = secret['Name'].replace(SECRETS_PREFIX, '')
            subaccounts.append({
                "name": name,
                "createdAt": secret.get('CreatedDate').isoformat() if secret.get('CreatedDate') else None,
                "lastChanged": secret.get('LastChangedDate').isoformat() if secret.get('LastChangedDate') else None
            })
        return {"subaccounts": subaccounts}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/subaccounts/{name}")
async def get_subaccount(name: str, user: dict = Depends(get_current_user)):
    """Get a specific subaccount (masked secrets)"""
    try:
        secret_name = f"{SECRETS_PREFIX}{name}"
        response = secretsmanager.get_secret_value(SecretId=secret_name)
        secret_data = json.loads(response['SecretString'])

        # Mask sensitive values
        return {
            "name": name,
            "binance_api_key": secret_data.get('binance_api_key', '')[:8] + '...' if secret_data.get('binance_api_key') else None,
            "binance_secret_key": "********" if secret_data.get('binance_secret_key') else None,
            "client_token": secret_data.get('client_token', '')[:8] + '...' if secret_data.get('client_token') else None,
            "activation_code": "********" if secret_data.get('activation_code') else None,
            "profile_name": secret_data.get('profile_name')
        }
    except secretsmanager.exceptions.ResourceNotFoundException:
        raise HTTPException(status_code=404, detail=f"Subaccount '{name}' not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/subaccounts")
async def create_subaccount(req: SubaccountRequest, user: dict = Depends(get_current_user)):
    """Create a new subaccount"""
    try:
        secret_name = f"{SECRETS_PREFIX}{req.name}"
        secret_data = {
            "binance_api_key": req.binance_api_key,
            "binance_secret_key": req.binance_secret_key,
            "client_token": req.client_token,
            "activation_code": req.activation_code,
            "profile_name": req.profile_name
        }

        secretsmanager.create_secret(
            Name=secret_name,
            SecretString=json.dumps(secret_data),
            Tags=[{"Key": "managed_by", "Value": "instance-manager"}]
        )

        return {
            "status": "created",
            "subaccount": req.name,
            "action_by": user["email"]
        }
    except secretsmanager.exceptions.ResourceExistsException:
        raise HTTPException(status_code=409, detail=f"Subaccount '{req.name}' already exists")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/api/subaccounts/{name}")
async def update_subaccount(name: str, req: SubaccountUpdateRequest, user: dict = Depends(get_current_user)):
    """Update an existing subaccount"""
    try:
        secret_name = f"{SECRETS_PREFIX}{name}"

        # Get existing secret
        response = secretsmanager.get_secret_value(SecretId=secret_name)
        secret_data = json.loads(response['SecretString'])

        # Update only provided fields
        if req.binance_api_key is not None:
            secret_data['binance_api_key'] = req.binance_api_key
        if req.binance_secret_key is not None:
            secret_data['binance_secret_key'] = req.binance_secret_key
        if req.client_token is not None:
            secret_data['client_token'] = req.client_token
        if req.activation_code is not None:
            secret_data['activation_code'] = req.activation_code
        if req.profile_name is not None:
            secret_data['profile_name'] = req.profile_name

        secretsmanager.update_secret(
            SecretId=secret_name,
            SecretString=json.dumps(secret_data)
        )

        return {
            "status": "updated",
            "subaccount": name,
            "action_by": user["email"]
        }
    except secretsmanager.exceptions.ResourceNotFoundException:
        raise HTTPException(status_code=404, detail=f"Subaccount '{name}' not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/subaccounts/{name}")
async def delete_subaccount(name: str, user: dict = Depends(get_current_user)):
    """Delete a subaccount"""
    try:
        secret_name = f"{SECRETS_PREFIX}{name}"
        secretsmanager.delete_secret(SecretId=secret_name, ForceDeleteWithoutRecovery=True)
        return {"status": "deleted", "subaccount": name, "action_by": user["email"]}
    except secretsmanager.exceptions.ResourceNotFoundException:
        raise HTTPException(status_code=404, detail=f"Subaccount '{name}' not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# --- Binance API ---

def binance_sign(params: dict, secret_key: str) -> str:
    """Create HMAC SHA256 signature for Binance API"""
    query_string = urlencode(params)
    signature = hmac.new(
        secret_key.encode('utf-8'),
        query_string.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    return signature


def binance_api_request(method: str, endpoint: str, api_key: str, secret_key: str, params: dict = None):
    """Make authenticated request to Binance API"""
    base_url = "https://api.binance.com"

    if params is None:
        params = {}

    params['timestamp'] = int(time.time() * 1000)
    params['signature'] = binance_sign(params, secret_key)

    headers = {"X-MBX-APIKEY": api_key}

    if method == "GET":
        response = requests.get(f"{base_url}{endpoint}", params=params, headers=headers, timeout=10)
    elif method == "POST":
        response = requests.post(f"{base_url}{endpoint}", params=params, headers=headers, timeout=10)
    else:
        raise ValueError(f"Unsupported method: {method}")

    return response.json()


def whitelist_ip_binance(api_key: str, secret_key: str, ip_address: str):
    """Add IP to Binance API key whitelist"""
    # Note: Binance doesn't have a direct API to whitelist IPs programmatically
    # This requires using the sub-account API if available
    # For now, return info about manual whitelisting requirement
    return {
        "status": "manual_required",
        "message": f"Please manually whitelist IP {ip_address} in Binance API settings",
        "ip": ip_address
    }


# Lambda handler
lambda_handler = Mangum(app)
