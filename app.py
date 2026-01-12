import json
import jwt
import requests
import os
import sqlite3
import boto3
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


# --- Lightsail ---

lightsail = boto3.client('lightsail', region_name='us-east-1')


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


@app.post("/api/instances")
async def create_instance(req: CreateInstanceRequest, user: dict = Depends(get_current_user)):
    """Create a new Lightsail instance from blueprint or snapshot"""
    try:
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
            return {
                "status": "creating",
                "instance": req.name,
                "snapshot": req.snapshotName,
                "bundle": req.bundleId,
                "action_by": user["email"]
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
            return {
                "status": "creating",
                "instance": req.name,
                "blueprint": req.blueprintId,
                "bundle": req.bundleId,
                "action_by": user["email"]
            }
        else:
            raise HTTPException(status_code=400, detail="Either blueprintId or snapshotName required")
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


# Lambda handler
lambda_handler = Mangum(app)
