from flask import Flask, request, jsonify, make_response
import jsonschema
from jsonschema import validate
import redis
import hashlib
import json
import jwt

app = Flask(__name__)
redis_db = redis.Redis()

schema = {
    "type": "object",
    "properties": {
        "planCostShares": {
            "type": "object",
            "properties": {
                "deductible": { "type": "integer" },
                "_org": { "type": "string" },
                "copay": { "type": "integer" },
                "objectId": { "type": "string" },
                "objectType": { "type": "string" }
            },
            "required": ["deductible", "_org", "copay", "objectId", "objectType"]
        },
        "linkedPlanServices": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "linkedService": {
                        "type": "object",
                        "properties": {
                            "_org": { "type": "string" },
                            "objectId": { "type": "string" },
                            "objectType": { "type": "string" },
                            "name": { "type": "string" }
                        },
                        "required": ["_org", "objectId", "objectType", "name"]
                    },
                    "planserviceCostShares": {
                        "type": "object",
                        "properties": {
                            "deductible": { "type": "integer" },
                            "_org": { "type": "string" },
                            "copay": { "type": "integer" },
                            "objectId": { "type": "string" },
                            "objectType": { "type": "string" }
                        },
                        "required": ["deductible", "_org", "copay", "objectId", "objectType"]
                    },
                    "_org": { "type": "string" },
                    "objectId": { "type": "string" },
                    "objectType": { "type": "string" }
                },
                "required": ["linkedService", "planserviceCostShares", "_org", "objectId", "objectType"]
            }
        },
        "_org": { "type": "string" },
        "objectId": { "type": "string" },
        "objectType": { "type": "string" },
        "planType": { "type": "string" },
        "creationDate": { "type": "string" }
    },
    "required": ["planCostShares", "linkedPlanServices", "_org", "objectId", "objectType", "planType", "creationDate"]
}

# Load RSA Keys
with open('private.pem', 'rb') as private_file:
    private_key = private_file.read()
with open('public.pem', 'rb') as public_file:
    public_key = public_file.read()

# generating JWT token
def generate_token():
    payload = {}  
    token = jwt.encode(payload, private_key, algorithm='RS256')
    return token

# validating the JWT token
def validate_token():
    token = request.headers.get('Authorization')
    if not token:
        return False

    token = token.split('Bearer ')[1]
    try:
        jwt.decode(token, public_key, algorithms=['RS256'])
        return True
    except jwt.ExpiredSignatureError:
        return False
    except jwt.DecodeError:
        return False

@app.route('/token', methods=['GET'])
def create_token():
    token = generate_token()
    return jsonify({'token': token})

@app.route('/validate_token', methods=['POST'])
def validating_token():
    
    token = request.headers.get('Authorization').split('Bearer ')[1]
    valid = validate_token()
    if valid:
        return jsonify({'message': 'Token is valid'}), 200
    else:
        return jsonify({'error': 'Token is invalid'}), 401

@app.route('/plan', methods=['POST'])
def create_plan():
    # checking if token is valid
    if not validate_token():
        return jsonify({'error': 'Invalid token'}), 401
    
    plan = request.get_json()
    key = plan.get('objectId')
    try:
        validate(plan, schema)
    except jsonschema.exceptions.ValidationError as e:
        missing_fields = " ".join(e.validator_value)
        return jsonify({'error': f"The following required fields are missing: {missing_fields}. Please mention"}), 400

    # ETag generation
    plan_str = json.dumps(plan)
    etag = hashlib.md5(plan_str.encode()).hexdigest()

    # Store plan in Redis with ETag as part of the value
    redis_db.set(key, json.dumps({'plan': plan, 'etag': etag}))

    response = jsonify({'objectid':key, 'message': 'plan created successfully', 'plan': plan})
    response.headers['ETag'] = etag
    
    return response, 201

@app.route('/plan/<key>', methods=['GET'])
def get_plan(key):
    # checking if token is valid
    if not validate_token():
        return jsonify({'error': 'Invalid token'}), 401
    
    plan = redis_db.get(key)
    if not plan:
        return jsonify({'error': 'plan not found'}), 404

    plan = json.loads(plan)
    etag = plan.get('etag')  # Retrieve the etag

    # Check If-Match header for ETag validation
    if request.headers.get('If-Match') and request.headers.get('If-Match') != etag:
        return jsonify({'error': 'ETag mismatch'}), 412

    # Check If-None-Match header for ETag validation
    if request.headers.get('If-None-Match') and request.headers.get('If-None-Match') == etag:
        return '', 304
    
        
    response = make_response(jsonify(plan['plan']), 200)
    response.headers['ETag'] = etag

    return response

@app.route('/plan/<key>', methods=['PATCH'])
def patch_plan(key):
    # checking if token is valid
    if not validate_token():
        return jsonify({'error': 'Invalid token'}), 401
    
    plan = redis_db.get(key)
    if not plan:
        return jsonify({'error': 'plan not found'}), 404

    plan = json.loads(plan)
    etag = plan.get('etag')
    
    # Check If-Match header for ETag validation
    if request.headers.get('If-Match') and request.headers.get('If-Match') != etag:
        return jsonify({'error': 'ETag mismatch'}), 412

    updated_linked_services = request.get_json()

    if 'linkedPlanServices'  not in updated_linked_services:
        return jsonify({'error': 'provide linkedPlanServices'}), 400
    
    if 'objectId'  not in updated_linked_services:
        return jsonify({'error': 'provide objectId'}), 400
    
    if not redis_db.get(updated_linked_services['objectId']):
        return jsonify({'error': 'invalid objectId'}), 400

    if key != updated_linked_services['objectId']:
        return jsonify({'error': 'invalid objectId or key'}), 400

    if 'planCostShares' in updated_linked_services:
        return jsonify({'error': 'cannot perform PATCH on planCostShares'}), 400

    plan['plan']['linkedPlanServices'] = updated_linked_services['linkedPlanServices']

    # Generate new ETag after update
    updated_plan_str = json.dumps(plan['plan'])
    new_etag = hashlib.md5(updated_plan_str.encode()).hexdigest()

    # Store updated plan in Redis with new ETag
    redis_db.set(key, json.dumps({'plan': plan['plan'], 'etag': new_etag}))

    response = make_response(jsonify(plan['plan']), 200)
    response = jsonify({'objectid':key, 'message': 'Plan updated successfully', 'plan': plan})
    
    response.headers['ETag'] = new_etag

    return response, 200

@app.route('/plan/<key>', methods=['PUT'])
def put_plan(key):
    # Checking if the token is valid
    if not validate_token():
        return jsonify({'error': 'Invalid token'}), 401

    updated_plan = request.get_json()

    # Checking if the request contains a valid plan
    try:
        validate(updated_plan, schema)
    except jsonschema.exceptions.ValidationError as e:
        missing_fields = " ".join(e.validator_value)
        return jsonify({'error': f"The following required fields are missing in the plan: {missing_fields}. Please provide all required fields"}), 400

    # Store the updated plan in Redis, replacing the existing resource
    etag = hashlib.md5(json.dumps(updated_plan).encode()).hexdigest()
    redis_db.set(key, json.dumps({'plan': updated_plan, 'etag': etag}))

    response = jsonify({'message': 'Plan updated successfully', 'objectid': key, 'plan': updated_plan})
    response.headers['ETag'] = etag

    return response, 200

@app.route('/plan/<key>', methods=['DELETE'])
def delete_plan(key):
    # checking if token is valid
    if not validate_token():
        return jsonify({'error': 'Invalid token'}), 401
    
    plan = redis_db.get(key)
    if not plan:
        return jsonify({'error': 'plan not found'}), 404

    plan = json.loads(plan)
    etag = plan.get('etag')  # Retrieve the etag

    # Check If-Match header for ETag validation
    if request.headers.get('If-Match') and request.headers.get('If-Match') != etag:
        return jsonify({'error': 'ETag mismatch'}), 412

    # Check If-None-Match header for ETag validation
    if request.headers.get('If-None-Match') and request.headers.get('If-None-Match') == etag:
        return jsonify({'error': 'ETag match, delete not allowed'}), 412

    deleted = redis_db.delete(key)
    if not deleted:
        return jsonify({'error': 'plan not found'}), 404
    return jsonify({'message': 'plan deleted successfully'}), 200

if __name__ == '__main__':
    app.run(debug=True)