from flask import Flask, request, jsonify, make_response
import jsonschema
from jsonschema import validate, exceptions
import redis
import hashlib
import json
import pika
import jwt
from elasticsearch import Elasticsearch


app = Flask(__name__)
redis_db = redis.Redis()

# RabbitMQ Configuration
RABBITMQ_QUEUE = "my_plan_queue"
RABBITMQ_URL = "localhost"
RABBITMQ_PORT = 5672

# Connect to RabbitMQ
connection = pika.BlockingConnection(pika.ConnectionParameters(host=RABBITMQ_URL, port=RABBITMQ_PORT))
channel = connection.channel()
channel.queue_declare(queue=RABBITMQ_QUEUE, durable=True)

# Elasticsearch Configuration
es = Elasticsearch(
    ['http://localhost:9200/'],
    http_auth=('elastic', 'EgV9dgLpiFSHaZoJSSOm'),
)
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

def create_index_with_mapping():
    index_name = "indexplan"  # Replace with your desired index name

    mapping = {
        "mappings": {
            "properties": {
                "plan": {
                    "properties": {
                        "_org": {"type": "text"},
                        "objectId": {"type": "keyword"},
                        "objectType": {"type": "text"},
                        "planType": {"type": "text"},
                        "creationDate": {"type": "date", "format": "MM-dd-yyyy"},
                        "planCostShares": {
                            "properties": {
                                "copay": {"type": "long"},
                                "deductible": {"type": "long"},
                                "_org": {"type": "text"},
                                "objectId": {"type": "keyword"},
                                "objectType": {"type": "text"}
                            }
                        },
                        "linkedPlanServices": {
                            "properties": {
                                "_org": {"type": "text"},
                                "objectId": {"type": "keyword"},
                                "objectType": {"type": "text"}
                            }
                        },
                        "linkedService": {
                            "properties": {
                                "_org": {"type": "text"},
                                "name": {"type": "text"},
                                "objectId": {"type": "keyword"},
                                "objectType": {"type": "text"}
                            }
                        },
                        "planserviceCostShares": {
                            "properties": {
                                "copay": {"type": "long"},
                                "deductible": {"type": "long"},
                                "_org": {"type": "text"},
                                "objectId": {"type": "keyword"},
                                "objectType": {"type": "text"}
                            }
                        },
                        "plan_join": {
                            "type": "join",
                            "eager_global_ordinals": True,
                            "relations": {
                                "plan": ["planCostShares", "linkedPlanServices"],
                                "linkedPlanServices": ["linkedService", "planserviceCostShares"]
                            }
                        }
                    }
                }
            }
        }
    }

    es.indices.create(index=index_name, body=mapping, ignore=400)  # Ignore 400 if index already exists

# Call the function to create the index with the specified mapping
create_index_with_mapping()

# POST endpoint
@app.route('/plan', methods=['POST'])
def create_plan():
    if not validate_token():
        return jsonify({'error': 'Invalid token'}), 401

    plan = request.get_json()
    key = plan.get('objectId')

    try:
        validate(plan, schema)
    except exceptions.ValidationError as e:
        missing_fields = " ".join(e.validator_value)
        return jsonify({'error': f"The following required fields are missing: {missing_fields}. Please mention"}), 400

    plan_str = json.dumps(plan)
    etag = hashlib.md5(plan_str.encode()).hexdigest()

    redis_db.set(key, json.dumps({'plan': plan, 'etag': etag}))

    # Send plan to RabbitMQ for queuing
    channel.basic_publish(
        exchange='',
        routing_key=RABBITMQ_QUEUE,
        body=json.dumps(plan),
        properties=pika.BasicProperties(
            delivery_mode=2,  # Make the message persistent
        )
    )
    
    # Index parent document in Elasticsearch with join field
    es.index(index='indexplan', id=key, body={
        'planCostShares': plan.get('planCostShares', {}),
        '_org': plan.get('_org'),
        'objectId': key,
        'objectType': 'plan',
        'planType': plan.get('planType'),
        'creationDate': plan.get('creationDate'),
        'plan_join': {'name': 'plan'},  # Add a join field
    })

    # Index child documents in Elasticsearch for linkedPlanServices
    for linked_service in plan.get('linkedPlanServices', []):
        es.index(index='indexplan', body={
            'linkedService': linked_service.get('linkedService', {}),
            'planserviceCostShares': linked_service.get('planserviceCostShares', {}),
            '_org': linked_service.get('_org'),
            'objectId': linked_service.get('objectId'),
            'objectType': 'planservice',
            'parent': key,  # Establish parent-child relationship
            'plan_join': {'name': 'linkedPlanServices'},  # Add a join field
        })

    response = jsonify({'objectid': key, 'message': 'Plan created successfully', 'plan': plan})
    response.headers['ETag'] = etag

    return response, 201

# GET endpoint
@app.route('/plan/<key>', methods=['GET'])
def get_plan(key):
    if not validate_token():
        return jsonify({'error': 'Invalid token'}), 401

    plan = redis_db.get(key)
    if not plan:
        return jsonify({'error': 'Plan not found'}), 404

    plan = json.loads(plan)
    etag = plan.get('etag')

    # Check If-Match header for ETag validation
    if request.headers.get('If-Match') and request.headers.get('If-Match') != etag:
        return jsonify({'error': 'ETag mismatch'}), 412

    # Check If-None-Match header for ETag validation
    if request.headers.get('If-None-Match') and request.headers.get('If-None-Match') == etag:
        return '', 304

    response = make_response(jsonify(plan['plan']), 200)
    response.headers['ETag'] = etag

    return response

# PATCH endpoint
@app.route('/plan/<key>', methods=['PATCH'])
def patch_plan(key):
    if not validate_token():
        return jsonify({'error': 'Invalid token'}), 401

    plan = redis_db.get(key)
    if not plan:
        return jsonify({'error': 'Plan not found'}), 404

    plan = json.loads(plan)
    etag = plan.get('etag')

    # Check If-Match header for ETag validation
    if request.headers.get('If-Match') and request.headers.get('If-Match') != etag:
        return jsonify({'error': 'ETag mismatch'}), 412

    updated_linked_services = request.get_json()

    # Validations
    if 'linkedPlanServices' not in updated_linked_services:
        return jsonify({'error': 'Provide linkedPlanServices'}), 400

    if 'objectId' not in updated_linked_services:
        return jsonify({'error': 'Provide objectId'}), 400

    if not redis_db.get(updated_linked_services['objectId']):
        return jsonify({'error': 'Invalid objectId'}), 400

    if key != updated_linked_services['objectId']:
        return jsonify({'error': 'Invalid objectId or key'}), 400

    if 'planCostShares' in updated_linked_services:
        return jsonify({'error': 'Cannot perform PATCH on planCostShares'}), 400

    plan['plan']['linkedPlanServices'] = updated_linked_services['linkedPlanServices']

    updated_plan_str = json.dumps(plan['plan'])
    new_etag = hashlib.md5(updated_plan_str.encode()).hexdigest()

    redis_db.set(key, json.dumps({'plan': plan['plan'], 'etag': new_etag}))
    
    # Index updated plan in Elasticsearch
    es.index(index='indexplan', id=key, body={
        'planCostShares': plan['plan'].get('planCostShares', {}),
        '_org': plan['plan'].get('_org'),
        'objectId': key,
        'objectType': 'plan',
        'planType': plan['plan'].get('planType'),
        'creationDate': plan['plan'].get('creationDate'),
        'plan_join': {'name': 'plan'}  # Add a join field
    })

    # Delete existing child documents
    es.delete_by_query(index='indexplan', body={
        'query': {
            'bool': {
                'must': [
                    {'term': {'parent': key}},
                    {'term': {'objectType': 'planservice'}}
                ]
            }
        }
    })

    # Index child documents in Elasticsearch for updated linkedPlanServices
    for linked_service in updated_linked_services.get('linkedPlanServices', []):
        es.index(index='indexplan', body={
            'linkedService': linked_service.get('linkedService', {}),
            'planserviceCostShares': linked_service.get('planserviceCostShares', {}),
            '_org': linked_service.get('_org'),
            'objectId': linked_service.get('objectId'),
            'objectType': 'planservice',
            'parent': key,  # Establish parent-child relationship
            'plan_join': {'name': 'linkedPlanServices'}  # Add a join field
        })

    response = make_response(jsonify(plan['plan']), 200)
    response.headers['ETag'] = new_etag

    return response, 200

# PUT endpoint
@app.route('/plan/<key>', methods=['PUT'])
def put_plan(key):
    if not validate_token():
        return jsonify({'error': 'Invalid token'}), 401

    updated_plan = request.get_json()

    try:
        validate(updated_plan, schema)
    except exceptions.ValidationError as e:
        missing_fields = " ".join(e.validator_value)
        return jsonify({'error': f"The following required fields are missing in the plan: {missing_fields}. Please provide all required fields"}), 400

    etag = hashlib.md5(json.dumps(updated_plan).encode()).hexdigest()
    redis_db.set(key, json.dumps({'plan': updated_plan, 'etag': etag}))

    # Publish to RabbitMQ
    channel.basic_publish(
        exchange='',
        routing_key=RABBITMQ_QUEUE,
        body=json.dumps(updated_plan),
        properties=pika.BasicProperties(
            delivery_mode=2,  # Make the message persistent
        )
    )

    # Index updated plan in Elasticsearch with nested structure
    es.index(index='indexplan', id=key, body={
        'planCostShares': updated_plan.get('planCostShares', {}),
        '_org': updated_plan.get('_org'),
        'objectId': key,
        'objectType': 'plan',
        'planType': updated_plan.get('planType'),
        'creationDate': updated_plan.get('creationDate'),
        'plan_join': {'name': 'plan'}  # Add a join field
    })

    # Delete existing child documents
    es.delete_by_query(index='indexplan', body={
        'query': {
            'bool': {
                'must': [
                    {'term': {'parent': key}},
                    {'term': {'objectType': 'planservice'}}
                ]
            }
        }
    })

    # Index child documents in Elasticsearch for updated linkedPlanServices
    for linked_service in updated_plan.get('linkedPlanServices', []):
        es.index(index='indexplan', body={
            'linkedService': linked_service.get('linkedService', {}),
            'planserviceCostShares': linked_service.get('planserviceCostShares', {}),
            '_org': linked_service.get('_org'),
            'objectId': linked_service.get('objectId'),
            'objectType': 'planservice',
            'plan_join': {'name': 'linkedPlanServices'}  # Add a join field
        })


    response = jsonify({'message': 'Plan updated successfully', 'objectid': key, 'plan': updated_plan})
    response.headers['ETag'] = etag

    return response, 200

# DELETE endpoint
@app.route('/plan/<key>', methods=['DELETE'])
def delete_plan(key):
    if not validate_token():
        return jsonify({'error': 'Invalid token'}), 401

    plan = redis_db.get(key)
    if not plan:
        return jsonify({'error': 'Plan not found'}), 404

    plan = json.loads(plan)
    etag = plan.get('etag')

    if request.headers.get('If-Match') and request.headers.get('If-Match') != etag:
        return jsonify({'error': 'ETag mismatch'}), 412

    # Cascade delete
    redis_db.delete(key)

    # Delete from Elasticsearch
    es.delete(index='indexplan', id=key)

    # Delete child documents from Elasticsearch
    es.delete_by_query(index='indexplan', body={
        'query': {
            'bool': {
                'must': [
                    {'term': {'parent': key}},
                    {'term': {'objectType': 'planservice'}}
                ]
            }
        }
    })
    print(es)

    # Publish delete event to RabbitMQ
    delete_message = {'event': 'delete', 'object_id': key}
    channel.basic_publish(
        exchange='',
        routing_key=RABBITMQ_QUEUE,
        body=json.dumps(delete_message),
        properties=pika.BasicProperties(
            delivery_mode=2,  # Make the message persistent
        )
    )
    
    return jsonify({'message': 'Plan deleted successfully'}), 200

if __name__ == '__main__':
    app.run(debug=True)