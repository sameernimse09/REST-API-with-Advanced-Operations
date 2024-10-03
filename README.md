# RESTful-API-with-Advanced-Operations
This project is a Python-based REST API capable of handling structured JSON data with advanced CRUD operations, validation, and security mechanisms. 

## Features
**CRUD Operations**: Full support for Create, Read, Update, and Delete operations, including PATCH and cascaded deletes.

**Validation**: Payloads are validated directly against a JSON Schema to ensure data consistency.

**Conditional Updates/Reads**: Uses ETag to manage resource state, allowing conditional updates only if changes are detected.

**Key-Value Store**: Data is stored in a key-value store for optimized performance.

**Elasticsearch Integration**: Advanced search features with join and Parent-Child indexing capabilities.

**Message Queuing**: RabbitMQ used for queuing and handling asynchronous messaging.

**Security**: API secured using RS256 token mechanism, with Google IDP used for signing and validating Bearer tokens.
