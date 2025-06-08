// MongoDB initialization script for MCP Security Guardian

// Connect to admin database to create user
db = db.getSiblingDB('admin');

// Check if the user already exists to avoid errors
const userExists = db.getUser('mcp_security');
if (!userExists) {
    // Create application user
    db.createUser({
        user: 'mcp_security',
        pwd: process.env.MONGO_INITDB_ROOT_PASSWORD,
        roles: [
            { role: 'readWrite', db: 'mcp_security' },
            { role: 'dbAdmin', db: 'mcp_security' }
        ]
    });
}

// Switch to application database
db = db.getSiblingDB('mcp_security');

// Create collections with validation schemas
db.createCollection('security_alerts', {
    validator: {
        $jsonSchema: {
            bsonType: 'object',
            required: ['alert_id', 'title', 'description', 'severity', 'created_at', 'status'],
            properties: {
                alert_id: { bsonType: 'string' },
                title: { bsonType: 'string' },
                description: { bsonType: 'string' },
                severity: { bsonType: 'string', enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] },
                created_at: { bsonType: 'date' },
                updated_at: { bsonType: 'date' },
                status: { bsonType: 'string', enum: ['ACTIVE', 'ACKNOWLEDGED', 'RESOLVED', 'FALSE_POSITIVE'] },
                source_id: { bsonType: 'string' },
                affected_entities: { bsonType: 'array' },
                organization_id: { bsonType: 'string' },
                created_by: { bsonType: 'string' },
                acknowledgments: { bsonType: 'array' },
                resolution: { bsonType: 'object' },
                metadata: { bsonType: 'object' }
            }
        }
    }
});

db.createCollection('archived_security_alerts');

db.createCollection('threat_intelligence', {
    validator: {
        $jsonSchema: {
            bsonType: 'object',
            required: ['indicator', 'type', 'created_at'],
            properties: {
                indicator: { bsonType: 'string' },
                type: { bsonType: 'string' },
                created_at: { bsonType: 'date' },
                updated_at: { bsonType: 'date' },
                source: { bsonType: 'string' },
                confidence: { bsonType: 'double', minimum: 0, maximum: 1 },
                severity: { bsonType: 'string', enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] },
                tags: { bsonType: 'array' },
                description: { bsonType: 'string' },
                metadata: { bsonType: 'object' }
            }
        }
    }
});

db.createCollection('relationship_graph', {
    validator: {
        $jsonSchema: {
            bsonType: 'object',
            required: ['source_id', 'source_type', 'target_id', 'target_type', 'relationship_type', 'created_at'],
            properties: {
                source_id: { bsonType: 'string' },
                source_type: { bsonType: 'string' },
                target_id: { bsonType: 'string' },
                target_type: { bsonType: 'string' },
                relationship_type: { bsonType: 'string' },
                created_at: { bsonType: 'date' },
                strength: { bsonType: 'double', minimum: 0, maximum: 1 },
                metadata: { bsonType: 'object' }
            }
        }
    }
});

db.createCollection('behavioral_patterns', {
    validator: {
        $jsonSchema: {
            bsonType: 'object',
            required: ['pattern_id', 'pattern_type', 'pattern_data', 'created_at'],
            properties: {
                pattern_id: { bsonType: 'string' },
                pattern_type: { bsonType: 'string' },
                pattern_data: { bsonType: 'object' },
                created_at: { bsonType: 'date' },
                updated_at: { bsonType: 'date' },
                source: { bsonType: 'string' },
                confidence: { bsonType: 'double', minimum: 0, maximum: 1 },
                description: { bsonType: 'string' },
                metadata: { bsonType: 'object' }
            }
        }
    }
});

db.createCollection('event_history', {
    validator: {
        $jsonSchema: {
            bsonType: 'object',
            required: ['event_id', 'event_type', 'timestamp', 'entity_id', 'entity_type'],
            properties: {
                event_id: { bsonType: 'string' },
                event_type: { bsonType: 'string' },
                timestamp: { bsonType: 'date' },
                entity_id: { bsonType: 'string' },
                entity_type: { bsonType: 'string' },
                user_id: { bsonType: 'string' },
                details: { bsonType: 'object' }
            }
        }
    }
});

// Create indexes for security_alerts collection
db.security_alerts.createIndex({ "alert_id": 1 }, { unique: true });
db.security_alerts.createIndex({ "created_at": 1 });
db.security_alerts.createIndex({ "severity": 1 });
db.security_alerts.createIndex({ "status": 1 });
db.security_alerts.createIndex({ "source_id": 1 });
db.security_alerts.createIndex({ "organization_id": 1 });
db.security_alerts.createIndex({ "created_by": 1 });

// Create indexes for archived_security_alerts collection
db.archived_security_alerts.createIndex({ "alert_id": 1 }, { unique: true });
db.archived_security_alerts.createIndex({ "created_at": 1 });
db.archived_security_alerts.createIndex({ "status": 1 });
db.archived_security_alerts.createIndex({ "organization_id": 1 });

// Create indexes for threat_intelligence collection
db.threat_intelligence.createIndex({ "indicator": 1 }, { unique: true });
db.threat_intelligence.createIndex({ "type": 1 });
db.threat_intelligence.createIndex({ "created_at": 1 });
db.threat_intelligence.createIndex({ "severity": 1 });
db.threat_intelligence.createIndex({ "tags": 1 });

// Create indexes for relationship_graph collection
db.relationship_graph.createIndex({ "source_id": 1, "source_type": 1 });
db.relationship_graph.createIndex({ "target_id": 1, "target_type": 1 });
db.relationship_graph.createIndex({ "relationship_type": 1 });
db.relationship_graph.createIndex({ "created_at": 1 });

// Create indexes for behavioral_patterns collection
db.behavioral_patterns.createIndex({ "pattern_id": 1 }, { unique: true });
db.behavioral_patterns.createIndex({ "pattern_type": 1 });
db.behavioral_patterns.createIndex({ "created_at": 1 });

// Create indexes for event_history collection
db.event_history.createIndex({ "event_id": 1 }, { unique: true });
db.event_history.createIndex({ "event_type": 1 });
db.event_history.createIndex({ "timestamp": 1 });
db.event_history.createIndex({ "entity_id": 1, "entity_type": 1 });
db.event_history.createIndex({ "user_id": 1 });

// Create time-to-live (TTL) index for event_history to automatically delete old records
db.event_history.createIndex({ "timestamp": 1 }, { expireAfterSeconds: 7776000 }); // 90 days

// Output success message
print('MongoDB initialization completed successfully');
print('Created collections: security_alerts, archived_security_alerts, threat_intelligence, relationship_graph, behavioral_patterns, event_history');
print('Created indexes for all collections'); 