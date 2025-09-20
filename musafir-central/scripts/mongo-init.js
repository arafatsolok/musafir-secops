// MongoDB initialization script
db = db.getSiblingDB('musafir');

// Create collections
db.createCollection('users');
db.createCollection('events');
db.createCollection('alerts');
db.createCollection('assets');
db.createCollection('tenants');

// Create indexes
db.events.createIndex({ "ts": 1 });
db.events.createIndex({ "tenant_id": 1 });
db.events.createIndex({ "asset.id": 1 });
db.events.createIndex({ "event.class": 1 });
db.events.createIndex({ "event.severity": 1 });

db.alerts.createIndex({ "timestamp": 1 });
db.alerts.createIndex({ "tenant_id": 1 });
db.alerts.createIndex({ "severity": 1 });
db.alerts.createIndex({ "status": 1 });

db.users.createIndex({ "email": 1 }, { unique: true });
db.users.createIndex({ "tenant_id": 1 });

db.assets.createIndex({ "id": 1, "tenant_id": 1 }, { unique: true });
db.assets.createIndex({ "tenant_id": 1 });
db.assets.createIndex({ "type": 1 });

db.tenants.createIndex({ "id": 1 }, { unique: true });

print('MongoDB initialized successfully');
