# Stellara Event Indexer

Example backend service for subscribing to and indexing Stellara smart contract events.

## Features

- Subscribes to Soroban contract events via RPC polling
- Decodes and parses event data from XDR format
- Stores events in SQLite database for querying
- Handles specific event types with custom business logic
- Tracks indexing progress with cursor persistence
- Graceful shutdown handling

## Event Types Supported

### Trading Events
- `trade` - Trade execution with full details
- `paused` - Contract pause events
- `unpause` - Contract unpause events
- `fee` - Fee collection events

### Governance Events
- `propose` - Proposal creation
- `approve` - Proposal approval
- `reject` - Proposal rejection
- `execute` - Proposal execution
- `cancel` - Proposal cancellation

### Social Rewards Events
- `reward` - Reward grants
- `claimed` - Reward claims

## Setup

```bash
# Install dependencies
npm install

# Start the indexer
npm start

# Or with environment variables
STELLAR_RPC_URL=https://soroban-testnet.stellar.org \
CONTRACT_IDS=CABC...,CDEF... \
npm start
```

## Configuration

Environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `STELLAR_RPC_URL` | Soroban RPC endpoint | `https://soroban-testnet.stellar.org` |
| `CONTRACT_IDS` | Comma-separated contract IDs to monitor | (all contracts) |
| `DATABASE_PATH` | Path to SQLite database file | `./events.db` |
| `POLL_INTERVAL` | Polling interval in milliseconds | `5000` |
| `START_LEDGER` | Starting ledger for initial sync | `0` (recent) |

## Database Schema

### `events` - Generic event storage
All events are stored with their raw data for flexibility.

### `trades` - Structured trade data
Parsed trade events with indexed fields for efficient querying.

### `proposals` - Governance proposal tracking
Tracks proposal lifecycle with status updates.

### `rewards` - Social rewards tracking
Tracks reward grants and claims per user.

## Querying Data

```typescript
import { EventDatabase } from './database';

const db = new EventDatabase('./events.db');

// Get trades for a specific trader
const trades = db.getTradesByTrader('GABCD...');

// Get trading volume for a pair
const volume = db.getTradeVolume('XLMUSDC', Date.now() - 86400000);

// Get pending rewards for a user
const rewards = db.getPendingRewards('GABCD...');

// Get active governance proposals
const proposals = db.getActiveProposals('CONTRACT_ID');
```

## Extending

To handle additional event types:

1. Add the event interface to `types.ts`
2. Add the topic constant to `EVENT_TOPICS`
3. Create a handler method in `EventHandler` class
4. Add a case to the switch statement in `processEvent()`

## Production Considerations

For production deployments, consider:

- Use PostgreSQL instead of SQLite for better concurrency
- Add proper error handling and retry logic
- Implement webhooks/notifications for critical events
- Add metrics and monitoring (Prometheus, etc.)
- Use a message queue for event processing
- Add authentication and rate limiting for API access
