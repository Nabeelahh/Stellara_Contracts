Stellara_backend
🚀 Stellara Backend — Web3 Crypto Academy Server

Stellara Backend is the server-side application powering Stellara AI, a next-generation Web3 learning and social trading platform built on the Stellar blockchain ecosystem. It is designed for crypto learners and traders who need real-time communication, secure account systems, AI-assisted learning tools, and on-chain trading services.

This backend manages authentication, courses, rewards, social feeds, messaging, AI integrations, and blockchain interactions, while exposing REST APIs and WebSocket gateways consumed by the Stellara AI frontend.

🚀 Overview
Stellara AI is designed to educate, empower, and connect crypto users by combining:

A crypto learning academy with structured courses and quizzes
An AI-powered assistant with text and voice guidance
A social crypto network with posts, comments, and interactions
Real-time messaging for one-on-one and group discussions
On-chain trading tools integrated with Stellar wallets
Live market news and insights powered by AI
The backend is responsible for securely managing the core application logic, database interactions, and blockchain integrations.

🧠 Core Features
🤖 Stellara AI Assistant
Text & voice-based AI crypto mentor
Explains trading strategies, blockchain concepts, and Stellar-specific tools
Provides market insights & educational guidance (not financial advice)
🎓 Crypto Academy
Structured learning paths (Beginner → Pro)
Stellar & Soroban smart contract education
Interactive quizzes and progress tracking
🗣 Social Crypto Feed
Post updates, ideas, and market thoughts
Like, comment, repost (tweet-style)
Follow other traders & educators
💬 Community Chat
One-on-one messaging
Group discussions & learning channels
Trading & ecosystem-focused rooms
📈 Trading & Wallet
Trade Stellar-based assets
Freighter wallet integration
Portfolio overview & transaction history
📰 News & Market Intelligence
Real-time crypto news
Stellar ecosystem updates
Market trend summaries via AI
🛠 Technology Stack
Backend
NestJS – API framework
PostgreSQL – Relational database
Redis – Caching & real-time messaging
WebSocket Gateway – Real-time chat & feed
Blockchain
Stellar SDK & Horizon API
Soroban Smart Contracts
Freighter Wallet integration
AI & Voice
LLM API (OpenAI or equivalent)
Speech-to-Text (Whisper or similar)
Text-to-Speech (TTS)
Infrastructure
Docker for containerization
AWS / Railway / Render for backend hosting
Vercel for frontend deployment
💎 Why Stellara AI Works
Instantly signals AI intelligence
Strong connection to Stellar blockchain
Easy to market & brand
Scales to mobile apps, APIs, and future tools
Credible to investors and partners
⚡ Getting Started

✅ Requirements

- Node.js v18+
- PostgreSQL
- Redis
- npm or pnpm

📦 Installation

```bash
git clone https://github.com/stellara-network/Stellara_Contracts
cd Stellara_Contracts/Backend
npm install
```

🔐 Secrets Management

This project uses **HashiCorp Vault** for secure secrets management. Secrets are NOT stored in the repository.

**Quick Start:**

1. **Local Development with Vault:**
   ```bash
   # Start Vault dev server (in a separate terminal)
   vault server -dev
   
   # In another terminal, provision development secrets
   export VAULT_ADDR='http://localhost:8200'
   export VAULT_TOKEN='devroot'
   ./scripts/vault/provision-dev.sh
   ```

2. **Local Development with .env.local:**
   ```bash
   # Create .env.local (ignored by git)
   cp .env.example .env.local
   # Edit .env.local with your development secrets
   ```

**For detailed setup instructions, see:**
- [Local Secrets Setup Guide](./docs/LOCAL_SECRETS_SETUP.md)
- [Secrets Management Strategy](./docs/SECRETS_MANAGEMENT.md)
- [Vault Client Implementation](./docs/VAULT_CLIENT_NODEJS.md)

⚠️ **SECURITY**: Never commit real secrets to the repository. See [.gitignore](.gitignore) for ignored files.

▶ Run Development Server npm run start:dev

▶ Run Development Server npm run start:dev

🧪 Testing npm run test npm run test:e2e

---

## 📐 API Error Contract (issue #827)

All responses from the Stellara API follow a **consistent envelope shape**, whether the call succeeds or fails. This makes it simple for frontend clients and third-party consumers to handle responses uniformly.

### ✅ Success Envelope

Every successful response is wrapped in:

```json
{
  "success": true,
  "statusCode": 200,
  "data": { ... },
  "timestamp": "2026-07-18T01:50:00.000Z",
  "path": "/auth/me"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `success` | `boolean` | Always `true` for 2xx responses |
| `statusCode` | `number` | HTTP status code |
| `data` | `any` | The actual response payload |
| `timestamp` | `string` (ISO-8601) | Server time when the response was produced |
| `path` | `string` | The request path |

### ❌ Error Envelope

Every error response uses this shape:

```json
{
  "success": false,
  "statusCode": 404,
  "errorCode": "WORKFLOW_NOT_FOUND",
  "message": "Workflow '123' not found",
  "details": null,
  "timestamp": "2026-07-18T01:50:00.000Z",
  "path": "/admin/workflows/123"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `success` | `boolean` | Always `false` for error responses |
| `statusCode` | `number` | HTTP status code |
| `errorCode` | `string` | Machine-readable snake-case code (see table below) |
| `message` | `string` | Human-readable description |
| `details` | `any \| null` | Optional structured details (e.g. validation field errors) |
| `timestamp` | `string` (ISO-8601) | Server time when the error occurred |
| `path` | `string` | The request path where the error occurred |

### 🔑 Error Code Reference

| `errorCode` | HTTP Status | When it occurs |
|-------------|-------------|----------------|
| `INTERNAL_SERVER_ERROR` | 500 | Unhandled / unexpected exception |
| `VALIDATION_ERROR` | 400 | Class-validator failure or bad request body |
| `NOT_FOUND` | 404 | Generic resource not found |
| `CONFLICT` | 409 | Duplicate resource |
| `UNAUTHORIZED` | 401 | Missing or invalid authentication |
| `FORBIDDEN` | 403 | Authenticated but lacks permission |
| `INVALID_SIGNATURE` | 401 | Wallet signature verification failed |
| `INVALID_NONCE` | 401 | Nonce is expired or already used |
| `TOKEN_EXPIRED` | 401 | JWT / refresh token expired |
| `TOKEN_INVALID` | 401 | JWT / refresh token malformed |
| `INSUFFICIENT_ROLE` | 403 | User authenticated but role insufficient |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests in the time window |
| `WORKFLOW_NOT_FOUND` | 404 | Workflow ID does not exist |
| `WORKFLOW_INVALID_STATE` | 400 | Workflow is not in the expected state for the operation |
| `STEP_NOT_FOUND` | 404 | Workflow step ID does not exist |
| `STEP_INVALID_STATE` | 400 | Step is not in the expected state for the operation |
| `RECOVERY_FAILED` | 500 | Manual recovery process failed |
| `COMPENSATION_FAILED` | 400 / 500 | Compensation operation failed |
| `WALLET_NOT_FOUND` | 404 | Wallet address not found |
| `WALLET_ALREADY_BOUND` | 409 | Wallet is already bound to an account |
| `WALLET_LAST_BOUND` | 400 | Cannot unbind the only wallet on the account |

### 📌 Examples for Frontend Consumers

#### Example 1 — Authentication (wallet login)

```http
POST /auth/wallet/login
Content-Type: application/json

{ "publicKey": "GABC...", "signature": "...", "nonce": "..." }
```

**Success (200):**
```json
{
  "success": true,
  "statusCode": 200,
  "data": {
    "accessToken": "eyJ...",
    "refreshToken": "eyJ...",
    "user": {
      "id": "uuid",
      "email": null,
      "username": null,
      "createdAt": "2026-07-18T01:50:00.000Z"
    }
  },
  "timestamp": "2026-07-18T01:50:00.000Z",
  "path": "/auth/wallet/login"
}
```

**Invalid signature (401):**
```json
{
  "success": false,
  "statusCode": 401,
  "errorCode": "INVALID_SIGNATURE",
  "message": "Invalid wallet signature",
  "details": null,
  "timestamp": "2026-07-18T01:50:00.000Z",
  "path": "/auth/wallet/login"
}
```

#### Example 2 — Workflow not found (404)

```http
GET /admin/workflows/does-not-exist
Authorization: Bearer eyJ...
```

```json
{
  "success": false,
  "statusCode": 404,
  "errorCode": "WORKFLOW_NOT_FOUND",
  "message": "Workflow 'does-not-exist' not found",
  "details": null,
  "timestamp": "2026-07-18T01:50:00.000Z",
  "path": "/admin/workflows/does-not-exist"
}
```

#### Example 3 — Validation failure (400)

```http
POST /auth/nonce
Content-Type: application/json

{}
```

```json
{
  "success": false,
  "statusCode": 400,
  "errorCode": "VALIDATION_ERROR",
  "message": "publicKey should not be empty",
  "details": ["publicKey should not be empty"],
  "timestamp": "2026-07-18T01:50:00.000Z",
  "path": "/auth/nonce"
}
```

#### Example 4 — Rate limit exceeded (429)

```json
{
  "success": false,
  "statusCode": 429,
  "errorCode": "RATE_LIMIT_EXCEEDED",
  "message": "Too many requests. Please slow down.",
  "details": { "retryAfter": "2026-07-18T01:51:00.000Z" },
  "timestamp": "2026-07-18T01:50:00.000Z",
  "path": "/auth/wallet/login"
}
```

#### Example 5 — Insufficient role (403)

```json
{
  "success": false,
  "statusCode": 403,
  "errorCode": "INSUFFICIENT_ROLE",
  "message": "Required role: admin or superadmin. User has: user",
  "details": null,
  "timestamp": "2026-07-18T01:50:00.000Z",
  "path": "/admin/audit-logs"
}
```

### 🛠 Implementation Details

The error pipeline is composed of three pieces registered globally in `main.ts`:

1. **`HttpExceptionFilter`** (`src/common/filters/http-exception.filter.ts`)  
   Catches all exceptions and serialises them into the error envelope.  
   Handles `ApiError` sub-classes (typed domain errors), generic `HttpException` (NestJS), and unknown errors (→ 500).

2. **`ResponseEnvelopeInterceptor`** (`src/common/interceptors/response-envelope.interceptor.ts`)  
   Wraps every successful controller response in the success envelope.

3. **`ApiError` + sub-classes** (`src/common/exceptions/api-error.exception.ts`)  
   Base class extending `HttpException`.  
   Every domain-specific exception (e.g. `WorkflowNotFoundError`, `InvalidSignatureError`) extends it and carries a typed `ApiErrorCode`.

**To create a new domain error:**
```typescript
import { ApiError, ApiErrorCode } from '../common/exceptions/api-error.exception';

// Directly:
throw new ApiError(HttpStatus.CONFLICT, ApiErrorCode.CONFLICT, 'Slot already booked');

// Or create a named sub-class in api-error.exception.ts:
export class SlotAlreadyBookedError extends ApiError {
  constructor() {
    super(HttpStatus.CONFLICT, ApiErrorCode.CONFLICT, 'Slot already booked');
  }
}
```

---

🤝 Contributing The first step is to Fork the repository then you Create a feature branch Commit your changes git pull latest changes to avoid conflicts Submit a pull request Issues and feature requests are welcome.

🗄️ Database & Migrations Workflow

Para garantizar la integridad de los datos y la consistencia entre entornos, este proyecto utiliza **TypeORM Migrations** y **Docker**.

1. Infraestructura Local
Levanta la base de datos PostgreSQL utilizando el contenedor preconfigurado:
bash
docker-compose up -d

Nota: La base de datos está mapeada al puerto 5433 para evitar conflictos con instalaciones locales preexistentes.

2. Comandos de Migración
Utiliza estos scripts para gestionar el esquema de la base de datos sin usar synchronize: true:

Generar Migración: (Ejecutar después de modificar una entidad .entity.ts)

Bash
npm run migration:generate -- src/database/migrations/NombreDeLaMigracion
Aplicar Migraciones: (Sincroniza tu base de datos local con los últimos cambios)

Bash
npm run migration:run
Revertir Cambios: (Deshace la última migración aplicada)

Bash
npm run migration:revert

3. Buenas Prácticas 
Nunca modifiques manualmente las tablas en la base de datos; usa siempre archivos de migración.

Revisa el archivo generado en src/database/migrations/ antes de hacer commit para asegurar que el SQL es el esperado.

Asegúrate de que tu archivo .env apunte al puerto 5433 si usas el entorno Docker provisto.