# Hestia Chat Backend

A secure, scalable backend for the Hestia Chat application built with Node.js, Express, TypeScript, and Prisma.

## Features

- **Authentication**: JWT-based authentication with rate limiting
- **Real-time Communication**: Socket.io integration for real-time messaging
- **Security**: Helmet for security headers, input validation with Joi
- **Performance**: Compression middleware, async handlers
- **Database**: Prisma ORM with PostgreSQL/SQLite support
- **Testing**: Jest test suite with supertest

## How to Run the Server (Development)

### Prerequisites

- Node.js (v18+ recommended)
- npm or pnpm
- Database (PostgreSQL or SQLite)

### Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/hestiachat/backend.git
   cd backend
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Environment Setup**
   Create a `.env` file in the root directory:
   ```env
   DATABASE_URL="your_database_connection_string"
   JWT_SECRET="your_super_secret_jwt_key"
   PORT=4000
   ```

4. **Database Setup**
   ```bash
   npm run prisma:generate
   npm run prisma:migrate
   ```

5. **Start Development Server**
   ```bash
   npm run dev
   ```

   The server will start on `http://localhost:4000` (or the port specified in your `.env` file).

### Build for Production

```bash
npm run build
npm start
```

## API Documentation

### Base URL
```
http://localhost:4000/api
```

### Authentication

All requests requiring authentication must include a JWT token in the Authorization header:
```
Authorization: Bearer <your_jwt_token>
```

### Endpoints

#### Authentication

##### Register User
```bash
curl -X POST http://localhost:4000/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "your_username",
    "password": "your_password"
  }'
```

**Response:**
```json
{
  "id": 1,
  "username": "your_username"
}
```

##### Login
```bash
curl -X POST http://localhost:4000/api/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "your_username",
    "password": "your_password"
  }'
```

**Response:**
```json
{
  "token": "your_jwt_token_here"
}
```

#### Groups

##### Create Group (Requires Authentication)
```bash
curl -X POST http://localhost:4000/api/groups \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <your_jwt_token>" \
  -d '{
    "name": "My Group"
  }'
```

##### Get User's Groups (Requires Authentication)
```bash
curl -X GET http://localhost:4000/api/groups \
  -H "Authorization: Bearer <your_jwt_token>"
```

##### Get Group Messages (Requires Authentication)
```bash
curl -X GET http://localhost:4000/api/groups/1/messages \
  -H "Authorization: Bearer <your_jwt_token>"
```

### Input Validation

- **Username**: 3-30 alphanumeric characters
- **Password**: 6-100 characters
- **Group Name**: 1-100 characters

### Rate Limiting

- **Registration**: 5 attempts per minute
- **Login**: 10 attempts per minute

### Error Responses

All error responses follow this format:
```json
{
  "error": "Error message description"
}
```

## Testing

Run the test suite:
```bash
npm test
```

Run tests in watch mode:
```bash
npm run test:watch
```

## Project Structure

```
src/
├── index.ts              # Main application entry point
├── middleware/           # Express middleware
│   ├── auth.ts          # JWT authentication middleware
│   └── errorHandler.ts  # Global error handler
├── routes/              # API route handlers
│   ├── auth.ts          # Authentication routes
│   ├── groups.ts        # Group management routes
│   └── friends.ts       # Friend management routes
├── prismaClient.ts      # Prisma database client
└── socket.ts            # Socket.io configuration
```

## Security Features

- **Helmet**: Secure HTTP headers
- **Rate Limiting**: Prevents brute force attacks
- **Input Validation**: Joi schema validation
- **JWT Authentication**: Secure token-based auth
- **Password Hashing**: bcrypt with salt rounds
- **CORS**: Configurable cross-origin requests

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Ensure all tests pass
6. Submit a pull request

## License

This project is licensed under the MIT License.