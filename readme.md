[![Build Status](https://img.shields.io/github/actions/workflow/status/hestiachat/backend/ci.yml?branch=main)](https://github.com/hestiachat/backend/actions)
[![Coverage](https://img.shields.io/codecov/c/github/hestiachat/backend)](https://codecov.io/gh/hestiachat/backend)
[![License](https://img.shields.io/github/license/hestiachat/backend)](https://github.com/hestiachat/backend/blob/main/LICENSE)
[![Release](https://img.shields.io/github/v/release/hestiachat/backend)](https://github.com/hestiachat/backend/releases)
[![Issues](https://img.shields.io/github/issues/hestiachat/backend)](https://github.com/hestiachat/backend/issues)
[![Pull Requests](https://img.shields.io/github/issues-pr/hestiachat/backend)](https://github.com/hestiachat/backend/pulls)
[![Last Commit](https://img.shields.io/github/last-commit/hestiachat/backend/main)](https://github.com/hestiachat/backend/commits/main)
[![Contributors](https://img.shields.io/github/contributors/hestiachat/backend)](https://github.com/hestiachat/backend/graphs/contributors)

# Hestia Chat Backend

> **Modern, secure, and scalable chat backend powering [Hestia Chat](https://github.com/hestiachat).**

This repository contains the backend API and real-time server for Hestia Chat, built with TypeScript, Prisma, MariaDB, and Socket.IO.  
It handles user authentication, messaging, groups, friends, file uploads, notifications (FCM), and more.

---

## 🚀 Features

- **JWT Authentication**  
- **Direct and Group Messaging** (end-to-end encrypted)
- **Real-time updates** (Socket.IO WebSocket API)
- **User Profiles & Avatars**
- **Friends and Requests**
- **Push Notifications** (FCM)
- **REST API** (well-documented below)
- **CI, Coverage, Releases**

---

## 🛠️ Getting Started

1. **Clone and install dependencies**
   ```sh
   git clone https://github.com/hestiachat/backend.git
   cd backend
   npm install
   ```

2. **Configure environment**

   - Copy `.env.example` to `.env` and fill in the variables (JWT secret, database, FCM, etc).

3. **Database setup**
   ```sh
   npx prisma migrate dev --name init
   npx prisma generate
   ```

4. **Run the server**
   ```sh
   npm run dev
   # or for production
   npm run build && npm start
   ```

---

## 🔒 Authorization

Most endpoints require a JWT token:

```
Authorization: Bearer <token>
```

You receive this token after logging in (`POST /auth/login`).  
**All endpoints under `/auth`, `/groups`, `/messages`, `/users`, `/friends` require authorization unless noted.**

**API Base URL:** `https://api.toster.lol`  
**WebSocket URL:** `wss://api.toster.lol` (Socket.IO)

---

## 📚 REST API Endpoints

### Health Check

- **GET `/health`**  
  Returns `{ status: "ok", timestamp: "<iso8601>" }`  
  _Public, no auth._

---

### Auth

- **POST `/auth/register`**  
  Register a new user.  
  Body: `{ "username": "string", "password": "string" }`  
  Response: `{ user: { id, username }, token }`

- **POST `/auth/login`**  
  Login.  
  Body: `{ "username": "string", "password": "string" }`  
  Response: `{ user: { id, username }, token }`

- **GET `/auth/status`**  
  Check login status.  
  Headers: `Authorization: Bearer <token>`  
  Response: `{ authenticated: true, user: { id, username } }`

---

### Users

- **GET `/users/by-username/:username`** — Get user info by username.
- **GET `/users/by-id/:id`** — Get user info by id.
- **GET `/users/me`** — Get your own profile.
- **DELETE `/users/me`** — Delete your account.
- **PATCH `/users/profile-picture`** — Update your profile picture. (FormData: `avatar` file or `profilePictureUrl` string)
- **PATCH `/users/status`** — Set your status. (Body: `{ status: "active" | "offline" | "do_not_disturb" }`)
- **PATCH `/users/fcm-token`** — Save/update your device's FCM token for push notifications.
- **PATCH `/users/bio`** — Update your bio. (Body: `{ "bio": "Your new bio" }`)

---

### Groups

- **POST `/groups`** — Create a group. (Body: `{ "name": "string" }`)
- **GET `/groups`** — List groups you belong to.
- **PUT `/groups/:id`** — Update group info.
- **POST `/groups/:id/messages`** — Send a message to a group.
- **GET `/groups/:id`** — Get group details.
- **GET `/groups/:id/messages`** — Get group messages.
- **DELETE `/groups/:id/members/:userId`** — Remove a member from a group.
- **POST `/groups/:id/members/:userId`** — Add a member to a group.

---

### Friends

- **POST `/friends/request/:id`** — Send a friend request.
- **GET `/friends`** — List your friends.
- **GET `/friends/requests`** — List incoming friend requests.
- **POST `/friends/accept/:id`** — Accept a friend request.

---

### Static Files

- **GET `/uploads/avatars/:filename`** — Serve uploaded profile pictures.

---

## 🔌 WebSocket API (Socket.IO)

**Connect to WebSocket:**

```js
const socket = io("https://api.toster.lol", {
  auth: { token: "<jwt_token>" }
});
```

### Client → Server Events

- **joinGroup**  
  Join a group chat room  
  ```js
  socket.emit("joinGroup", { groupId: 123 });
  ```
- **leaveGroup**  
  Leave a group chat room  
  ```js
  socket.emit("leaveGroup", { groupId: 123 });
  ```
- **sendDM**  
  Send a direct/private message  
  ```js
  socket.emit("sendDM", { toId: 42, content: "Hello!" });
  ```
- **getDMHistory**  
  Fetch message history with a user  
  ```js
  socket.emit("getDMHistory", { otherId: 42 }, (messages) => {
    // messages: [{ id, content, createdAt, userId, username }]
  });
  ```
- **sendGroupMessage**  
  Send a message to a group  
  ```js
  socket.emit("sendGroupMessage", { groupId: 123, content: "Hello group!" });
  ```
- **getGroupHistory**  
  Fetch message history for a group  
  ```js
  socket.emit("getGroupHistory", { groupId: 123 }, (messages) => {
    // messages: [{ id, content, createdAt, userId, username, groupId }]
  });
  ```

### Server → Client Events

- **newDM**  
  Receive a new direct message  
  ```js
  socket.on("newDM", (msg) => { ... });
  ```
- **dmNotification**  
  Notification about a new DM  
  ```js
  socket.on("dmNotification", (data) => { ... });
  ```
- **newGroupMessage**  
  New message in a group  
  ```js
  socket.on("newGroupMessage", (msg) => { ... });
  ```
- **error**  
  Error event  
  ```js
  socket.on("error", (err) => { ... });
  ```

---

### Example: Minimal Realtime Chat

```js
const socket = io("https://api.toster.lol", {
  auth: { token: "<jwt_token>" }
});

// Send a DM
socket.emit("sendDM", { toId: 2, content: "hi!" });

// Listen for DMs
socket.on("newDM", (msg) => {
  console.log("You received a DM:", msg);
});
```

---

## 📝 Example REST Usage

- **Register:** `POST /auth/register`
- **Login:** `POST /auth/login` (get JWT)
- Use JWT in `Authorization` header for all protected endpoints.
- Manage groups, friends, and messages.

---

## ⚠️ Notes

- Most endpoints return errors as: `{ error: "error message" }`
- Rate limits apply to some endpoints.
- For full API details, see the [OpenAPI spec](./openapi.yaml) (if present).

---

## 🤝 Contributing

PRs, suggestions, and bug reports are welcome!  
See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---