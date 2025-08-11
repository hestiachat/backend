[![Build Status](https://img.shields.io/github/actions/workflow/status/hestiachat/backend/ci.yml?branch=main)](https://github.com/hestiachat/backend/actions)
[![Coverage](https://img.shields.io/codecov/c/github/hestiachat/backend)](https://codecov.io/gh/hestiachat/backend)
[![License](https://img.shields.io/github/license/hestiachat/backend)](https://github.com/hestiachat/backend/blob/main/LICENSE)
[![Release](https://img.shields.io/github/v/release/hestiachat/backend)](https://github.com/hestiachat/backend/releases)
[![Issues](https://img.shields.io/github/issues/hestiachat/backend)](https://github.com/hestiachat/backend/issues)
[![Pull Requests](https://img.shields.io/github/issues-pr/hestiachat/backend)](https://github.com/hestiachat/backend/pulls)
[![Last Commit](https://img.shields.io/github/last-commit/hestiachat/backend/main)](https://github.com/hestiachat/backend/commits/main)
[![Contributors](https://img.shields.io/github/contributors/hestiachat/backend)](https://github.com/hestiachat/backend/graphs/contributors)
# Hestia Chat Backend — API Documentation

## Authorization

Most endpoints require a JWT token in the `Authorization` header:
```
Authorization: Bearer <token>
```
You receive this token after logging in (`POST /auth/login`).  
**All endpoints prefixed with `/auth`, `/groups`, `/messages`, `/users`, `/friends` require authorization unless noted.**

### **API Base URL => `https://api.toster.lol`** 

---

## Endpoints

### Health Check

- **GET `/health`**
  - Returns `{ status: "ok", timestamp: "<iso8601>" }`
  - No auth required.

---

### Auth

- **POST `/auth/register`**
  - Register a new user.
  - Body: `{ "username": "string", "password": "string" }`
  - Response: `{ user: { id, username }, token }` or error.

- **POST `/auth/login`**
  - Login.
  - Body: `{ "username": "string", "password": "string" }`
  - Response: `{ user: { id, username }, token }` or error.

- **GET `/auth/status`**
  - Check login status.
  - Headers: `Authorization: Bearer <token>`
  - Response: `{ authenticated: true, user: { id, username } }` or error.

---

### Users

- **GET `/users/by-username/:username`**
  - Get user info by username.

- **GET `/users/by-id/:id`**
  - Get user info by id.

- **GET `/users/me`**
  - Get your own profile.

- **DELETE `/users/me`**
  - Delete your account.

- **PATCH `/users/profile-picture`**
  - Update your profile picture.
  - FormData: `avatar` file or `profilePictureUrl` string.

- **PATCH `/users/bio`**
  - Change your bio.
  - Body: `{ "bio": "Your new bio" }`
  - Auth required.
  - Response: `{ id, username, profilePictureUrl, bio }`

---

### Groups

- **POST `/groups`**
  - Create a group.
  - Body: `{ "name": "string" }`
  - Requires auth.
- **GET `/groups`**
  - List groups you belong to.
  - Requires auth.
- **PUT `/groups/:id`**
  - Update group
- **POST `/groups/:id/messages`** 
  - Send a message to a group by ID
- **GET `/groups/:id`**
  - Get group details by id.
  - Requires auth.
- **GET `/groups/:id/messages`**
  - Get messages from a group.
  - Requires auth.
  - Returns: `[{ id, content, createdAt, username }, ...]`
- **DELETE `/groups/:id/members/:userId`**
  - Deletes :userId from group :id
- **POST `/groups/:id/members/:userId`** 
  - Add member :userId to group :id
---

---

### Friends

- **POST `/friends/request/:id`**
  - Send a friend request (to user id).

- **GET `/friends`**
  - List your friends.

- **GET `/friends/requests`**
  - List incoming friend requests.

- **POST `/friends/accept/:id`**
  - Accept friend request (from user id).

---

## Static Files

- **GET `/uploads/avatars/:filename`**
  - Serve uploaded profile pictures.

---

## Socket.IO (Realtime Chat)

- Connect:  
  ```js
  const socket = io("https://api.toster.lol", {
    auth: { token: "<jwt_token>" }
  });
  ```
  - **Events:**  
    - `joinGroup(groupId)`
    - `leaveGroup(groupId)`
    - `sendMessage({ groupId, content })`
    - Listen for: `newMessage { id, content, createdAt, username }`

---

## Example Usage

- **Register:** `POST /auth/register`
- **Login:** `POST /auth/login` (get JWT)
- Use JWT in `Authorization` header for all protected endpoints.
- Manage groups, friends, and messages.

---

## Notes

- Most endpoints return errors in the form: `{ error: "error message" }`
- Rate limits apply to some endpoints.
