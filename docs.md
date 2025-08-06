Hestia Backend API — Dokumentacja

Autoryzacja

- Większość endpointów wymaga tokenu JWT w nagłówku Authorization.
- Format nagłówka:
  Authorization: Bearer <token>
- Token otrzymujesz po zalogowaniu (/login).

---

Endpoints

1. Rejestracja użytkownika

`POST /api/register`
Content-Type: application/json

Body:
```json

{
  "username": "janek",
  "password": "tajne123"
}
```
Response:

- Sukces (201 lub 200):
```json

{
  "id": 1,
  "username": "janek"
}
```
- Błąd (np. użytkownik istnieje lub brak danych):
```json

{
  "error": "User already exists or invalid data"
}
```
---

2. Logowanie

`POST /login`
Content-Type: application/json

Body:
```json

{
  "username": "janek",
  "password": "tajne123"
}
```
Response:

- Sukces:
```json

{
  "token": "<jwt_token>"
}
```
- Błąd:
```json

{
  "error": "Invalid credentials"
}
```
---

3. Tworzenie grupy (wymaga autoryzacji)

`POST /groups`
Authorization: Bearer \<token>
Content-Type: application/json

Body:
```json

{
  "name": "Moja grupa"
}
```
Response:

- Sukces:
```json

{
  "id": 1,
  "name": "Moja grupa"
}
```
- Błąd (np. nazwa zajęta):
```json
{
  "error": "Group name taken or invalid data"
}
```

---

4. Pobieranie grup użytkownika (wymaga autoryzacji)

`GET /groups`
Authorization: Bearer <token>

Response:
```json
[
  {
    "id": 1,
    "name": "Moja grupa"
  },
  ...
]
```
---

5. Pobieranie wiadomości z grupy (wymaga autoryzacji)

GET /groups/:id/messages
Authorization: Bearer <token>

Response:

[
  {
    "id": 10,
    "content": "Cześć wszystkim!",
    "createdAt": "2025-08-06T15:00:00Z",
    "username": "janek"
  },
  ...
]

---

Socket.IO - Chat

- Połącz się z serwerem Socket.IO z tokenem w `auth`:

```js
const socket = io("http://api.toster.lol", {
  auth: { token: "<jwt_token>" }
});
// Emituj zdarzenia:

joinGroup(groupId)

leaveGroup(groupId)

sendMessage({ groupId, content })

// Odbieraj zdarzenia:

newMessage { id, content, createdAt, username }

// Użycie

// Zarejestruj się: POST /api/register

// Zaloguj się: POST /login — odbierz token

Używaj tokenu w nagłówkach Authorization lub w Socket.IO

Twórz i zarządzaj grupami i wiadomościami

```