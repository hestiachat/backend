# Contributing to Hestia Chat Backend

Thank you for considering contributing! 🎉  
We welcome pull requests, issues, and suggestions from everyone.

---

## How to Contribute

### 1. Fork the repository

Click "Fork" at the top right of the [repo page](https://github.com/hestiachat/backend).

### 2. Clone your fork

```sh
git clone https://github.com/your-username/backend.git
cd backend
```

### 3. Create a new branch

Use a descriptive name, e.g. `feature/add-group-endpoint` or `fix/friend-requests-bug`:

```sh
git checkout -b my-feature-branch
```

### 4. Install dependencies

```sh
npm install
```

### 5. Code!

- Keep code style consistent (Prettier/ESLint are enforced).
- Write clear, concise commit messages.
- Write or update tests if needed.

### 6. Test your changes

- Run tests:  
  ```sh
  npm test
  ```
- Run linter:  
  ```sh
  npm run lint
  ```

### 7. Rebase onto latest main

```sh
git fetch origin
git rebase origin/main
```

### 8. Push your branch

```sh
git push origin my-feature-branch
```

### 9. Create a Pull Request

- Go to [Pull Requests](https://github.com/hestiachat/backend/pulls) on GitHub.
- Click "New Pull Request", select your branch.
- Fill out the PR template and describe your changes.

---

## Code of Conduct

By participating, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

---

## Guidelines

- **Small, focused PRs:** One purpose per PR.
- **Tests:** If you add/modify features, add/modify tests.
- **Docs:** Update docs/comments if you change public APIs.
- **Discussions:** Use [GitHub Discussions](https://github.com/hestiachat/backend/discussions) or open an issue for ideas/feedback.

---

## Need Help?

Open an [issue](https://github.com/hestiachat/backend/issues) or join our Discussions!

Thank you for helping make Hestia Chat better! 🚀