# Contributing to CoC Studio

Thank you for your interest in contributing to **CoC Studio (Vopple Open Source Governance File Generator)**!

This project provides a clean, minimalist web tool for generating `CODE_OF_CONDUCT.md`, `CONTACT.md`, `SECURITY.md`, `CODEOWNERS`, and `CONTRIBUTING.md` for open source repositories.

---

## Code of Conduct

All contributors and participants are expected to adhere to our community standards. Please treat fellow contributors with respect, patience, and kindness.

---

## Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/VicRoger27/CoC-Gen.git
   cd CoC-Gen
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Start the local dev server:**
   ```bash
   npm run dev
   ```

4. **Verify TypeScript & build:**
   ```bash
   npm run lint
   npm run build
   ```

---

## Submitting a Pull Request

1. Create a descriptive feature branch from `main` (`git checkout -b feat/my-improvement`).
2. Keep changes focused and clean.
3. Test your changes locally to ensure `npm run build` and `npm run lint` pass without errors.
4. Push your branch and open a Pull Request describing what changes were made.
