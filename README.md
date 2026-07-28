# RozVibe Encryption Core

> **The open-source client-side encryption engine powering RozVibe — a privacy-first encrypted journaling app for Android.**

---

## Overview

Unlike many cloud-based journaling platforms where encryption is performed on the server (or where service providers can technically access user data), RozVibe encrypts journal entries locally on the user's device before they are synchronized to the cloud.

The purpose of open-sourcing this module is simple: **Privacy should be verifiable—not merely promised.**

Instead of asking users to blindly trust our security claims, we want developers, researchers, and the broader security community to inspect the mathematical implementation themselves.

---

## About RozVibe & The Philosophy

RozVibe is a private encrypted journaling application designed for people who value emotional privacy. The project started after a realization: people subconsciously censor themselves in digital journals because they don't fully trust where their data is going.

I often found myself rewriting—or deleting—personal thoughts because I wasn't completely confident about who could potentially access it. That experience became the foundation of RozVibe. Rather than treating encryption as an afterthought or a premium feature, RozVibe treats it as the core architecture.

Our philosophy is simple: **People write more honestly when they genuinely feel safe.**

---

## 🔒 The Zero-Knowledge Architecture

RozVibe performs encryption entirely on the user's device. At no point during normal operation is plaintext journal content transmitted to the cloud.

### 1. Key Derivation (PBKDF2)
When you set up RozVibe, the app combines your unique User ID with your secret PIN (or a secure default if no PIN is chosen).

* We use **PBKDF2 with HMAC-SHA256 (100,000 iterations)** alongside a unique 16-byte cryptographically secure random salt to stretch this password.
* To prevent UI freezing, this massive 100k-iteration process runs in a background **Isolate** (a separate CPU thread).
* The resulting 76-byte key material is cached locally in Android's hardware-backed `EncryptedSharedPreferences`.

### 2. AES-256-GCM Encryption
We use **AES in GCM (Galois/Counter Mode)** for authenticated encryption, providing confidentiality, integrity, and authentication.

* **Dynamic IVs:** Every single encryption operation generates a completely fresh, secure, random 12-byte Initialization Vector (IV).
* The authentication tag ensures that unauthorized modifications or database tampering can be instantly detected during decryption.

### 3. Blind Search Indexing
Searching encrypted content presents an interesting challenge. Decrypting an entire journal for every search becomes increasingly inefficient.

* RozVibe addresses this using a blind-index architecture. Instead of storing searchable plaintext terms, the `SearchTokenizer` normalizes text and generates deterministic HMAC-SHA256 hashes locally.
* These hashes are stored strictly in an offline, local SQLite database (`SearchIndexDatabase`).
* Search queries remain local to the device. Only matching encrypted entries are pulled from the cloud and decrypted.

---

## 📁 Repository Scope

This repository focuses exclusively on the cryptographic components that power RozVibe.

**What is included:**
* AES-256-GCM authenticated encryption engine (`encryption_service.dart`)
* PBKDF2-HMAC-SHA256 key derivation logic
* Blind index token generation (`search_tokenizer.dart`)
* Local offline SQLite indexing logic (`search_index_database.dart`)

**This repository intentionally excludes:**
* The Flutter UI and custom animations
* Firebase/Firestore synchronization logic
* Authentication flows and Business logic
* Proprietary application features (Mood tracking, analytics, etc.)

---

## 🛡️ Threat Model

No security architecture can eliminate every threat. This project attempts to minimize realistic risks while remaining practical for everyday users.

#### This module primarily protects against:
* Database compromise or data breaches
* Cloud storage exposure
* Unauthorized server access
* Passive interception during synchronization
* Curious service providers or developers

#### This module does NOT protect against:
* Malware executing on a user's device (e.g., keyloggers)
* A compromised operating system (rooted/jailbroken devices)
* Physical access to an already unlocked device
* Hardware-level attacks or screen recording

---

## Key Management Philosophy

One of the primary goals of RozVibe is reducing unnecessary trust. Encryption keys are:
* Derived locally
* Reconstructed when needed
* Held only in memory during active use
* Cleared from memory on logout
* Never stored in Firestore or embedded inside encrypted journal documents.

---

## Auditing & Vulnerability Disclosure

Privacy software should welcome scrutiny. Publishing this encryption module allows security professionals to review the implementation, identify weaknesses, and verify architectural claims. Constructive criticism is highly encouraged.

However, cryptography should never rely solely on documentation. If you discover a potential issue or exploitable vulnerability, please report it responsibly rather than publicly disclosing it.

**Contact:** support@rozvibe.me

---

## Related Links

* **RozVibe Website:** [https://www.rozvibe.me](https://www.rozvibe.me)
* **Google Play:** [Download](https://play.google.com/store/apps/details?id=com.SezRonix.RozVibe)
* **Security Overview:** [https://www.rozvibe.me/security.html](https://www.rozvibe.me/security.html)
* **Press Kit:** [https://www.rozvibe.me/press.html](https://www.rozvibe.me/press.html)
* **Privacy Policy:** [https://www.rozvibe.me/privacy-policy.html](https://www.rozvibe.me/privacy-policy.html)

---

## License

This repository is provided under a Source-Available, Non-Commercial License.

The source code is published here strictly for transparency, educational purposes, and security auditing. You are welcome to read, review, and analyze the code. However, you are strictly prohibited from copying, redistributing, or using this code in any commercial product, application, or service without explicit written permission from SezRonix.

---

*RozVibe isn't built on the assumption that users should simply trust the developer. It's built on the belief that the most important privacy claims should be understandable, inspectable, and open to scrutiny.*
