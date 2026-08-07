# MCMS Backend – Full Audit Report

---

## 1. Architecture Overview

The backend has been successfully refactored into a clean **Domain/Feature Module** structure. At a high level:

```
src/
├── server.js         → Entry point
├── app.js            → Express app + middleware + route mounting
├── config/           → DB + Firebase init
├── middlewares/      → Auth + error handling
└── modules/
    ├── users/
    ├── camps/
    ├── registrations/
    ├── payments/
    ├── feedback/
    └── public/
```

**Verdict**: Architecture is sound and significantly improved. Issues found are at the logic, security, and consistency level.

---

## 2. 🔴 Critical Issues

### 2.1 — `.env` File Is Tracked With Sensitive Data

> [!CAUTION]
> The `.env` file contains real Stripe secret keys, MongoDB credentials, and a Firebase Admin SDK service account key. While `.env` is in `.gitignore`, the `serviceAccountKey.json` file listed there suggests these credentials **may have already been committed** in a previous version.

**Affected**: `.env`, `.gitignore`

**Recommendations**:

- Rotate the Stripe secret key, MongoDB password, and Firebase service account key immediately if they were ever committed.
- Confirm `.env` is not present in any historical git commit with `git log --all --full-history -- .env`.

---

### 2.2 — `firebase.js` Runs at Module Load Time (Top-Level Side Effect)

> [!CAUTION]
> [src/config/firebase.js](file:///d:/workspace/prime_showcase/medical-camp-management-system/MCMS-backend/src/config/firebase.js) runs `admin.initializeApp()` and `Buffer.from(process.env.FB_SERVICE_KEY...)` at the moment the module is `require()`'d — **before `dotenv.config()` has run in some import orderings**. If `firebase.js` is loaded before `dotenv` initialises, `process.env.FB_SERVICE_KEY` will be `undefined`, causing a crash.

**Affected**: [src/config/firebase.js](file:///d:/workspace/prime_showcase/medical-camp-management-system/MCMS-backend/src/config/firebase.js), [src/server.js](file:///d:/workspace/prime_showcase/medical-camp-management-system/MCMS-backend/src/server.js)

**Fix**: Move `require('dotenv').config()` to the very top of `server.js` — **before any other require()**. Currently it is on line 1 which is correct, but confirm no other top-level module triggers firebase loading before it.

---

### 2.3 — `DELETE /registrations/:id` Has No Auth Protection

> [!CAUTION]
> The route `DELETE /registrations/:id` in [registrations.routes.js](file:///d:/workspace/prime_showcase/medical-camp-management-system/MCMS-backend/src/modules/registrations/registrations.routes.js) (line 17) has **zero authentication or authorization middleware**. Any unauthenticated user who knows a registration ObjectId can delete any registration.

```js
// INSECURE - no verifyFBToken, no ownership check
router.delete('/registrations/:id', registrationsController.deleteRegistration);
```

**Fix**: Add `verifyFBToken` + an ownership check (verify the registration's `participantEmail` matches `req.user.email`).

---

### 2.4 — Stripe Webhook Has No Raw Body Guard in `app.js`

> [!CAUTION]
> `express.json()` parses the body globally in [app.js](file:///d:/workspace/prime_showcase/medical-camp-management-system/MCMS-backend/src/app.js) **before** the stripe webhook handler gets the raw buffer. Stripe's `constructEvent()` **requires the raw, unparsed body** — once `express.json()` has consumed it, the webhook signature verification will **always fail** in production.

**Fix**: Register the Stripe webhook route _before_ `app.use(express.json())` in `app.js`, or use conditional raw body parsing before mounting the payment routes.

---

### 2.5 — `payments.controller.js` — Stripe Initialised at Module Load

> [!WARNING]
> [payments.controller.js](file:///d:/workspace/prime_showcase/medical-camp-management-system/MCMS-backend/src/modules/payments/payments.controller.js) line 1:
>
> ```js
> const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
> ```
>
> If `STRIPE_SECRET_KEY` is undefined at module load (e.g. env not yet loaded), this will silently create a Stripe client with an invalid key rather than crashing immediately, causing confusing runtime errors on payment calls.

---

## 3. 🟠 Security Issues

### 3.1 — User Role Can Be Freely Set on Registration

In [users.controller.js](file:///d:/workspace/prime_showcase/medical-camp-management-system/MCMS-backend/src/modules/users/users.controller.js) `upsertUser`:

```js
const { email, name, photoURL, role, created_at, last_login } = req.body;
```

The `role` field is taken directly from the request body and stored with `$setOnInsert`. A client can set `role: "organizer"` on self-registration, granting themselves organizer privileges.

**Fix**: Never trust the `role` field from the client. Always default new users to `role: "participant"` server-side:

```js
role: 'participant', // always set server-side
```

### 3.2 — `PUT /users/:email` Allows Role Escalation

In `updateUser`, the `role` field is accepted from the request body without restriction and can be used to escalate any user's role:

```js
if (role !== undefined) updateFields.role = role;
```

**Fix**: Remove `role` from the `updateUser` handler. Role changes should be a separate admin-only endpoint.

### 3.3 — `GET /users/:email` Is Publicly Accessible

Any unauthenticated user can fetch another user's full profile including `photoURL`, `role`, `phone`, `address`, and `last_login` just by knowing their email.

**Fix**: Add `verifyFBToken` to `GET /users/:email`.

### 3.4 — `GET /users/:email/role` Is Publicly Accessible

Role information is a privileged detail that leaks whether any given email has organizer access.

**Fix**: Add `verifyFBToken` to `GET /users/:email/role`.

### 3.5 — CORS Applied Twice in `app.js`

`cors()` is applied with no configuration first in `app.js`, then overridden with the proper origin whitelist configuration. The first unconfigured `cors()` call is a leftover from the original `index.js` and should be removed.

Wait — looking at the current code: this was already cleaned up. ✅

### 3.6 — Rate Limiting Is Global and Too Permissive

100 requests per 15 minutes applies to all routes equally including auth-sensitive ones like `/create-payment-intent` and `POST /feedback`. Consider adding stricter per-route limiters on payment and auth endpoints.

### 3.7 — No Input Sanitization Against NoSQL Injection

User-supplied `search` strings in `getCamps` and `getAllRegistrations` are inserted into `RegExp` without escaping. A malicious regex like `(.|+)*` could cause a **ReDoS (Regular Expression Denial of Service)** attack.

**Fix**: Escape regex special characters before constructing the `RegExp`:

```js
const escaped = search.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const searchRegex = new RegExp(escaped, 'i');
```

---

## 4. 🟡 Logic & Data Integrity Issues

### 4.1 — `deleteRegistration` Doesn't Decrement Participant Count

`deleteRegistration` (used by the organizer admin delete) deletes the registration document but **never decrements `participantCount`** on the camps collection. Only `cancelRegistration` does this correctly.

### 4.2 — `deleteCamp` Deletes Registrations But Not Payments or Feedback

When a camp is deleted, associated `registrations` are cascade-deleted, but **payments** and **feedback** linked to that camp are **orphaned** in their collections.

### 4.3 — `registerForCamp` Uses a Placeholder `transactionId`

```js
transactionId: new ObjectId(), // Generate a unique ID
```

A random ObjectId is generated as a `transactionId` at registration time. This field is later set to the real Stripe transaction ID at payment time. However, the unique index on `transactionId` means this random ObjectId must be unique — while this works, it makes the schema misleading. The unique index should be `sparse: true` on the actual payment transactionId and the field shouldn't be pre-populated at registration.

### 4.4 — `getAllRegistrations` Status Filter Uses Wrong Field

```js
if (status !== 'all') {
  filter.status = status; // ← wrong field
}
```

The registrations collection uses `confirmationStatus` and `paymentStatus` as field names. There is no field called `status`. This filter will always return 0 results when used.

**Fix**: Clarify which status field is intended and use the correct field name.

### 4.5 — `getPaymentsByEmail` Has a Redundant Endpoint

`GET /payments` (authenticated, uses `req.user.email`) and `GET /paymentsByEmail` (authenticated, requires `email` query param and cross-checks with token) do the same thing. The `/paymentsByEmail` endpoint is redundant and creates a confusing API surface.

### 4.6 — `checkRegistration` Doesn't Validate `campId`

```js
const { campId } = req.query;
const registration = await registrationsCollection.findOne({
  campId: new ObjectId(campId), // will throw if campId is invalid
  ...
});
```

If `campId` is missing or invalid, `new ObjectId(campId)` will throw an unhandled exception that falls through to a 500 error. Should validate the campId first.

### 4.7 — Inconsistent Response Format

Different modules return responses in different shapes:

- Some return `{ success: true, data: [...] }` (public module)
- Some return raw arrays (feedback `getFeedback`)
- Some return `{ error: "..." }` while others use `{ message: "..." }`
- Some use `res.send()` and some use `res.json()`

This makes frontend integration unpredictable. Standardize on one response envelope.

---

## 5. 🔵 Code Quality Issues

### 5.1 — `auth.middleware.js` — Unused `error` Variable (ESLint Warnings)

```js
} catch (error) {  // 'error' is defined but never used (lines 28, 41)
  return res.status(500).json({ ... });
}
```

**Fix**: Replace `error` with `_error` or just `_` to silence the lint warning while keeping intent clear:

```js
} catch (_error) {
```

### 5.2 — `verifyOrganizer` and `verifyParticipant` Make DB Calls on Every Request

Each protected route makes a fresh `findOne` to the users collection on every single request to verify the role. This is an N+1 performance issue for heavily-used endpoints.

**Fix**: Cache the user role in the JWT token claims (Firebase custom claims) or in `req.user` after the token is verified in `verifyFBToken`.

### 5.3 — `addCamp` Has No Input Validation

`POST /camps` accepts the entire `req.body` as the new camp document with no validation of required fields (name, fees, location, dateTime, etc.). A malformed camp document can be inserted directly into the database.

### 5.4 — `updateCamp` Blindly Sets All Body Fields

```js
const result = await campsCollection.updateOne(
  { _id: new ObjectId(campId) },
  { $set: updatedCamp } // updatedCamp = entire req.body
);
```

This allows an organizer to overwrite system fields like `organizerEmail`, `createdAt`, `participantCount` by including them in the request body.

**Fix**: Whitelist only the editable fields:

```js
const { name, location, fees, dateTime, healthcareProfessional, description } = req.body;
const updateFields = { name, location, fees, ... };
```

### 5.5 — No `start` Script in `package.json`

There is no `"start": "node src/server.js"` script. Deployments on many platforms (including some Vercel configurations) look for the `start` script as a fallback.

### 5.6 — `getCampsWithRegistrations` is in the Wrong Module

This is a participant-specific view in [camps.controller.js](file:///d:/workspace/prime_showcase/medical-camp-management-system/MCMS-backend/src/modules/camps/camps.controller.js), but it primarily operates on registrations and is participant-scoped. It would be better placed in the `registrations` module.

### 5.7 — No Graceful Shutdown Handling

The server has no `SIGTERM`/`SIGINT` handler to close the MongoDB connection cleanly on process exit or container stop.

---

## 6. Summary Table

| #   | Severity    | Area          | Issue                                              |
| --- | ----------- | ------------- | -------------------------------------------------- |
| 2.1 | 🔴 Critical | Security      | Real credentials in `.env` at risk                 |
| 2.2 | 🔴 Critical | Config        | Firebase init runs before dotenv                   |
| 2.3 | 🔴 Critical | Auth          | `DELETE /registrations/:id` is unprotected         |
| 2.4 | 🔴 Critical | Payments      | Stripe webhook body parsing broken                 |
| 2.5 | 🔴 Critical | Config        | Stripe key may be undefined at module load         |
| 3.1 | 🟠 Security | Users         | Role can be set freely on sign-up                  |
| 3.2 | 🟠 Security | Users         | `PUT /users/:email` allows role escalation         |
| 3.3 | 🟠 Security | Users         | `GET /users/:email` is unauthenticated             |
| 3.4 | 🟠 Security | Users         | `GET /users/:email/role` is unauthenticated        |
| 3.6 | 🟠 Security | App           | Rate limit too permissive on sensitive routes      |
| 3.7 | 🟠 Security | Camps         | ReDoS via unescaped regex in search                |
| 4.1 | 🟡 Logic    | Registrations | Admin delete doesn't decrement count               |
| 4.2 | 🟡 Logic    | Camps         | Cascade delete orphans payments/feedback           |
| 4.3 | 🟡 Logic    | Registrations | Misleading pre-set `transactionId` at registration |
| 4.4 | 🟡 Logic    | Registrations | Status filter uses wrong field name                |
| 4.5 | 🟡 Logic    | Payments      | Redundant `/paymentsByEmail` endpoint              |
| 4.6 | 🟡 Logic    | Registrations | `checkRegistration` doesn't validate campId        |
| 4.7 | 🟡 Logic    | All           | Inconsistent response format                       |
| 5.1 | 🔵 Quality  | Middlewares   | Unused `error` var (ESLint warnings)               |
| 5.2 | 🔵 Quality  | Auth          | DB call on every protected request                 |
| 5.3 | 🔵 Quality  | Camps         | No input validation on `addCamp`                   |
| 5.4 | 🔵 Quality  | Camps         | `updateCamp` overwrites system fields              |
| 5.5 | 🔵 Quality  | Config        | No `start` script in `package.json`                |
| 5.6 | 🔵 Quality  | Structure     | `getCampsWithRegistrations` in wrong module        |
| 5.7 | 🔵 Quality  | Server        | No graceful shutdown handler                       |

---

## 7. Recommended Priority Order

1. Fix **2.3** (unprotected delete endpoint) — immediate security risk
2. Fix **2.4** (Stripe webhook body parsing) — breaks payment confirmation
3. Fix **3.1 + 3.2** (role escalation) — authorization bypass
4. Fix **4.4** (wrong status field) — broken organizer filter
5. Fix **3.7** (regex injection) — denial of service vector
6. Fix **2.2 + 2.5** (env load order) — startup reliability
7. Fix **5.4** (whitelist camp update fields) — data integrity
8. Fix **3.3 + 3.4** (unprotected user endpoints) — data privacy
9. Add `start` script, graceful shutdown, response normalization
