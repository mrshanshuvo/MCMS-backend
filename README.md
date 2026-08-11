# Medical Camp Management System (Backend)

[![GitHub Repo](https://img.shields.io/badge/repo-MCMS--backend-blue)](https://github.com/mrshanshuvo/MCMS-backend)

## Overview

The **Medical Camp Management System (MCMS)** is a full-stack application built with **Node.js, Express, and MongoDB (Mongoose ODM)**, providing RESTful APIs to manage medical camps, registrations, payments, analytics, and notifications.

---

## Features

- **Authentication & Security**: JWT-based authentication, Firebase Social OAuth verification, bcrypt password hashing, and role-based access control (RBAC).
- **Core Operations**: Camp creation, updating, deletion, text search, multi-field filtering, sorting, and pagination.
- **Analytics & Exports**: Dashboard overview metrics, monthly revenue trends, participant breakdowns, and CSV data exports.
- **Validations & Error Handling**: Server-side Zod payload schemas and centralized error handling middleware.

---

## Tech Stack

- **Backend Framework**: Node.js & Express.js (v5)
- **Database & ODM**: MongoDB with Mongoose (v9)
- **Security & Headers**: Helmet, CORS, Express Rate Limit, bcryptjs, JsonWebToken
- **Validation**: Zod (v4)
- **Logging**: Winston & Morgan

---

## Demo Credentials & Database Seeding

Run the seed script to automatically generate standard and organizer demo accounts:

```bash
npm run seed:users
```

### Demo Accounts:
| Role | Email | Password | Access Rights |
| :--- | :--- | :--- | :--- |
| **Organizer / Admin** | `organizer@carecamp.com` | `Password123!` | Full camp management, analytics, user management |
| **Participant** | `participant@carecamp.com` | `Password123!` | Registrations, payments, feedback |

---

## API Route Quick Reference

### Authentication & Users
- `POST /api/auth/register` — Register user account
- `POST /api/auth/login` — Authenticate and receive JWT token
- `GET /api/users/profile` — Get current user profile
- `PUT /api/users/profile` — Update current user profile
- `GET /api/users` — Admin list all users
- `PATCH /api/users/:id/role` — Update user role
- `DELETE /api/users/:id` — Delete user account

### Camps / Items
- `GET /api/camps` (or `/api/items`) — List camps (search, filter, sort, paginate)
- `GET /api/camps/:id` — Get camp details by ID
- `POST /api/camps` — Create camp (Organizer/Admin only)
- `PUT /api/camps/:campId` — Update camp details (Organizer/Admin only)
- `DELETE /api/camps/:campId` — Delete camp (Organizer/Admin only)

### Analytics & Exports
- `GET /api/analytics/overview` — Dashboard summary metrics
- `GET /api/analytics/charts` — Aggregated chart datasets
- `GET /api/analytics/export/registrations` — Download registrations as CSV
- `GET /api/analytics/export/payments` — Download payments as CSV

### Public & Support
- `POST /api/contact` — Submit contact form message
- `GET /api/successStories` — Public success stories
- `GET /api/faqs` — Public FAQ list
- `GET /api/blogs` — Public blog articles

---

## Setup & Installation

1. **Clone Repository**:
   ```bash
   git clone https://github.com/mrshanshuvo/MCMS-backend.git
   cd MCMS-backend
   ```

2. **Install Dependencies**:
   ```bash
   npm install
   ```

3. **Configure Environment Variables**:
   Copy `.env.example` to `.env` and fill in your MongoDB URI and JWT Secret:
   ```bash
   cp .env.example .env
   ```

4. **Seed Database**:
   ```bash
   npm run seed:users
   ```

5. **Start Development Server**:
   ```bash
   npm start
   ```
