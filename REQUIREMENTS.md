# Project Requirements - Backend (API & Database)

## 1. Technical Stack & Architecture

- **Framework**: Express.js
- **Database & ORM/ODM**: MongoDB with Mongoose (or PostgreSQL/MySQL with Prisma).
- **Architecture Pattern**: Basic modular structure:
  - `server/` or `src/` root
  - `routes/`: API endpoint definitions
  - `controllers/`: Request handling & business logic
  - `middleware/`: Auth, validation, error handling, CORS
  - `config/`: Database connections & environment configurations
- **API Standards**: RESTful route design, proper HTTP status codes (200, 201, 400, 401, 403, 404, 500), centralized error handling middleware.

## 2. Authentication & Authorization

- **Authentication**: JWT (JSON Web Token) based authentication header verification.
- **Social Login Backend Integration**: Verification for Google/Facebook OAuth tokens or sessions.
- **Security & Encryption**:
  - Password hashing using `bcrypt` / `bcryptjs`.
  - Role-Based Access Control (RBAC) middleware supporting roles like `User`, `Admin`, and `Manager`.
- **CORS Configuration**: Configured CORS middleware allowing request origins from the web client.

## 3. Database Schema & Data Models

- **Schema Planning**: Well-structured schemas for Users, Items/Camps, Registrations/Orders, Reviews, and Categories.
- **Data Relationships**: Define proper references/populates or relational foreign key associations between models (e.g., User to Bookings, Admin to Created Items).

## 4. Endpoints & Features Required

### Authentication & User Management

- `POST /api/auth/register`: User registration with server-side validation and password hashing.
- `POST /api/auth/login`: User login returning JWT token and user profile role info.
- `GET /api/users/profile`: Get current logged-in user profile.
- `PUT /api/users/profile`: Update user profile details.
- Admin Endpoints: Manage, list, update user roles or accounts (`GET /api/users`, `PATCH /api/users/:id/role`, `DELETE /api/users/:id`).

### Core Listing / Explore & Search Endpoints

- `GET /api/items`: List all items/camps with support for:
  - Multi-field filtering (min 2 fields: e.g., category, price range, rating, location, date).
  - Sorting options (e.g., price, creation date, popularity).
  - Pagination parameters (`page`, `limit`).
- `GET /api/items/:id`: Get detailed single item/camp information.
- `POST /api/items`: Create item/camp (Admin / Manager only).
- `PUT /api/items/:id`: Edit item/camp (Admin / Manager only).
- `DELETE /api/items/:id`: Delete item/camp (Admin / Manager only).

### Dashboard & Analytics Endpoints

- Analytics aggregation routes providing dynamic real data for dashboard charts:
  - `GET /api/analytics/overview`: Summary metrics (Total Users, Total Items/Camps, Revenue/Fees, Registrations).
  - `GET /api/analytics/charts`: Aggregated dataset for Bar, Line, and Pie charts.

### Form Handling & Server-Side Validation

- Server-side validation for all incoming POST/PUT payloads (using `express-validator`, `joi`, or custom middleware):
  - Login payload validation
  - Registration payload validation
  - Contact message submission
  - Item creation/editing payload validation
  - Profile update payload validation

## 5. Security & Robustness

- Sanitize input fields to prevent injection attacks.
- Centralized error handling middleware returning standardized error responses `{ success: false, message: "..." }`.
- Environment variable configuration (`.env`) for DB connection strings, JWT secret keys, and server port.

## 6. Code Quality Rules

- Clean, organized, and modular folder structure.
- Environment variables used for all sensitive configuration.
- No `console.log` statements in production code.
- Meaningful commit messages.

## 7. Submission Checklist Data Support

- API documentation or route reference to support deployment URLs.
- Admin and standard user demo credential support in seed script or database setup.
