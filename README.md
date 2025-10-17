# Medical Camp Management System (Backend)

[![GitHub Repo](https://img.shields.io/badge/repo-MCMS--backend-blue)](https://github.com/mrshanshuvo/MCMS-backend)

## Overview
The **Medical Camp Management System (MCMS)** is a full-stack application to manage medical camps efficiently.  
This repository contains the **backend server** built with **Node.js, Express, and MongoDB**, providing RESTful APIs to handle organizers, participants, schedules, and notifications.

The backend works seamlessly with the [MCMS web client](https://github.com/mrshanshuvo/MCMS-web-client).

---

## Features

- User authentication and authorization (JWT-based)
- CRUD operations for organizers, participants, and camps
- Search, filter, and pagination for participants and camps
- Notifications for participants about upcoming camps
- Secure data storage using MongoDB
- RESTful API endpoints for frontend consumption

---

## Tech Stack

- **Backend:** Node.js, Express.js  
- **Database:** MongoDB (Mongoose)  
- **Authentication:** JWT (JSON Web Tokens)  
- **Environment Management:** dotenv  
- **Other:** Nodemon for development, bcrypt for password hashing

---

## Setup & Installation

1. **Clone the repo**
```bash
git clone https://github.com/mrshanshuvo/MCMS-backend.git
cd MCMS-backend
