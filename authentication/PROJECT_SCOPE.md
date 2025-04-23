# Eye Clinic Management System

## Project Scope Statement
This document defines the boundaries and deliverables for version 1.0 of the Eye Clinic Management System, focusing exclusively on authentication and user management features.

**Project Overview**  
A secure, role‑based web application that provides authentication, user management, and password security workflows for clinic staff and patients.

**Objectives**  
- Deliver a dependable Login/Logout system with strong password policies.  
- Enforce Role‑Based Access Control for Admin, Doctor, Nurse, Receptionist, and Patient.  
- Enable administrators to manage user accounts (create, modify, delete) with email notifications.  
- Provide a safe and user‑friendly password reset process.

**In‑Scope Features**  
1. **Authentication System**  
   - Login / Logout functionality  
   - Role‑Based Access Control (RBAC)  
   - Password complexity rules and expiration policies  
2. **User Management**  
   - Admin Dashboard for creating, editing, deleting users and role assignment  
   - Email notifications for account creation and changes  
3. **Password Reset**  
   - Secure, token‑based reset flow with email verification  
   - Enforced password strength requirements  
4. **Security Features**  
   - Password hashing (bcrypt)  
   - Session management with secure cookies and timeouts  
   - CSRF protection on all forms

**Out‑of‑Scope Features**  
- Appointment scheduling and calendar integration  
- Patient record creation, editing, or history tracking  
- Prescription creation and pharmacy workflows  
- Billing, payments, and insurance handling  
- Mobile‑specific interfaces (web only)

**Deliverables**  
- Fully functional Authentication & User Management module  
- Automated tests covering core authentication and user‑management flows  
- Deployment pipeline configuration (Render setup)  
- User guide for Admins and end users  
- Technical documentation: architecture overview and API reference

**Constraints & Assumptions**  
- Built with Flask and SQLAlchemy (SQLite for PoC, PostgreSQL in production)  
- Hosted on Render, environment configuration via `.env`  
- Email delivered via Gmail SMTP with App Passwords  
- Target user base ≤50 concurrent sessions  
- Supported browsers: latest Chrome, Firefox, Edge, Safari

**Timeline (High‑Level)**  
| Phase                            | Duration |
|----------------------------------|----------|
| Requirements & Design            | 1 week   |
| Authentication & RBAC            | 1 week   |
| Admin User Management            | 1 week   |
| Password Reset & Security        | 1 week   |
| Testing, Documentation & Deployment | 1 week |

---

## Getting Started

### Prerequisites
- Python 3.8+  
- PostgreSQL or SQLite (for development)

### Installation
1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/eye-clinic-auth.git
   cd eye-clinic-auth/authentication
