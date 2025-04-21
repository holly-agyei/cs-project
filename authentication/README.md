# Eye Clinic Management System

A comprehensive web-based management system for eye clinics, featuring role-based access control, patient management, and secure authentication.

## Features

- 🔐 Secure Authentication System
- 👥 Role-Based Access Control
- 👨‍⚕️ Multiple User Roles (Admin, Doctor, Nurse, Intern, Receptionist, Pharmacist)
- 🏥 Patient Management
- 📊 Role-Specific Dashboards
- 🔑 Password Reset Functionality
- 📱 Responsive Design

## Tech Stack

- Python 3.9
- Flask 2.0.1
- SQLAlchemy
- SQLite Database
- HTML5/CSS3
- JavaScript
- Font Awesome Icons

## Prerequisites

- Python 3.9 or higher
- pip (Python package manager)
- Virtual environment (recommended)

## Local Development Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd authentication
```

2. Create and activate a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
Create a `.env` file in the project root with:
```
MAIL_SERVER=your-smtp-server
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email
MAIL_PASSWORD=your-email-password
MAIL_DEFAULT_SENDER=your-email
```

5. Run the application:
```bash
python app.py
```

The application will be available at `http://localhost:10000`

## Deployment on Render

1. Create a new Web Service on Render
2. Connect your repository
3. Use the following settings:
   - Environment: Python
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `gunicorn app:app --bind 0.0.0.0:$PORT`
   - Environment Variables:
     ```
     PYTHON_VERSION=3.9.0
     PORT=10000
     FLASK_ENV=production
     ```

## Default Users

The system comes with pre-configured users for testing:

| Username      | Password    | Role         |
|--------------|-------------|--------------|
| admin1       | adminpass   | Admin        |
| dr_smith     | docpass     | Doctor       |
| nurse_amy    | nursepass   | Nurse        |
| intern_john  | internpass  | Intern       |
| receptionist1| recpass     | Receptionist |
| pharma1      | pharmapass  | Pharmacist   |

## Role-Based Access

Different roles have access to different functionalities:

- **Admin**: Full system access, user management
- **Doctor**: Patient records, prescriptions, examinations
- **Nurse**: Patient vitals, basic records
- **Intern**: Limited patient information, learning resources
- **Receptionist**: Appointments, patient registration
- **Pharmacist**: Prescriptions, medication management

## Security Features

- Password hashing using Werkzeug
- Session-based authentication
- Password reset via email
- Password complexity requirements:
  - Minimum 8 characters
  - At least one uppercase letter
  - At least one number
  - At least one special character

## API Endpoints

### Authentication
- `POST /login`: User login
- `GET /logout`: User logout
- `POST /forgot-password`: Request password reset
- `POST /reset-password/<token>`: Reset password

### User Management
- `POST /manage_users`: Create new user (Admin only)
- `POST /create_personnel`: Create new personnel (Admin only)
- `DELETE /admin/users/<user_id>/delete`: Delete user (Admin only)
- `POST /admin/users/<user_id>/edit`: Edit user (Admin only)

### Patient Management
- `POST /select_patient/<patient_id>`: Select patient for viewing
- Additional endpoints for patient data management

## Database Schema

The application uses SQLite with the following main tables:
- Users
- Patients
- PasswordReset

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License. 
