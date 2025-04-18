# Eye Clinic Management System

A web-based management system for eye clinics, featuring role-based access control, patient management, and user administration.

# Features

- Role-based access control (Admin, Doctor, Nurse, Intern, Receptionist, Pharmacist)
- Patient information management
- User administration
- Role-specific dashboards and statistics
- Secure authentication
- Responsive design

# Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd eye-clinic-management
```

2. Create a virtual environment and activate it:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up the environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

5. Initialize the database:
```bash
flask db init
flask db migrate
flask db upgrade
```

## Usage

1. Start the development server:
```bash
flask run
```

2. Access the application at `http://localhost:5000`

3. Login with one of the default accounts:

## Project Structure

```
.
├── app.py              # Main application file
├── models.py           # Database models
├── requirements.txt    # Python dependencies
├── .env               # Environment configuration
├── templates/         # HTML templates
│   ├── dashboard.html
│   ├── edit_user.html
│   ├── login.html
│   └── manage_users.html
└── instance/          # Instance-specific files
    └── clinic.db      # SQLite database
```

## Security Features

- Password hashing using Werkzeug
- Session-based authentication
- Role-based access control
- CSRF protection
- Secure password storage

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

# License

This project is licensed under the MIT License - see the LICENSE file for details. 
