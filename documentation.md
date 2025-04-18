# Eye Clinic Management System Documentation

## 1. Project Overview

The Eye Clinic Management System is a comprehensive web application designed to streamline the operations of an eye clinic. It provides role-based access control to ensure that different staff members have appropriate access to various features based on their responsibilities. The system manages patient information, medical records, prescriptions, and administrative tasks in a secure and efficient manner.

## 2. Tech Stack

- **Backend**: Python 3.x
- **Web Framework**: Flask
- **Frontend**: HTML, CSS, JavaScript
- **Database**: SQLite
- **Version Control**: Git + GitHub
- **Authentication**: Flask session-based authentication

## 3. User Roles and Access

The system implements role-based access control with the following roles:

| Role | Description | Access Level |
|------|-------------|--------------|
| Admin | System administrator | Full access to all features including user management |
| Doctor | Medical practitioner | Access to patient records, diagnosis, prescriptions, and medical procedures |
| Nurse | Healthcare provider | Access to patient vitals, basic records, and assistance features |
| Intern | Medical trainee | Limited access to patient records for learning purposes |
| Receptionist | Front desk staff | Access to patient scheduling and basic information |
| Pharmacist | Medication specialist | Access to prescription management and medication records |

### Tab Access Permissions

| Tab | Accessible By |
|-----|--------------|
| HPI (History of Present Illness) | Doctor, Nurse, Admin |
| CC (Chief Complaint) | Doctor, Nurse, Admin, Intern, Receptionist, Pharmacist |
| ROS (Review of Systems) | Doctor, Nurse, Admin |
| PMH (Past Medical History) | Doctor, Nurse, Admin |
| P/FH (Past/Family History) | Doctor, Nurse, Admin |
| Vision | Doctor, Admin |
| Exam | Doctor, Admin |
| Photos/Videos | Doctor, Admin |
| E-prescribe | Doctor, Pharmacist, Admin |
| Hand Off | Doctor, Nurse, Admin |
| Manage Users | Admin only |

## 4. System Features

### Authentication
- Secure login system with password hashing
- Session management for authenticated users
- Role-based access control

### Patient Management
- Patient selection interface
- Patient information sidebar with key details
- Comprehensive patient records

### Clinical Features
- **HPI**: Record and view patient's history of present illness
- **CC**: Document chief complaints
- **ROS**: Comprehensive review of systems
- **PMH**: Past medical history documentation
- **P/FH**: Family and personal medical history
- **Vision**: Vision assessment tools and records
- **Exam**: Clinical examination documentation
- **Photos/Videos**: Medical imaging storage and viewing
- **E-prescribe**: Electronic prescription management
- **Hand Off**: Patient handoff documentation between providers

### Administrative Features
- User management (Admin only)
- Create, edit, and delete personnel accounts
- Assign custom tab permissions to users
- View system statistics and usage

## 5. How to Run the App

### Prerequisites
- Python 3.x
- pip (Python package manager)
- Git

### Setup Instructions

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/eye-clinic-management.git
   cd eye-clinic-management/authentication
   ```

2. **Set up a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application**
   ```bash
   python app.py
   ```

5. **Access the application**
   Open your web browser and navigate to `http://127.0.0.1:5000`

## 6. Contributing

### Development Workflow

1. **Fork the repository** on GitHub
2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes** and commit them with descriptive messages
   ```bash
   git commit -m "Add feature: description of changes"
   ```
4. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```
5. **Create a pull request** from your fork to the main repository

### Coding Guidelines

- Follow PEP 8 style guide for Python code
- Use meaningful variable and function names
- Add comments for complex logic
- Write unit tests for new features
- Keep commits focused and atomic

## 7. Sample Data

The system comes pre-populated with sample data for testing:

### Test User Accounts

| Username | Password | Role |
|----------|----------|------|
| admin1 | adminpass | Admin |
| dr_smith | docpass | Doctor |
| nurse_amy | nursepass | Nurse |
| intern_john | internpass | Intern |
| receptionist1 | recpass | Receptionist |
| pharma1 | pharmapass | Pharmacist |

### Sample Patients

The system includes sample patient records with the following information:
- Patient ID
- Name
- Age
- Gender
- Appointment date
- Diagnosis

## 8. Future Improvements

### Planned Features

1. **Appointment Calendar**
   - Schedule management
   - Reminder notifications
   - Conflict detection

2. **Billing System**
   - Insurance processing
   - Payment tracking
   - Invoice generation

3. **Reporting Dashboard**
   - Patient statistics
   - Financial reports
   - Staff performance metrics

4. **Mobile Application**
   - Cross-platform access
   - Push notifications
   - Offline capabilities

5. **Integration with External Systems**
   - Electronic Health Records (EHR)
   - Laboratory Information Systems
   - Imaging systems

6. **Advanced Analytics**
   - Patient outcome tracking
   - Treatment effectiveness analysis
   - Predictive analytics for patient care

---

*This documentation is maintained by the Eye Clinic Management System development team. For questions or support, please contact the system administrator.* 