from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from functools import wraps
import os
from datetime import datetime, timedelta
from models import db, User, Patient
from flask_migrate import Migrate
from flask_mail import Mail, Message
import secrets
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env file

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///clinic.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

# Initialize database
db.init_app(app)
migrate = Migrate(app, db)

mail = Mail(app)

# Available roles for new users
AVAILABLE_ROLES = ["Doctor", "Nurse", "Intern", "Receptionist", "Pharmacist", "Admin"]

# Tab permissions for each role
TAB_PERMISSIONS = {
    "HPI": ["Doctor", "Nurse", "Admin"],
    "CC": ["Doctor", "Nurse", "Admin", "Intern", "Receptionist", "Pharmacist"],
    "ROS": ["Doctor", "Nurse", "Admin"],
    "PMH": ["Doctor", "Nurse", "Admin"],
    "P/FH": ["Doctor", "Nurse", "Admin"],
    "Vision": ["Doctor", "Admin"],
    "Exam": ["Doctor", "Admin"],
    "Photos/Videos": ["Doctor", "Admin"],
    "E-prescribe": ["Doctor", "Pharmacist", "Admin"],
    "Hand Off": ["Doctor", "Nurse", "Admin"],
    "Manage Users": ["Admin"],
    "Settings": ["Doctor", "Nurse", "Admin", "Intern", "Receptionist", "Pharmacist"]  # Available to all roles
}

# Roles that can view patient information
PATIENT_INFO_ACCESS = ["Doctor", "Admin", "Intern", "Nurse", "Pharmacist"]

# Add this after the TAB_PERMISSIONS dictionary
CUSTOM_TAB_PERMISSIONS = {}

# Add this to your database model
class PasswordReset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in first.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'role' not in session or session['role'] != 'Admin':
            flash('Admin access required.')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            session['username'] = username
            session['role'] = user.role
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            # Set default patient if user has access
            if user.role in PATIENT_INFO_ACCESS:
                first_patient = Patient.query.first()
                if first_patient:
                    session['selected_patient_id'] = first_patient.id
            
            flash(f'Welcome {username}!')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    role = session['role']
    user = User.query.filter_by(username=session['username']).first()
    
    # Get accessible tabs for the current role
    custom_permissions = user.get_custom_permissions() if user else []
    if custom_permissions:
        # Use custom permissions if available
        accessible_tabs = {
            tab: tab in custom_permissions
            for tab in TAB_PERMISSIONS.keys()
        }
    else:
        # Use default role-based permissions
        accessible_tabs = {
            tab: tab in [t for t, roles in TAB_PERMISSIONS.items() if role in roles]
            for tab in TAB_PERMISSIONS.keys()
        }
    
    # Role-specific stats
    role_stats = {
        'Admin': {
            'total_patients': Patient.query.count(),
            'active_cases': Patient.query.filter(Patient.diagnosis.isnot(None)).count(),
            'pending_reviews': Patient.query.filter(Patient.diagnosis.is_(None)).count()
        },
        'Doctor': {
            'patients_today': Patient.query.filter_by(appointment_date=datetime.now().date()).count(),
            'pending_reports': Patient.query.filter(Patient.diagnosis.is_(None)).count(),
            'prescriptions': 8  # This would come from a prescriptions table in a real app
        },
        'Nurse': {
            'assigned_patients': Patient.query.count(),
            'vitals_pending': 3,  # This would come from a vitals table in a real app
            'follow_ups': 4  # This would come from a follow-ups table in a real app
        },
        'Intern': {
            'observed_cases': 10,  # This would come from a cases table in a real app
            'assisted_cases': 5,
            'study_hours': 15
        },
        'Receptionist': {
            'appointments_today': Patient.query.filter_by(appointment_date=datetime.now().date()).count(),
            'check_ins': 15,  # This would come from a check-ins table in a real app
            'pending_calls': 4  # This would come from a calls table in a real app
        },
        'Pharmacist': {
            'prescriptions_pending': 12,  # This would come from a prescriptions table in a real app
            'completed_orders': 35,
            'inventory_alerts': 3
        }
    }

    # Check if user has access to patient information
    can_view_patient_info = role in PATIENT_INFO_ACCESS
    
    # Get current patient data
    current_patient = None
    if can_view_patient_info:
        current_patient = Patient.query.get(session.get('selected_patient_id'))
        if not current_patient:
            current_patient = Patient.query.first()
            if current_patient:
                session['selected_patient_id'] = current_patient.id

    return render_template('dashboard.html',
                         username=session['username'],
                         role=role,
                         tabs=accessible_tabs,
                         stats=role_stats[role],
                         can_view_patient_info=can_view_patient_info,
                         patient_data=current_patient.to_dict() if current_patient else None,
                         all_patients=[p.to_dict() for p in Patient.query.all()] if can_view_patient_info else None,
                         users=[u.to_dict() for u in User.query.all()] if role == 'Admin' else None)

@app.route('/select_patient/<patient_id>')
@login_required
def select_patient(patient_id):
    if session['role'] not in PATIENT_INFO_ACCESS:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403
    
    patient = Patient.query.get(patient_id)
    if patient:
        session['selected_patient_id'] = patient_id
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error', 'message': 'Patient not found'}), 404

@app.route('/admin/users/<int:user_id>/delete', methods=['DELETE'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.role == 'Admin' and User.query.filter_by(role='Admin').count() <= 1:
        return jsonify({'status': 'error', 'message': 'Cannot delete the last admin user'}), 400
    
    db.session.delete(user)
    db.session.commit()
    return jsonify({'status': 'success'})

@app.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        name = request.form.get('name')
        role = request.form.get('role')
        status = request.form.get('status')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not all([name, role, status, email]):
            flash('All fields are required.')
            return redirect(url_for('edit_user', user_id=user_id))
        
        if role not in AVAILABLE_ROLES:
            flash('Invalid role selected.')
            return redirect(url_for('edit_user', user_id=user_id))
        
        # Check if email is being changed and if it's already in use
        if email != user.email and User.query.filter_by(email=email).first():
            flash('Email already exists.')
            return redirect(url_for('edit_user', user_id=user_id))
        
        user.name = name
        user.role = role
        user.status = status
        user.email = email
        
        if password:
            user.set_password(password)
        
        db.session.commit()
        flash(f'User {user.username} has been updated successfully.')
        return redirect(url_for('dashboard'))
    
    return render_template('edit_user.html', user=user, available_roles=AVAILABLE_ROLES)

@app.route('/manage_users', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_users():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')
        name = request.form.get('name')
        email = request.form.get('email')

        if not all([username, password, role, name, email]):
            flash('All fields are required.')
            return redirect(url_for('manage_users'))

        if role not in AVAILABLE_ROLES:
            flash('Invalid role selected.')
            return redirect(url_for('manage_users'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists.')
            return redirect(url_for('manage_users'))

        if User.query.filter_by(email=email).first():
            flash('Email already exists.')
            return redirect(url_for('manage_users'))

        new_user = User(username=username, role=role, name=name, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        flash(f'User {username} with role {role} has been added successfully.')
        return redirect(url_for('manage_users'))

    return render_template('manage_users.html',
                         username=session['username'],
                         role=session['role'],
                         users=User.query.all(),
                         available_roles=AVAILABLE_ROLES)

@app.route('/create_personnel', methods=['GET', 'POST'])
@login_required
@admin_required
def create_personnel():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')
        name = request.form.get('name')
        email = request.form.get('email')
        tab_permissions = request.form.getlist('tab_permissions')

        if not all([username, password, role, name, email]):
            flash('All fields are required.')
            return redirect(url_for('create_personnel'))

        if role not in AVAILABLE_ROLES:
            flash('Invalid role selected.')
            return redirect(url_for('create_personnel'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists.')
            return redirect(url_for('create_personnel'))

        if User.query.filter_by(email=email).first():
            flash('Email already exists.')
            return redirect(url_for('create_personnel'))

        # Create new user with custom permissions
        new_user = User(username=username, role=role, name=name, email=email)
        new_user.set_password(password)
        new_user.set_custom_permissions(tab_permissions)
        db.session.add(new_user)
        db.session.commit()
        
        flash(f'Personnel {username} has been created successfully.')
        return redirect(url_for('dashboard'))

    # Get all available tabs for permissions
    all_tabs = list(TAB_PERMISSIONS.keys())
    
    return render_template('create_personnel.html',
                         username=session['username'],
                         role=session['role'],
                         available_roles=AVAILABLE_ROLES,
                         all_tabs=all_tabs)

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    data = request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    if not current_password or not new_password:
        return jsonify({'status': 'error', 'message': 'Missing required fields'}), 400
    
    user = User.query.filter_by(username=session['username']).first()
    
    if not user or not user.check_password(current_password):
        return jsonify({'status': 'error', 'message': 'Current password is incorrect'}), 401
    
    # Password requirements validation
    if len(new_password) < 8:
        return jsonify({'status': 'error', 'message': 'Password must be at least 8 characters long'}), 400
    
    if not any(c.isupper() for c in new_password):
        return jsonify({'status': 'error', 'message': 'Password must contain at least one uppercase letter'}), 400
    
    if not any(c.isdigit() for c in new_password):
        return jsonify({'status': 'error', 'message': 'Password must contain at least one number'}), 400
    
    if not any(c in '@$!%*?&' for c in new_password):
        return jsonify({'status': 'error', 'message': 'Password must contain at least one special character (@$!%*?&)'}), 400
    
    user.set_password(new_password)
    db.session.commit()
    
    return jsonify({'status': 'success', 'message': 'Password changed successfully'})

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Generate a unique token
            token = secrets.token_urlsafe(32)
            
            # Delete any existing reset tokens for this user
            PasswordReset.query.filter_by(user_id=user.id).delete()
            
            # Create new reset token
            reset_token = PasswordReset(
                user_id=user.id,
                token=token,
                expires_at=datetime.utcnow() + timedelta(hours=1)
            )
            db.session.add(reset_token)
            db.session.commit()
            
            # Create reset password link
            reset_url = url_for('reset_password', token=token, _external=True)
            
            # Send email
            msg = Message('Password Reset Request',
                        recipients=[user.email])
            msg.body = f'''To reset your password, visit the following link:
{reset_url}

If you did not make this request, please ignore this email.

This link will expire in 1 hour.
'''
            mail.send(msg)
            
            flash('Password reset instructions have been sent to your email.', 'success')
            return redirect(url_for('login'))
        
        flash('No account found with that email address.', 'error')
        return redirect(url_for('forgot_password'))
    
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # First check if the token exists and is valid
    reset_token = PasswordReset.query.filter_by(token=token).first()
    
    if not reset_token or reset_token.expires_at < datetime.utcnow():
        flash('The password reset link is invalid or has expired.', 'error')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if new_password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password.html', token=token)
        
        # Password validation
        if not validate_password(new_password):
            flash('Password does not meet requirements.', 'error')
            return render_template('reset_password.html', token=token)
        
        # Update the user's password
        user = User.query.get(reset_token.user_id)
        user.set_password(new_password)
        
        # Delete the used token
        db.session.delete(reset_token)
        db.session.commit()
        
        flash('Your password has been successfully reset. You can now login with your new password.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)

def validate_password(password):
    """
    Validate that the password meets the requirements:
    - At least 8 characters long
    - Contains at least one uppercase letter
    - Contains at least one number
    - Contains at least one special character
    """
    if len(password) < 8:
        return False
    if not any(c.isupper() for c in password):
        return False
    if not any(c.isdigit() for c in password):
        return False
    if not any(c in '!@#$%^&*(),.?":{}|<>' for c in password):
        return False
    return True

# Create database tables and add initial data
def init_db():
    with app.app_context():
        db.create_all()
        
        # Add initial users if none exist
        if User.query.count() == 0:
            initial_users = [
                {"username": "admin1", "password": "adminpass", "role": "Admin", "name": "Admin User", "email": "admin1@eyeclinic.com"},
                {"username": "dr_smith", "password": "docpass", "role": "Doctor", "name": "Dr. Smith", "email": "dr.smith@eyeclinic.com"},
                {"username": "nurse_amy", "password": "nursepass", "role": "Nurse", "name": "Nurse Amy", "email": "nurse.amy@eyeclinic.com"},
                {"username": "intern_john", "password": "internpass", "role": "Intern", "name": "John Intern", "email": "intern.john@eyeclinic.com"},
                {"username": "receptionist1", "password": "recpass", "role": "Receptionist", "name": "Receptionist", "email": "receptionist1@eyeclinic.com"},
                {"username": "pharma1", "password": "pharmapass", "role": "Pharmacist", "name": "Pharmacist", "email": "pharma1@eyeclinic.com"}
            ]
            
            for user_data in initial_users:
                user = User(
                    username=user_data["username"],
                    role=user_data["role"],
                    name=user_data["name"],
                    email=user_data["email"]
                )
                user.set_password(user_data["password"])
                db.session.add(user)
            
            db.session.commit()
        
        # Add initial patients if none exist
        if Patient.query.count() == 0:
            initial_patients = [
                {
                    "id": "EC-2025-001",
                    "name": "John Doe",
                    "age": 42,
                    "gender": "Male",
                    "appointment_date": datetime(2025, 4, 15).date(),
                    "diagnosis": "Glaucoma (under observation)"
                },
                {
                    "id": "EC-2025-002",
                    "name": "Mary Smith",
                    "age": 29,
                    "gender": "Female",
                    "appointment_date": datetime(2025, 4, 13).date(),
                    "diagnosis": "Cataracts"
                },
                {
                    "id": "EC-2025-003",
                    "name": "James Brown",
                    "age": 36,
                    "gender": "Male",
                    "appointment_date": datetime(2025, 4, 14).date(),
                    "diagnosis": "Refractive error (Myopia)"
                },
                {
                    "id": "EC-2025-004",
                    "name": "Angela White",
                    "age": 51,
                    "gender": "Female",
                    "appointment_date": datetime(2025, 4, 16).date(),
                    "diagnosis": "Diabetic Retinopathy"
                },
                {
                    "id": "EC-2025-005",
                    "name": "Carlos Fernandez",
                    "age": 60,
                    "gender": "Male",
                    "appointment_date": datetime(2025, 4, 17).date(),
                    "diagnosis": "Macular Degeneration"
                }
            ]
            
            for patient_data in initial_patients:
                patient = Patient(**patient_data)
                db.session.add(patient)
            
            db.session.commit()

if __name__ == '__main__':
    init_db()
    app.run(debug=True) 
