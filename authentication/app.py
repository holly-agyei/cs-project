from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from functools import wraps
import os
from datetime import datetime, timedelta, timezone
from models import db, User, Patient, PatientView, HandOff
from flask_migrate import Migrate
from flask_mail import Mail, Message
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from sqlalchemy import or_
import pytz

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

# Add this after the AVAILABLE_ROLES list
CUSTOM_ROLES = {}  # This will store custom roles and their permissions

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
    "Hand Off": ["Doctor", "Nurse", "Admin", "Intern", "Receptionist", "Pharmacist"],  # All roles have access
    "Manage Users": ["Admin"],
    "Settings": ["Doctor", "Nurse", "Admin", "Intern", "Receptionist", "Pharmacist"]  # Available to all roles
}

# Roles that can view patient information
PATIENT_INFO_ACCESS = ["Doctor", "Admin", "Intern", "Nurse", "Pharmacist", "Receptionist"]

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
    
    # Initialize accessible_tabs dictionary
    accessible_tabs = {}
    
    if custom_permissions:
        # Use custom permissions if available
        for tab in TAB_PERMISSIONS.keys():
            accessible_tabs[tab] = tab in custom_permissions
    else:
        # Use default role-based permissions
        for tab in TAB_PERMISSIONS.keys():
            accessible_tabs[tab] = role in TAB_PERMISSIONS[tab]
    
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

    # Get all users for handoff functionality
    all_users = User.query.all()

    # Get received handoffs
    received_handoffs = HandOff.query.filter_by(
        to_user_id=user.id,
        is_acknowledged=False
    ).order_by(HandOff.created_at.desc()).all()

    return render_template('dashboard.html',
                         username=session['username'],
                         name=user.name,
                         role=role,
                         current_user=user,
                         tabs=accessible_tabs,
                         stats=role_stats[role],
                         can_view_patient_info=can_view_patient_info,
                         patient_data=current_patient.to_dict() if current_patient else None,
                         all_patients=[p.to_dict() for p in Patient.query.all()] if can_view_patient_info else None,
                         users=[u.to_dict() for u in all_users],
                         received_handoffs=[h.to_dict() for h in received_handoffs])

@app.route('/select_patient/<patient_id>')
@login_required
def select_patient(patient_id):
    if session['role'] not in PATIENT_INFO_ACCESS:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403
    
    patient = Patient.query.get(patient_id)
    if patient:
        session['selected_patient_id'] = patient_id
        
        # Create a new patient view record
        current_user = User.query.filter_by(username=session['username']).first()
        patient_view = PatientView(
            patient_id=patient_id,
            user_id=current_user.id
        )
        db.session.add(patient_view)
        db.session.commit()
        
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

@app.route('/admin/roles/create', methods=['POST'])
@login_required
@admin_required
def create_role():
    try:
        data = request.get_json()
        role_name = data.get('role_name')
        permissions = data.get('permissions', [])
        
        # Validate role name
        if not role_name:
            return jsonify({'success': False, 'error': 'Role name is required'}), 400
            
        # Check if role already exists
        if role_name in AVAILABLE_ROLES or role_name in CUSTOM_ROLES:
            return jsonify({'success': False, 'error': 'Role already exists'}), 400
            
        # Validate role name format (alphanumeric and spaces only)
        if not all(c.isalnum() or c.isspace() for c in role_name):
            return jsonify({'success': False, 'error': 'Role name can only contain letters, numbers, and spaces'}), 400
            
        # Store new role and its permissions
        CUSTOM_ROLES[role_name] = permissions
        
        # Add to available roles
        AVAILABLE_ROLES.append(role_name)
        
        return jsonify({
            'success': True,
            'message': f'Role {role_name} created successfully',
            'role': {
                'name': role_name,
                'permissions': permissions
            }
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

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

        # Check if role is valid (either in AVAILABLE_ROLES or CUSTOM_ROLES)
        if role not in AVAILABLE_ROLES and role not in CUSTOM_ROLES:
            flash('Invalid role selected.')
            return redirect(url_for('create_personnel'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists.')
            return redirect(url_for('create_personnel'))

        if User.query.filter_by(email=email).first():
            flash('Email already exists.')
            return redirect(url_for('create_personnel'))

        # Create new user
        new_user = User(username=username, role=role, name=name, email=email)
        new_user.set_password(password)
        
        # Set permissions based on role type
        if role in CUSTOM_ROLES:
            new_user.set_custom_permissions(CUSTOM_ROLES[role])
        else:
            new_user.set_custom_permissions(tab_permissions)
            
        db.session.add(new_user)
        db.session.commit()
        
        flash(f'Personnel {username} has been created successfully.')
        return redirect(url_for('dashboard'))

    # Get all available tabs for permissions
    all_tabs = list(TAB_PERMISSIONS.keys())
    
    # Combine default and custom roles
    all_roles = AVAILABLE_ROLES + list(CUSTOM_ROLES.keys())
    
    return render_template('create_personnel.html',
                         username=session['username'],
                         role=session['role'],
                         available_roles=all_roles,
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
    if not any(c in '@$!%*?&' for c in password):
        return False
    return True

@app.route('/handoff', methods=['POST'])
@login_required
def handoff():
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['to_user_id', 'patient_name', 'care_instructions']
    if not all(field in data and data[field] for field in required_fields):
        return jsonify({'status': 'error', 'message': 'Missing required fields'}), 400
    
    # Get the target user
    target_user = User.query.get(data['to_user_id'])
    if not target_user or target_user.username == session['username']:
        return jsonify({'status': 'error', 'message': 'Invalid target user'}), 400
    
    try:
        # Create new handoff record
        handoff = HandOff(
            from_user_id=User.query.filter_by(username=session['username']).first().id,
            to_user_id=target_user.id,
            patient_name=data['patient_name'],
            care_instructions=data['care_instructions'],
            medications=data.get('medications', ''),
            pending_tasks=data.get('pending_tasks', ''),
            critical_alerts=','.join(data.get('alerts', []))
        )
        
        db.session.add(handoff)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': f'Patient successfully handed off to {target_user.name}'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/acknowledge_handoff/<int:handoff_id>', methods=['POST'])
@login_required
def acknowledge_handoff(handoff_id):
    try:
        handoff = HandOff.query.get_or_404(handoff_id)
        
        # Get current user
        current_user = User.query.filter_by(username=session['username']).first()
        if not current_user:
            return jsonify({'status': 'error', 'message': 'Current user not found'}), 404
        
        # Verify the handoff is for the current user
        if handoff.to_user_id != current_user.id:
            return jsonify({'status': 'error', 'message': 'Unauthorized to acknowledge this handoff'}), 403
            
        # Mark the handoff as acknowledged
        handoff.is_acknowledged = True
        handoff.acknowledged_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({'status': 'success', 'message': 'Handoff acknowledged successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/create_handoff', methods=['POST'])
@login_required
def create_handoff():
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['to_user_id', 'patient_name', 'care_instructions']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Get current user
        current_user = User.query.filter_by(username=session['username']).first()
        if not current_user:
            return jsonify({'error': 'Current user not found'}), 404

        # Create new handoff
        handoff = HandOff(
            from_user_id=current_user.id,
            to_user_id=data['to_user_id'],
            patient_name=data['patient_name'],
            care_instructions=data['care_instructions'],
            medications=data.get('medications', ''),
            pending_tasks=data.get('pending_tasks', ''),
            critical_alerts=data.get('critical_alerts', ''),
            is_acknowledged=False,
            created_at=datetime.utcnow()
        )
        
        db.session.add(handoff)
        db.session.commit()
        
        return jsonify({
            'message': 'Handoff created successfully',
            'handoff_id': handoff.id
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/archive_handoff/<int:handoff_id>', methods=['POST'])
@login_required
def archive_handoff(handoff_id):
    try:
        handoff = HandOff.query.get_or_404(handoff_id)
        
        # Verify the handoff is for the current user
        current_user = User.query.filter_by(username=session['username']).first()
        if handoff.to_user_id != current_user.id:
            return jsonify({'success': False, 'error': 'Unauthorized to archive this handoff'}), 403
            
        # Only allow archiving of acknowledged handoffs
        if not handoff.is_acknowledged:
            return jsonify({'success': False, 'error': 'Handoff must be acknowledged before archiving'}), 400
            
        # Archive the handoff
        handoff.is_archived = True
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Handoff archived successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/get_handoffs', methods=['GET'])
@login_required
def get_handoffs():
    try:
        # Get current user
        current_user = User.query.filter_by(username=session['username']).first()
        if not current_user:
            return jsonify({'error': 'Current user not found'}), 404

        # Get query parameters
        filter_type = request.args.get('type', 'all')  # all, sent, received
        include_acknowledged = request.args.get('include_acknowledged', 'false').lower() == 'true'
        show_archived = request.args.get('show_archived', 'false').lower() == 'true'
        
        # Base query
        query = HandOff.query
        
        # Apply filters
        if filter_type == 'sent':
            query = query.filter_by(from_user_id=current_user.id)
        elif filter_type == 'received':
            query = query.filter_by(to_user_id=current_user.id)
        else:  # 'all'
            query = query.filter(or_(
                HandOff.from_user_id == current_user.id,
                HandOff.to_user_id == current_user.id
            ))
        
        # Filter acknowledged status if specified
        if not include_acknowledged:
            query = query.filter_by(is_acknowledged=False)
            
        # Filter archived status
        if not show_archived:
            query = query.filter_by(is_archived=False)
            
        # Order by creation date, newest first
        handoffs = query.order_by(HandOff.created_at.desc()).all()
        
        # Format handoffs for response
        formatted_handoffs = []
        for handoff in handoffs:
            from_user = User.query.get(handoff.from_user_id)
            to_user = User.query.get(handoff.to_user_id)
            
            handoff_dict = handoff.to_dict()
            handoff_dict['is_receiver'] = handoff.to_user_id == current_user.id
            
            formatted_handoffs.append(handoff_dict)
        
        return jsonify({'handoffs': formatted_handoffs}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/get_users', methods=['GET'])
@login_required
def get_users():
    try:
        # Get current user
        current_user = User.query.filter_by(username=session['username']).first()
        if not current_user:
            return jsonify({'error': 'Current user not found'}), 404

        # Get all users except the current user
        users = User.query.filter(User.id != current_user.id).all()
        
        # Format users for response
        formatted_users = [{
            'id': user.id,
            'name': user.name,
            'username': user.username,
            'role': user.role
        } for user in users]
        
        return jsonify({'users': formatted_users}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Create database tables and add initial data
def init_db():
    with app.app_context():
        # Drop all tables and recreate them
        db.drop_all()
        db.create_all()
        
        # Add initial users if none exist
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
        
        # Add initial patients
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

# Add datetime filter
@app.template_filter('datetime')
def format_datetime(value):
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace('Z', '+00:00'))
    
    # Convert to Central Time
    central = pytz.timezone('America/Chicago')
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    central_time = value.astimezone(central)
    
    return central_time.strftime('%B %d, %Y at %I:%M %p CT')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8084))
    app.run(host='0.0.0.0', port=port, debug=False)
    #done
