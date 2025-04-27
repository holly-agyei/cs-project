from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(80), nullable=False)
    name = db.Column(db.String(120))
    status = db.Column(db.String(20), default='active')
    last_login = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    custom_permissions = db.Column(db.String(500))  # Store tab permissions as comma-separated string
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def set_custom_permissions(self, permissions):
        if isinstance(permissions, list):
            self.custom_permissions = ','.join(permissions)
        else:
            self.custom_permissions = permissions

    def get_custom_permissions(self):
        if self.custom_permissions:
            return self.custom_permissions.split(',')
        return []

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'role': self.role,
            'name': self.name,
            'status': self.status,
            'last_login': self.last_login.strftime('%Y-%m-%dT%H:%M:%S.%f') if self.last_login else None,
            'custom_permissions': self.get_custom_permissions(),
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class Patient(db.Model):
    id = db.Column(db.String(20), primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer)
    gender = db.Column(db.String(10))
    appointment_date = db.Column(db.Date)
    diagnosis = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Add relationship to PatientView
    views = db.relationship('PatientView', backref='patient', lazy='dynamic', order_by='PatientView.viewed_at.desc()')

    def to_dict(self):
        # Get all views, ordered by most recent first
        all_views = [view.to_dict() for view in self.views.all()]
        
        return {
            'id': self.id,
            'name': self.name,
            'age': self.age,
            'gender': self.gender,
            'appointment_date': self.appointment_date.isoformat() if self.appointment_date else None,
            'diagnosis': self.diagnosis,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'views': all_views,
            'last_view': all_views[0] if all_views else None
        }

class PatientView(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.String(20), db.ForeignKey('patient.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    viewed_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Add relationship to User
    user = db.relationship('User', backref='patient_views')
    
    def to_dict(self):
        return {
            'id': self.id,
            'patient_id': self.patient_id,
            'user_id': self.user_id,
            'user_name': self.user.name,
            'user_role': self.user.role,
            'viewed_at': self.viewed_at.isoformat() if self.viewed_at else None
        }

class HandOff(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    from_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    to_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    patient_name = db.Column(db.String(100), nullable=False)
    care_instructions = db.Column(db.Text, nullable=False)
    medications = db.Column(db.Text)
    pending_tasks = db.Column(db.Text)
    critical_alerts = db.Column(db.Text)
    is_acknowledged = db.Column(db.Boolean, default=False)
    is_archived = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    acknowledged_at = db.Column(db.DateTime)
    
    # Relationships
    from_user = db.relationship('User', foreign_keys=[from_user_id], backref='handoffs_sent')
    to_user = db.relationship('User', foreign_keys=[to_user_id], backref='handoffs_received')

    def to_dict(self):
        from_user = User.query.get(self.from_user_id)
        to_user = User.query.get(self.to_user_id)
        return {
            'id': self.id,
            'from_user_id': self.from_user_id,
            'to_user_id': self.to_user_id,
            'from_user_name': from_user.name if from_user else 'Unknown',
            'to_user_name': to_user.name if to_user else 'Unknown',
            'patient_name': self.patient_name,
            'care_instructions': self.care_instructions,
            'medications': self.medications,
            'pending_tasks': self.pending_tasks,
            'critical_alerts': self.critical_alerts,
            'is_acknowledged': self.is_acknowledged,
            'is_archived': self.is_archived,
            'created_at': self.created_at.isoformat(),
            'acknowledged_at': self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            'is_receiver': True  # This will be modified by the route handler
        } 