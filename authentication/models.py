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

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'age': self.age,
            'gender': self.gender,
            'appointment_date': self.appointment_date.isoformat() if self.appointment_date else None,
            'diagnosis': self.diagnosis,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        } 