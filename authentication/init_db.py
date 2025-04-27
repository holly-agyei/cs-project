from app import app, db, User, Patient, PatientView
from datetime import datetime

with app.app_context():
    db.drop_all()
    db.create_all()
    
    # Create initial users
    initial_users = [
        {
            "username": "admin1",
            "password": "adminpass",
            "role": "Admin",
            "name": "Admin User",
            "email": "admin1@eyeclinic.com"
        },
        {
            "username": "dr_smith",
            "password": "docpass",
            "role": "Doctor",
            "name": "Dr. Smith",
            "email": "dr.smith@eyeclinic.com"
        },
        {
            "username": "nurse_amy",
            "password": "nursepass",
            "role": "Nurse",
            "name": "Nurse Amy",
            "email": "nurse.amy@eyeclinic.com"
        }
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

    # Create initial patients
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
    
    # Add some initial patient views
    admin = User.query.filter_by(username="admin1").first()
    nurse = User.query.filter_by(username="nurse_amy").first()
    doctor = User.query.filter_by(username="dr_smith").first()
    
    initial_views = [
        {
            "patient_id": "EC-2025-001",
            "user_id": doctor.id,
            "viewed_at": datetime(2025, 4, 15, 10, 30)
        },
        {
            "patient_id": "EC-2025-002",
            "user_id": nurse.id,
            "viewed_at": datetime(2025, 4, 13, 14, 15)
        }
    ]
    
    for view_data in initial_views:
        view = PatientView(**view_data)
        db.session.add(view)
    
    db.session.commit()
    print("Database initialized successfully with default users, patients, and patient views!") 