from app import app, db, User, Patient
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
    print("Database initialized successfully with default users and patients!") 