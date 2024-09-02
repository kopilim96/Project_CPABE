import os
import django

# Set up Django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "myproject.settings")
django.setup()

from django.db import connection
from django.contrib.auth.hashers import make_password

def insert_user(username, password, ca_approve, is_admin, is_ca, is_doctor, is_patient):
    hashed_password = make_password(password)
    with connection.cursor() as cursor:
        cursor.execute('''
        INSERT OR REPLACE INTO users 
        (username, password, ca_approve, is_admin, is_ca, is_doctor, is_patient)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        ''', [username, hashed_password, ca_approve, is_admin, is_ca, is_doctor, is_patient])
    print("User {0} inserted or updated".format(username))

# Insert sample users
insert_user('admin', '123', 1, 1, 0, 0, 0)
insert_user('doctor1', '123', 0, 0, 0, 1, 0)
insert_user('patient1', '123', 0, 0, 0, 0, 1)
insert_user('ca1', '123', 1, 0, 1, 0, 0)

print("Users have been created with hashed passwords.")