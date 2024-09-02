# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.utils import timezone
from django.conf import settings
from django.core.mail import send_mail, EmailMessage
from django.shortcuts import render, redirect, get_object_or_404, HttpResponse
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib.auth.decorators import login_required
from django.core.files.storage import FileSystemStorage
from .forms import UserLoginForm, RegisterForm, FileUploadForm
from .models import User, UserKey, Specialist
from datetime import datetime
import subprocess
import os


# OpenAbe path
OABE_SETUP = './libopenabe/cli/cli/oabe_setup'
OABE_ENC = './libopenabe/cli/cli/oabe_enc'
OABE_KEYGEN = './libopenabe/cli/cli/oabe_keygen'

User = get_user_model()

# Login Function
def user_login(request):
    if request.method == 'POST':
        form = UserLoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user_type = form.cleaned_data['user_type']

            print("Attempting to authenticate user:", username)
            print("User type selected:", user_type)
            print("Password entered:", password)  # Be cautious with this in production!

            # Check if the user exists in the database
            try:
                user_obj = User.objects.get(username=username)
                print("User found in database:", user_obj)
                print("Stored password hash:", user_obj.password)
            except User.DoesNotExist:
                print("User not found in database")
                user_obj = None

            user = authenticate(username=username, password=password)

            if user is not None:
                print("User authenticated successfully:", user)
                login(request, user)
                print("User logged in:", request.user.is_authenticated())
                
                if user_type == 'Admin' and user.is_admin:
                    print("Redirecting to admin_page")
                    return redirect('admin_page')
                elif user_type == 'CA' and user.is_ca:
                    print("Redirecting to ca_page")
                    return redirect('ca_page')
                elif user_type == 'Doctor' and user.is_doctor:
                    print("Redirecting to doctor_page")
                    return redirect('doctor_page')
                elif user_type == 'Patient' and user.is_patient:
                    print("Redirecting to patient_page")
                    return redirect('patient_page')
                else:
                    print("Invalid user type for authenticated user:", user_type)
                    return render(request, 'myapp/login.html', {'form': form, 'error': 'Invalid user type.'})
            else:
                print("Authentication failed for username:", username)
                return render(request, 'myapp/login.html', {'form': form, 'error': 'Invalid username or password.'})
        else:
            print("Form validation failed. Errors:", form.errors)
    else:
        form = UserLoginForm()
    return render(request, 'myapp/login.html', {'form': form})

# ------------------- Admin ------------------------
@login_required
def admin_page(request):
    if not request.user.is_admin:
        return redirect('login')
    return render(request, 'myapp/admin_page.html')

@login_required
def create_user(request):
    if not request.user.is_admin:
        return redirect('login')

    if request.method == 'POST':
        print("POST request received")
        form = RegisterForm(request.POST)
        if form.is_valid():
            print("Form is valid")
            user = form.save(commit=False)
            user.is_admin = False
            user.is_ca = False
            user.set_password(form.cleaned_data['password'])
            user_type = form.cleaned_data['user_type']

            # Determine if the user is a doctor or patient
            if user_type == 'Doctor':
                user.is_doctor = True
                user.is_patient = False
            else:
                user.is_doctor = False
                user.is_patient = True

            user.save()
            print("User created successfully")

            # Save the specialist information if the user is a doctor
            specialist = form.cleaned_data.get('specialist')
            if user.is_doctor and specialist:
                Specialist.objects.create(user=user, specialist=specialist)
                print("Specialist added to table")

            return redirect('admin_page')
        else:
            print("Form is invalid")
            print(form.errors)
    else:
        form = RegisterForm()

    return render(request, 'myapp/create_user.html', {'form': form})

# ---------------- End of Admin ----------------------- 

# ----------------- CA ----------------------
@login_required
def ca_page(request):
    if not request.user.is_ca:
        return redirect('login')
    
    unapproved_users = User.objects.filter(ca_approve=0)
    approved_users = User.objects.filter(ca_approve=1)
    
    return render(request, 'myapp/ca_page.html', {
        'unapproved_users': unapproved_users,
        'approved_users': approved_users
    })

@login_required
def approve_user(request, user_id, action):
    if not request.user.is_ca:
        messages.error(request, "You don't have permission to perform this action.")
        return redirect('login')

    user = get_object_or_404(User, id=user_id)

    if action == 'approve':
        user.ca_approve = 1
        user.save()

        # Create user-specific directory and filenames using the username
        user_dir = os.path.join(settings.MEDIA_ROOT, 'certs', user.username)
        if not os.path.exists(user_dir):
            os.makedirs(user_dir)

        private_key_path = os.path.join(user_dir, '{}_private_key.pem'.format(user.username))
        public_key_path = os.path.join(user_dir, '{}_public_key.pem'.format(user.username))
        csr_path = os.path.join(user_dir, '{}_request.csr'.format(user.username))
        cert_path = os.path.join(user_dir, '{}_certificate.crt'.format(user.username))

        try:
            # Generate the private key
            subprocess.check_call([
                'openssl', 'genpkey', '-algorithm', 'RSA',
                '-out', private_key_path,
                '-pkeyopt', 'rsa_keygen_bits:2048'
            ])

            # Generate the public key
            subprocess.check_call([
                'openssl', 'rsa',
                '-in', private_key_path,
                '-pubout',
                '-out', public_key_path
            ])

            # Generate the CSR (Certificate Signing Request)
            subprocess.check_call([
                'openssl', 'req', '-new',
                '-key', private_key_path,
                '-out', csr_path,
                '-subj', "/CN={}/O=Organization/C=UK".format(user.username),
                '-config', '/etc/ssl/openssl.cnf'
            ])

            # Sign the certificate (self-signed for demonstration)
            subprocess.check_call([
                'openssl', 'x509', '-req',
                '-in', csr_path,
                '-signkey', private_key_path,
                '-out', cert_path,
                '-days', '365'
            ])

            # Read the public key
            with open(public_key_path, 'r') as pk_file:
                public_key = pk_file.read()

            # Store the public key in the database
            UserKey.objects.create(user=user, public_key=public_key)

            # Read the private key
            with open(private_key_path, 'r') as prk_file:
                private_key = prk_file.read()

            # Send the private key and certificate via email
            email_subject = 'Your Private Key and Certificate'
            email_body = (
                "Dear {},\n\n"
                "Your account has been approved. Attached are your private key and certificate.\n\n"
                "Please keep your private key secure and do not share it with anyone.\n\n"
                "Best regards,\n"
                "Your Organization"
            ).format(user.username)

            email = EmailMessage(
                email_subject,
                email_body,
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
            )

            email.attach('{}_private_key.pem'.format(user.username), private_key, 'application/x-pem-file')

            # Read the certificate
            with open(cert_path, 'r') as cert_file:
                certificate = cert_file.read()

            email.attach('{}_certificate.crt'.format(user.username), certificate, 'application/x-x509-ca-cert')

            email.send(fail_silently=False)  # Ensure email errors are raised

            messages.success(request, "User {} has been approved and credentials sent.".format(user.username))

        except subprocess.CalledProcessError as e:
            messages.error(request, "An error occurred during key generation: {}".format(e))
            return redirect('ca_page')

        except IOError as e:
            messages.error(request, "File error: {}".format(e))
            return redirect('ca_page')

    elif action == 'deny':
        user.ca_approve = 2
        user.save()
        messages.info(request, "User {} has been denied.".format(user.username))

    else:
        messages.error(request, "Invalid action specified.")

    return redirect('ca_page')

def store_key_pair(user_id, private_key, public_key):
    key_entry = UserKey(user_id=user_id, public_key=public_key, private_key=private_key)
    key_entry.save()

def send_private_key_via_email(email, private_key):
    subject = 'Your Private Key'
    message = 'Please keep this private key safe: {}\n\n'.format(private_key)
    send_mail(subject, message, 'admin@example.com', [email])

def test_send_email(request):
    try:
        send_mail(
            'Test Email',
            'This is a test email.',
            settings.DEFAULT_FROM_EMAIL,
            ['kopibryant55@gmail.com'],  # Replace with your email or a test email
            fail_silently=False,
        )
        return HttpResponse('Email sent successfully!')
    except Exception as e:
        return HttpResponse('Error sending email: {}'.format(e))

# ------------------- End of CA --------------------------------

def ensure_directory_exists(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

# Generate a unique filename for encryption
def generate_unique_filename(patient):
    timestamp = datetime.now().strftime('%d%m%y_%H%M')
    return "{}_{}.cpabe".format(patient.username, timestamp)

# Encrypt a file using OpenABE
def encrypt_file(doctor, patient, file_path):
    try:
        specialist = Specialist.objects.get(userid=patient.id)
    except Specialist.DoesNotExist:
        raise ValueError("No specialist found for patient.")

    # Encryption policy, for example: 'Doctor AND Neurologist'
    policy = "({} AND {})".format(patient.username, specialist.specialist)
    
    # Ensure the directory for encrypted files exists
    encrypted_file_dir = os.path.join(settings.MEDIA_ROOT, 'encrypted_files')
    ensure_directory_exists(encrypted_file_dir)
    
    # Generate the output file path
    encrypted_file_path = os.path.join(encrypted_file_dir, generate_unique_filename(patient))

    try:
        # Execute the OpenABE encryption command
        subprocess.check_call([
            OABE_SETUP, '-s', 'CP', '-p', 'org1'
        ])
        
        subprocess.check_call([
            OABE_ENC, '-s', 'CP', '-p', 'org1', '-e', policy,
            '-i', file_path, '-o', encrypted_file_path
        ])
        return encrypted_file_path
    
    except subprocess.CalledProcessError as e:
        print("Encryption failed: {}".format(e))
        return None

# ./libopenabe/cli/cli/oabe_setup -s CP -p org1
# ./libopenabe/cli/cli/oabe_dec -s CP -p org1 -k doctor1.cpabe.key -i  -o d1.txt
def keygen(patient):
    try:
        specialist = Specialist.objects.get(userid=patient.id)
    except Specialist.DoesNotExist:
        raise ValueError("No specialist found for patient.")

    # Define the policy based on the patient's username and specialist
    policy = "{}|{}".format(patient.username, specialist.specialist)
    
    # CP name, which will be used to name the key file
    cp_name = "{}".format(patient.username)

    # Ensure the directory for the keys exists
    key_dir = os.path.join(settings.MEDIA_ROOT, 'keys')
    ensure_directory_exists(key_dir)
    
    # Generate the key file path
    key_file_path = os.path.join(key_dir, "{}.cpabe".format(cp_name))

    try:
        # Execute the OpenABE setup command
        subprocess.check_call([
            OABE_SETUP, '-s', 'CP', '-p', 'org1'
        ])
        
        # Generate the CP-ABE key for the patient
        subprocess.check_call([
            OABE_KEYGEN, '-s', 'CP', '-p', 'org1', '-i', policy,
            '-o', key_file_path
        ])
        
        # Return the path to the generated CP-ABE key file
        return key_file_path
    
    except subprocess.CalledProcessError as e:
        print("Key generation failed: {}".format(e))
        return None


# Send the encrypted file via email to the patient
def send_encrypted_file_via_email(patient, encrypted_file_path, cpkey_path):
    email_subject = 'Encrypted Medical File'
    email_body = (
        "Dear {},\n\n"
        "Attached are your encrypted medical file and the decryption key.\n"
        "Please use the decryption key to access the contents of the encrypted file.\n\n"
        "Best regards,\n"
        "Your Medical Provider"
    ).format(patient.username)

    email = EmailMessage(
        email_subject,
        email_body,
        settings.DEFAULT_FROM_EMAIL,
        [patient.email],
    )

    # Attach the encrypted file
    if os.path.exists(encrypted_file_path):
        try:
            with open(encrypted_file_path, 'rb') as encrypted_file:
                email.attach(os.path.basename(encrypted_file_path), encrypted_file.read(), 'application/octet-stream')
        except Exception as e:
            print("Failed to attach encrypted file: {}".format(e))
    else:
        print("Encrypted file does not exist: {}".format(encrypted_file_path))

    # Correctly reference the CP-ABE key file with the '.key' extension
    cpkey_file_with_extension = "{}.key".format(cpkey_path)

    # Attach the CP-ABE key file
    if os.path.exists(cpkey_file_with_extension):
        try:
            with open(cpkey_file_with_extension, 'rb') as cpkey_file:
                email.attach(os.path.basename(cpkey_file_with_extension), cpkey_file.read(), 'application/octet-stream')
        except Exception as e:
            print("Failed to attach CP-ABE key: {}".format(e))
    else:
        print("CP-ABE key file does not exist: {}".format(cpkey_file_with_extension))

    # Attempt to send the email
    try:
        email.send(fail_silently=False)
        print("Email sent successfully to {}".format(patient.email))
    except Exception as e:
        print("Failed to send email: {}".format(e))


# View for the doctor's main page
@login_required
def doctor_page(request):
    if not request.user.is_doctor:
        return redirect('login')
    
    specialist = None
    try:
        specialist = Specialist.objects.get(userid=request.user.id).specialist
    except Specialist.DoesNotExist:
        pass 
    
    if specialist:
        # Get user IDs with the same specialist
        specialist_user_ids = Specialist.objects.filter(specialist=specialist).values_list('userid', flat=True)
        
        # Get users who are patients and have the same specialist
        patients = User.objects.filter(id__in=specialist_user_ids, is_patient=True)
    else:
        patients = []

    if request.method == 'POST':
        selected_patients = request.POST.getlist('patients')
        uploaded_file = request.FILES['file']
        
        # Ensure the file is saved
        file_path = os.path.join(settings.MEDIA_ROOT, uploaded_file.name)
        with open(file_path, 'wb+') as destination:
            for chunk in uploaded_file.chunks():
                destination.write(chunk)
        
        # Encrypt the file for each selected patient
        for patient_id in selected_patients:
            patient = User.objects.get(id=patient_id)
            cpKey = keygen(patient)
            encrypted_file_path = encrypt_file(request.user, patient, file_path)
            
            if encrypted_file_path:
                # Send encrypted file via email
                send_encrypted_file_via_email(patient, encrypted_file_path, cpKey)

        # Clean up: remove the unencrypted file
        if os.path.exists(file_path):
            os.remove(file_path)

        return redirect('doctor_page')

    context = {
        'specialist': specialist,
        'patients': patients,
    }

    return render(request, 'myapp/doctor_page.html', context)  

# ./libopenabe/cli/cli/oabe_dec -s CP -p org1 -k /mnt/c/Users/User/Downloads/patient1.cpabe.key -i /mnt/c/Users/User/Downloads/patient1_010924_2255.cpabe -o decrypted_output.txt

@login_required
def patient_page(request):
    context = {}

    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'decrypt':
            private_key = request.FILES.get('private_key')
            encrypted_file = request.FILES.get('encrypted_file')

            if private_key and encrypted_file:
                # Save the private key temporarily
                fs_keys = FileSystemStorage(location=os.path.join(settings.MEDIA_ROOT, 'keys'))
                private_key_name = private_key.name
                private_key_path = fs_keys.save(private_key_name, private_key)

                # Save the encrypted file temporarily
                fs_encrypted = FileSystemStorage(location=os.path.join(settings.MEDIA_ROOT, 'encrypted_files'))
                encrypted_file_name = encrypted_file.name
                encrypted_file_path = fs_encrypted.save(encrypted_file_name, encrypted_file)

                try:
                    # Perform decryption using the same name as the original file
                    decrypted_file_path = os.path.join(settings.MEDIA_ROOT, encrypted_file_name)

                    subprocess.check_call([
                        './libopenabe/cli/cli/oabe_dec', '-s', 'CP', '-p', 'org1',
                        '-k', fs_keys.path(private_key_path), '-i', fs_encrypted.path(encrypted_file_path),
                        '-o', decrypted_file_path
                    ])

                    # Email the decrypted file
                    send_decrypted_file_via_email(request.user, decrypted_file_path)
                    context['success_message'] = "Decryption successful! The decrypted file has been sent to your email."

                except subprocess.CalledProcessError as e:
                    context['error_message'] = "Decryption failed: {}".format(e)

                finally:
                    # Clean up: remove the temporary files
                    if os.path.exists(fs_keys.path(private_key_path)):
                        os.remove(fs_keys.path(private_key_path))
                    if os.path.exists(fs_encrypted.path(encrypted_file_path)):
                        os.remove(fs_encrypted.path(encrypted_file_path))
                    if os.path.exists(decrypted_file_path):
                        os.remove(decrypted_file_path)

            else:
                context['error_message'] = "Both the private key and the encrypted file are required."

    return render(request, 'myapp/patient_page.html', context)

def ensure_directory_exists(path):
    if not os.path.exists(path):
        os.makedirs(path)

def send_decrypted_file_via_email(patient, decrypted_file_path):
    email_subject = 'Decrypted Medical File'
    email_body = (
        "Dear {},\n\n"
        "Attached is your decrypted medical file.\n\n"
        "Best regards,\n"
        "Your Medical Provider"
    ).format(patient.username)

    email = EmailMessage(
        email_subject,
        email_body,
        settings.DEFAULT_FROM_EMAIL,
        [patient.email],
    )

    if os.path.exists(decrypted_file_path):
        try:
            with open(decrypted_file_path, 'rb') as decrypted_file:
                email.attach(os.path.basename(decrypted_file_path), decrypted_file.read(), 'text/plain')
            email.send(fail_silently=False)
        except Exception as e:
            print("Failed to send email: {}".format(e))
    else:
        print("Decrypted file does not exist: {}".format(decrypted_file_path))


def redirect_to_login(request):
    return redirect('login')

# Logout function
@login_required
def user_logout(request):
    logout(request)
    return redirect('login')
