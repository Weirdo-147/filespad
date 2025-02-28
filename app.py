import os
import re
from datetime import datetime, timedelta
from flask import Flask, render_template, request, send_file, redirect, url_for, flash, abort, jsonify, Response
from werkzeug.utils import secure_filename
import cloudinary
import cloudinary.uploader
import cloudinary.api
import requests
from flask_apscheduler import APScheduler
from cryptography.fernet import Fernet
import secrets
import json
from dotenv import load_dotenv
from io import BytesIO
import uuid
from werkzeug.security import generate_password_hash, check_password_hash

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(16))
scheduler = APScheduler()

# Cloudinary configuration
cloudinary.config(
    cloud_name=os.getenv('CLOUDINARY_CLOUD_NAME'),
    api_key=os.getenv('CLOUDINARY_API_KEY'),
    api_secret=os.getenv('CLOUDINARY_API_SECRET')
)

# Initialize encryption key
ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY', Fernet.generate_key())
fernet = Fernet(ENCRYPTION_KEY)

# Session storage (in production, use a database)
SESSIONS = {}

def get_cloudinary_stats():
    """Get total number of sessions and files from Cloudinary"""
    try:
        # Get all folders in the root
        folders_result = cloudinary.api.root_folders()
        total_folders = len(folders_result['folders'])
        
        total_files = 0
        # Get files count from each folder
        for folder in folders_result['folders']:
            try:
                # Get resources in the folder
                resources = cloudinary.api.resources(
                    resource_type="raw",
                    type="upload",
                    prefix=folder['path'],
                    max_results=500  # Adjust if needed
                )
                total_files += len(resources.get('resources', []))
            except Exception as e:
                app.logger.error(f"Error counting files in folder {folder['path']}: {str(e)}")
                continue
                
        return {
            'total_folders': total_folders,
            'total_files': total_files
        }
    except Exception as e:
        app.logger.error(f"Error getting Cloudinary stats: {str(e)}")
        return {
            'total_folders': 0,
            'total_files': 0
        }

def create_session_folder(session_code):
    """Create a new folder in Cloudinary for the session"""
    try:
        cloudinary.api.create_folder(session_code)
        return True
    except Exception as e:
        app.logger.error(f"Error creating folder: {str(e)}")
        return False

def delete_session_folder(session_code):
    """Delete a session folder and all its contents from Cloudinary"""
    try:
        # Delete all files in the folder
        cloudinary.api.delete_resources_by_prefix(f"{session_code}/")
        # Delete the folder
        cloudinary.api.delete_folder(session_code)
        return True
    except Exception as e:
        app.logger.error(f"Error deleting folder: {str(e)}")
        return False

def encrypt_file(file_data):
    """Encrypt file data before uploading"""
    return fernet.encrypt(file_data)

def decrypt_file(encrypted_data):
    """Decrypt file data before sending"""
    return fernet.decrypt(encrypted_data)

def is_valid_custom_code(code):
    """Validate custom code format"""
    if not code or not isinstance(code, str):
        return False
    return bool(re.match(r'^[a-zA-Z0-9_-]{3,20}$', code))

def sync_session_with_cloudinary(session_code):
    """Sync session data with Cloudinary storage"""
    try:
        # Get all files in the session folder
        resources = cloudinary.api.resources(
            resource_type="raw",
            type="upload",
            prefix=f"{session_code}/",
            max_results=500
        )
        
        app.logger.info(f"Found resources: {json.dumps(resources, indent=2)}")
        
        # Initialize session if it doesn't exist
        if session_code not in SESSIONS:
            SESSIONS[session_code] = {
                'created_at': datetime.utcnow(),
                'files': {}
            }
        
        # Clear existing files to prevent duplicates
        SESSIONS[session_code]['files'].clear()
        
        # Update session with files from Cloudinary
        for resource in resources.get('resources', []):
            try:
                # Extract file_id from the public_id (remove folder prefix)
                public_id = resource['public_id']
                file_parts = public_id.split('/')[-1].split('_', 1)  # Split on first underscore
                file_id = file_parts[0]
                
                # Try multiple ways to get the original filename
                original_filename = None
                filename = None
                
                # First try to get from context metadata
                if 'context' in resource and 'custom' in resource['context']:
                    original_filename = resource['context']['custom'].get('original_name')
                    filename = resource['context']['custom'].get('original_filename')
                
                # Then try to extract from public_id
                if not filename and len(file_parts) > 1:
                    filename = file_parts[1]
                
                # Then try other metadata fields
                if not filename:
                    filename = (
                        resource.get('metadata', {}).get('original_filename') or
                        resource.get('original_filename') or
                        os.path.basename(resource.get('secure_url', '')) or
                        file_id
                    )
                
                if not original_filename:
                    original_filename = filename
                
                # Create timestamps
                now = datetime.utcnow()
                upload_date = datetime.strptime(resource['created_at'], "%Y-%m-%dT%H:%M:%SZ")
                expiry_date = upload_date + timedelta(days=3)
                
                app.logger.info(f"Processing file: {file_id}")
                app.logger.info(f"Original filename: {original_filename}")
                app.logger.info(f"Public ID: {public_id}")
                app.logger.info(f"Upload date: {upload_date}")
                app.logger.info(f"Expiry date: {expiry_date}")
                
                SESSIONS[session_code]['files'][file_id] = {
                    'filename': filename,
                    'original_filename': original_filename,
                    'url': resource['secure_url'],
                    'password': None,  # We can't recover passwords for existing files
                    'upload_date': upload_date,
                    'expiry_date': expiry_date
                }
                
                app.logger.info(f"Added file to session: {json.dumps(SESSIONS[session_code]['files'][file_id], default=str)}")
                
            except Exception as e:
                app.logger.error(f"Error processing file {resource.get('public_id')}: {str(e)}")
                continue
        
        app.logger.info(f"Total files in session: {len(SESSIONS[session_code]['files'])}")
        return True
        
    except Exception as e:
        app.logger.error(f"Error syncing with Cloudinary: {str(e)}")
        return False

def calculate_session_storage(session_code):
    """Calculate total storage used by a session"""
    try:
        total_size = 0
        resources = cloudinary.api.resources(
            resource_type="raw",
            type="upload",
            prefix=f"{session_code}/",
            max_results=500
        )
        
        for resource in resources.get('resources', []):
            total_size += resource.get('bytes', 0)
        
        # Convert to human readable format
        for unit in ['B', 'KB', 'MB', 'GB']:
            if total_size < 1024:
                return f"{total_size:.1f} {unit}"
            total_size /= 1024
        return f"{total_size:.1f} TB"
    except Exception as e:
        app.logger.error(f"Error calculating storage: {str(e)}")
        return "Unknown"

def verify_session_password(session_code, password=None):
    """Verify session password if it exists"""
    if session_code not in SESSIONS:
        return False
        
    session = SESSIONS[session_code]
    if 'password' not in session or not session['password']:
        return True  # No password protection
        
    if not password:
        return False
        
    return check_password_hash(session['password'], password)

@app.route('/')
def index():
    stats = get_cloudinary_stats()
    return render_template('index.html', 
                         total_codes=stats['total_folders'],
                         total_files=stats['total_files'])

@app.route('/verify-code', methods=['POST'])
def verify_code():
    access_code = request.form.get('access_code')
    if not access_code:
        flash('Please enter an access code')
        return redirect(url_for('index'))
    
    # Validate code format
    if not is_valid_custom_code(access_code):
        flash('Invalid code format. Use 3-20 characters, letters, numbers, underscore and hyphen only.')
        return redirect(url_for('index'))
    
    # Try to sync with Cloudinary first
    if sync_session_with_cloudinary(access_code):
        return redirect(url_for('dashboard', access_code=access_code))
    else:
        # Create new session folder in Cloudinary
        if not create_session_folder(access_code):
            flash('Error creating session. Please try again.')
            return redirect(url_for('index'))
        
        # Create new session
        SESSIONS[access_code] = {
            'created_at': datetime.utcnow(),
            'files': {}
        }
        return redirect(url_for('upload_console', session_code=access_code))

@app.route('/create-upload-session', methods=['POST'])
def create_upload_session():
    custom_code = request.form.get('custom_code')
    
    # Validate custom code
    if not is_valid_custom_code(custom_code):
        flash('Invalid custom code format. Use 3-20 characters, letters, numbers, underscore and hyphen only.')
        return redirect(url_for('index'))
    
    # Check if code is already in use
    if custom_code in SESSIONS:
        flash('This code is already in use. Please choose another one.')
        return redirect(url_for('index'))
    
    SESSIONS[custom_code] = {
        'created_at': datetime.utcnow(),
        'files': {}
    }
    return redirect(url_for('upload_console', session_code=custom_code))

@app.route('/dashboard/<access_code>')
def dashboard(access_code):
    # First validate the code format
    if not is_valid_custom_code(access_code):
        flash('Invalid access code format')
        return redirect(url_for('index'))
    
    app.logger.info(f"Accessing dashboard for code: {access_code}")
    
    # Try to sync with Cloudinary
    sync_success = sync_session_with_cloudinary(access_code)
    app.logger.info(f"Sync success: {sync_success}")
    
    if not sync_success:
        flash('Error syncing with storage')
        return redirect(url_for('index'))
    
    if access_code not in SESSIONS:
        flash('Invalid or expired access code')
        return redirect(url_for('index'))
    
    session = SESSIONS[access_code]
    
    # Check if password protected and not owner
    if not request.args.get('is_owner') and 'password' in session and session['password']:
        return render_template('password_verify.html', 
                             access_code=access_code,
                             return_url=url_for('dashboard', access_code=access_code, is_owner=True))
    
    current_time = datetime.utcnow()
    
    # Prepare files data for the template
    files = []
    for file_id, file_info in session['files'].items():
        # Include all files that haven't expired
        if current_time <= file_info['expiry_date']:
            file_data = {
                'id': file_id,
                'filename': file_info['filename'],
                'password': file_info['password'],
                'upload_date': file_info['upload_date'],
                'expiry_date': file_info['expiry_date']
            }
            files.append(file_data)
    
    # Log the files being sent to template
    app.logger.info(f"Number of files to display: {len(files)}")
    for file in files:
        app.logger.info(f"File to display: {json.dumps({**file, 'upload_date': file['upload_date'].isoformat(), 'expiry_date': file['expiry_date'].isoformat()})}")
    
    # Sort files by upload date, newest first
    files.sort(key=lambda x: x['upload_date'], reverse=True)
    
    return render_template('dashboard.html',
                         access_code=access_code,
                         files=files,
                         now=current_time,
                         session_created_at=session['created_at'],
                         session=session,  # Pass the entire session data
                         is_owner=True)  # In production, implement proper ownership check

@app.route('/upload/<session_code>')
def upload_console(session_code):
    if session_code not in SESSIONS:
        flash('Invalid or expired session')
        return redirect(url_for('index'))
    return render_template('upload.html', session_code=session_code)

@app.route('/upload/<session_code>/file', methods=['POST'])
def upload_file(session_code):
    if session_code not in SESSIONS:
        return {'error': 'Invalid or expired session'}, 400
    
    if 'file' not in request.files:
        return {'error': 'No file selected'}, 400
    
    file = request.files['file']
    if file.filename == '':
        return {'error': 'No file selected'}, 400
    
    # Generate unique file ID
    file_id = str(uuid.uuid4())
    
    # Secure the filename while preserving extension
    original_filename = file.filename
    filename = secure_filename(original_filename)
    
    # Optional password protection
    password = request.form.get('password')
    
    try:
        # Encrypt file data
        encrypted_data = encrypt_file(file.read())
        
        # Upload to Cloudinary in the session folder
        upload_result = cloudinary.uploader.upload(
            encrypted_data,
            resource_type="raw",
            public_id=f"{file_id}_{filename}",  # Include filename in public_id
            folder=session_code,
            use_filename=True,
            context={
                'original_filename': filename,
                'original_name': original_filename  # Store both secured and original filename
            },
            tags=[filename, os.path.splitext(filename)[1][1:] if os.path.splitext(filename)[1] else '']  # Add extension as tag
        )

        # Store file metadata
        SESSIONS[session_code]['files'][file_id] = {
            'filename': filename,
            'original_filename': original_filename,
            'url': upload_result['secure_url'],
            'password': password,
            'upload_date': datetime.utcnow(),
            'expiry_date': datetime.utcnow() + timedelta(days=3)
        }

        return jsonify({
            'status': 'success',
            'access_code': session_code,
            'filename': filename
        })
    except Exception as e:
        app.logger.error(f"Upload error: {str(e)}")
        return {'error': 'Error uploading file'}, 500

@app.route('/verify-access', methods=['POST'])
def verify_access():
    access_code = request.form.get('access_code')
    password = request.form.get('password')
    
    if not access_code:
        return jsonify({'error': 'Access code is required'}), 400
        
    if not verify_session_password(access_code, password):
        return jsonify({'error': 'Incorrect password'}), 401
        
    return jsonify({'status': 'success'})

@app.route('/download/<access_code>/<file_id>', methods=['GET', 'POST'])
def download_file(access_code, file_id):
    if access_code not in SESSIONS:
        flash('Invalid access code')
        return redirect(url_for('index'))

    session = SESSIONS[access_code]
    
    # Check session password protection first
    if not request.args.get('is_owner') and 'password' in session and session['password']:
        if request.method == 'GET':
            return render_template('password_verify.html', 
                                access_code=access_code,
                                file_id=file_id,
                                return_url=url_for('download_file', access_code=access_code, file_id=file_id, is_owner=True))
        
        password = request.form.get('password')
        if not verify_session_password(access_code, password):
            flash('Incorrect password')
            return render_template('password_verify.html', 
                                access_code=access_code,
                                file_id=file_id,
                                return_url=url_for('download_file', access_code=access_code, file_id=file_id, is_owner=True))

    if file_id not in session['files']:
        flash('File not found')
        return redirect(url_for('dashboard', access_code=access_code))

    file_info = session['files'][file_id]
    
    # Check if file has expired
    if datetime.utcnow() > file_info['expiry_date']:
        del session['files'][file_id]
        flash('File has expired')
        return redirect(url_for('dashboard', access_code=access_code))

    # Handle individual file password protection
    if file_info['password']:
        if request.method == 'GET':
            return render_template('password.html', 
                                access_code=access_code,
                                file_id=file_id)
        
        if request.form.get('password') != file_info['password']:
            flash('Incorrect password')
            return render_template('password.html', 
                                access_code=access_code,
                                file_id=file_id)

    try:
        # Get the file from Cloudinary using the full path including filename
        filename = file_info['filename']
        resource = cloudinary.api.resource(
            f"{access_code}/{file_id}_{filename}",  # Include both ID and filename
            resource_type="raw"
        )
        
        app.logger.info(f"Downloading file: {resource['secure_url']}")
        
        # Download the encrypted file
        response = requests.get(resource['secure_url'])
        if response.status_code != 200:
            app.logger.error(f"Error downloading file: Status code {response.status_code}")
            flash('Error downloading file')
            return redirect(url_for('dashboard', access_code=access_code))
        
        # Decrypt the file data
        encrypted_data = response.content
        decrypted_data = decrypt_file(encrypted_data)
        
        # Create a BytesIO object for the decrypted data
        file_data = BytesIO(decrypted_data)
        
        # Use the original filename for download if available
        download_name = file_info.get('original_filename') or file_info['filename'] or f"download_{file_id}"
        
        app.logger.info(f"Sending file: {download_name}")
        
        return send_file(
            file_data,
            download_name=download_name,
            as_attachment=True
        )
    except Exception as e:
        app.logger.error(f"Download error: {str(e)}")
        flash('Error downloading file')
        return redirect(url_for('dashboard', access_code=access_code))

@app.route('/delete/<access_code>/<file_id>', methods=['POST'])
def delete_file(access_code, file_id):
    if access_code not in SESSIONS:
        return jsonify({'error': 'Invalid access code'}), 404

    session = SESSIONS[access_code]
    if file_id not in session['files']:
        return jsonify({'error': 'File not found'}), 404

    try:
        # Delete from Cloudinary using folder
        cloudinary.uploader.destroy(
            file_id,  # Just the file ID
            resource_type="raw",
            invalidate=True,
            folder=access_code  # Specify the folder
        )
        # Remove from session
        del session['files'][file_id]
        
        # If this was the last file and session is old enough, clean up the session
        if not session['files'] and datetime.utcnow() - session['created_at'] > timedelta(hours=24):
            delete_session_folder(access_code)
            del SESSIONS[access_code]
            return jsonify({'status': 'success', 'redirect': 'home'})
        
        return jsonify({'status': 'success'})
    except Exception as e:
        app.logger.error(f"Error deleting file: {str(e)}")
        return jsonify({'error': 'Error deleting file'}), 500

def cleanup_expired_files():
    """Remove expired files from storage"""
    current_time = datetime.utcnow()
    
    for session_code, session in list(SESSIONS.items()):
        # Clean up expired files
        expired_files = [
            file_id for file_id, file_info in session['files'].items()
            if current_time > file_info['expiry_date']
        ]
        
        for file_id in expired_files:
            try:
                # Delete from Cloudinary using folder
                cloudinary.uploader.destroy(
                    file_id,  # Just the file ID
                    resource_type="raw",
                    invalidate=True,
                    folder=session_code  # Specify the folder
                )
                # Remove from session
                del session['files'][file_id]
            except Exception as e:
                app.logger.error(f"Error deleting file {file_id}: {str(e)}")
        
        # Remove empty sessions older than 24 hours
        if not session['files'] and current_time - session['created_at'] > timedelta(hours=24):
            # Delete the session folder from Cloudinary
            delete_session_folder(session_code)
            del SESSIONS[session_code]

# Schedule cleanup job
scheduler.add_job(
    id='cleanup_expired_files',
    func=cleanup_expired_files,
    trigger='interval',
    hours=24
)

@app.route('/settings/<access_code>/storage-info')
def get_storage_info(access_code):
    if access_code not in SESSIONS:
        return jsonify({'error': 'Invalid access code'}), 404
    
    storage_used = calculate_session_storage(access_code)
    return jsonify({'storage_used': storage_used})

@app.route('/settings/<access_code>/lock', methods=['POST'])
def set_code_lock(access_code):
    if access_code not in SESSIONS:
        return jsonify({'error': 'Invalid access code'}), 404
    
    data = request.get_json()
    password = data.get('password')
    
    if not password:
        return jsonify({'error': 'Password is required'}), 400
    
    try:
        # Store the password hash instead of plain text
        SESSIONS[access_code]['password'] = generate_password_hash(password)
        return jsonify({'status': 'success'})
    except Exception as e:
        app.logger.error(f"Error setting password: {str(e)}")
        return jsonify({'error': 'Error setting password'}), 500

@app.route('/settings/<access_code>/delete-all', methods=['POST'])
def delete_all(access_code):
    if access_code not in SESSIONS:
        return jsonify({'error': 'Invalid access code'}), 404
    
    try:
        # Delete all files from Cloudinary
        delete_session_folder(access_code)
        # Remove session
        del SESSIONS[access_code]
        return jsonify({'status': 'success'})
    except Exception as e:
        app.logger.error(f"Error deleting everything: {str(e)}")
        return jsonify({'error': 'Error deleting everything'}), 500

@app.route('/settings/<access_code>/lock', methods=['DELETE'])
def remove_password(access_code):
    if access_code not in SESSIONS:
        return jsonify({'status': 'error', 'error': 'Invalid access code'}), 404

    # Remove the password from the session
    SESSIONS[access_code]['password'] = None
    return jsonify({'status': 'success'})

if __name__ == '__main__':
    scheduler.init_app(app)
    scheduler.start()
    app.run(debug=True) 