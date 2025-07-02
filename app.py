from flask import Flask, render_template, request, redirect, session, flash, url_for, send_from_directory
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import MySQLdb.cursors
import hashlib
import os
from datetime import datetime

app = Flask(__name__)

app.secret_key = 'f9af10f27cc3b5317420d4570c8921e2d7a4c6c6713b10c4739de1d14a76d78e'

# MySQL Database Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Alwyn@123'
app.config['MYSQL_DB'] = 'secure_edoc'

# File Upload Configuration
UPLOAD_FOLDER = 'uploads' # Ensure this folder exists and is writable, but NOT directly web-accessible
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'png', 'jpg', 'jpeg', 'gif', 'docx'}

mysql = MySQL(app)

# Helper function to check allowed file types
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Helper function for role-based access control
def is_logged_in(required_role):
    # Check if user is logged in AND has the required role
    return 'role' in session and session['role'] == required_role

# --- Public Routes ---
@app.route('/')
def home():
    # Redirect logged-in users to their respective dashboards
    if 'role' in session:
        return redirect(f"/{session['role']}")
    return render_template('login.html') # Default landing is login

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Public signup is only for 'user' role as per template modification
        role = request.form.get('role') # Should always be 'user' from public form
        raw_password = request.form.get('password')

        # Basic validation
        if not raw_password:
            flash("Password is required.", 'error')
            return redirect(url_for('signup'))

        password_hash = generate_password_hash(raw_password)

        cur = mysql.connection.cursor()
        try:
            # Only allow 'user' role for public signup
            if role == 'user':
                aadhar = request.form.get('aadhar')
                if not aadhar:
                    flash("Aadhaar Number is required for user registration.", 'error')
                    return redirect(url_for('signup'))
                # Check if Aadhaar already exists
                cur.execute("SELECT id FROM users WHERE aadhar = %s", (aadhar,))
                if cur.fetchone():
                    flash("Aadhaar number already registered. Please login or use a different Aadhaar.", 'error')
                    return redirect(url_for('signup'))
                # Insert new user
                cur.execute("INSERT INTO users (aadhar, password, role) VALUES (%s, %s, %s)", (aadhar, password_hash, role))
            else:
                # This path should ideally not be hit by the public signup form,
                # but it handles cases where role might be manipulated.
                flash("Invalid role for public signup. Only 'user' registration is allowed.", 'error')
                return redirect(url_for('signup'))

            mysql.connection.commit()
            cur.close()
            flash("Account created successfully! Please login.", 'success')
            return redirect(url_for('login'))
        except Exception as e:
            mysql.connection.rollback()
            flash(f"An unexpected error occurred during signup. Please try again. Error: {e}", 'error')
            app.logger.error(f"Signup database error: {e}")
            return redirect(url_for('signup'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        role = request.form.get('role')
        raw_password = request.form.get('password')
        
        identifier = None
        query_field = None

        # Determine identifier based on role
        if role == 'user':
            identifier = request.form.get('aadhar')
            query_field = 'aadhar'
        else: # For verifier and admin
            identifier = request.form.get('username')
            query_field = 'username'

        if not identifier or not raw_password:
            flash("Please provide both identifier (Aadhaar/Username) and password.", 'error')
            return redirect(url_for('login'))

        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor) # Use DictCursor to access columns by name
        try:
            # Query user by identifier and role
            cur.execute(f"SELECT id, aadhar, username, password, role FROM users WHERE {query_field} = %s AND role = %s", (identifier, role))
            user = cur.fetchone()
            cur.close()

            if user and check_password_hash(user['password'], raw_password):
                # Store user role and identifier in session
                session['role'] = user['role']
                session['id'] = user['aadhar'] if user['role'] == 'user' else user['username'] # Identifier (Aadhaar or Username)

                # Log successful login attempt
                cur = mysql.connection.cursor()
                cur.execute("INSERT INTO logins (user_identifier, user_role, login_time) VALUES (%s, %s, NOW())",
                            (session['id'], session['role']))
                mysql.connection.commit()
                cur.close()

                flash(f"Welcome, {session['id']}!", 'success')
                return redirect(f"/{role}") # Redirect to role-specific dashboard
            else:
                flash("Invalid credentials or role mismatch. Please check your input.", 'error')
                return redirect(url_for('login'))
        except Exception as e:
            flash(f"An error occurred during login. Please try again. Error: {e}", 'error')
            app.logger.error(f"Login database error: {e}")
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    flash("You have been logged out successfully.", 'info')
    session.clear() # Clear all session data
    return redirect(url_for('home'))

# --- Admin Routes ---
@app.route('/admin')
def admin_dashboard():
    # Enforce admin role for access
    if not is_logged_in('admin'):
        flash("Access Denied: You must be logged in as an administrator to view this page.", 'error')
        return redirect(url_for('login'))

    cur = mysql.connection.cursor()
    
    # Fetch all users for the 'Registered Users' table
    cur.execute("SELECT id, aadhar, username, role, created_at FROM users ORDER BY created_at DESC")
    users_data = cur.fetchall() # Raw fetched data

    display_users = []
    for user_row in users_data:
        user_id = user_row[0]
        identifier = user_row[1] if user_row[1] else user_row[2] # Use aadhar if user, else username
        role = user_row[3]
        created_at = user_row[4]
        display_users.append((user_id, identifier, role, created_at.strftime('%Y-%m-%d %H:%M:%S')))

    # Fetch dashboard statistics
    cur.execute("SELECT COUNT(*) FROM documents WHERE DATE(timestamp) = CURDATE()")
    uploads_today = cur.fetchone()[0] # Count documents issued today

    cur.execute("SELECT COUNT(*) FROM documents WHERE status = 'Tampered'")
    tampered_docs = cur.fetchone()[0] # Count tampered documents

    cur.execute("SELECT COUNT(*) FROM users WHERE WEEK(created_at, 1) = WEEK(NOW(), 1) AND YEAR(created_at) = YEAR(NOW())")
    new_users = cur.fetchone()[0] # Count new users this week

    # Fetch recent login attempts (all roles)
    cur.execute("SELECT user_identifier, user_role, login_time FROM logins ORDER BY login_time DESC LIMIT 5")
    recent_logins_data = cur.fetchall()
    
    recent_logins_display = []
    for login_entry in recent_logins_data:
        identifier, role, login_time = login_entry
        recent_logins_display.append((identifier, role, login_time.strftime('%Y-%m-%d %H:%M:%S')))

    cur.close()

    return render_template("admin_dashboard.html",
                           identifier=session['id'], # Admin's username
                           users=display_users,
                           uploads_today=uploads_today,
                           tampered_docs=tampered_docs,
                           new_users=new_users,
                           recent_logins=recent_logins_display)

@app.route('/admin/view-documents', methods=['GET', 'POST'])
def admin_view_documents():
    # Enforce admin role for access
    if not is_logged_in('admin'):
        flash("Access Denied: You must be logged in as an administrator.", 'error')
        return redirect(url_for('login'))
    
    cur = mysql.connection.cursor()

    if request.method == 'POST':
        document_id = request.form.get('document_id')
        action = request.form.get('action')
        document_filename = request.form.get('filename') # Used for file deletion

        if document_id:
            try:
                # Handle status updates (Verify, Reject, Tampered)
                if action in ['Verify', 'Reject', 'Tampered']:
                    new_status = action # Status directly matches action value
                    cur.execute("UPDATE documents SET status = %s WHERE id = %s", (new_status, document_id))
                    mysql.connection.commit()
                    flash(f"Document (ID: {document_id}) status updated to '{new_status}'.", 'success')
                # Handle document deletion
                elif action == 'Delete':
                    if document_filename:
                        filepath = os.path.join(app.config['UPLOAD_FOLDER'], document_filename)
                        if os.path.exists(filepath):
                            os.remove(filepath) # Delete file from server storage
                            flash(f"File '{document_filename}' deleted from server storage.", 'info')
                        else:
                            flash(f"Warning: File '{document_filename}' not found on server for deletion (ID: {document_id}).", 'warning')
                    
                    cur.execute("DELETE FROM documents WHERE id = %s", (document_id,)) # Delete database record
                    mysql.connection.commit()
                    flash(f"Document (ID: {document_id}) and its record deleted successfully.", 'success')
                else:
                    flash("Invalid action provided for document.", 'error')
            except Exception as e:
                mysql.connection.rollback()
                flash(f"An error occurred during document action: {e}", 'error')
                app.logger.error(f"Admin document action error: {e}")
        else:
            flash("Document ID not provided for action.", 'error')
        
        return redirect(url_for('admin_view_documents')) # Redirect back to refresh the list

    # Fetch all documents for display (GET request)
    cur.execute("SELECT id, user_id, filename, token, status, timestamp, blockchain_tx_id FROM documents ORDER BY timestamp DESC")
    documents = cur.fetchall()
    cur.close()
    
    return render_template('uploaded_documents.html', documents=documents)

@app.route('/admin/issue_document', methods=['GET', 'POST'])
def admin_issue_document():
    # Enforce admin role for access
    if not is_logged_in('admin'):
        flash("Access Denied: You must be logged in as an administrator.", 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        recipient_user_id = request.form.get('recipient_user_id')
        file = request.files['file']

        # Input validation
        if not recipient_user_id:
            flash("Recipient User ID (Aadhaar/Username) is required.", 'error')
            return redirect(url_for('admin_issue_document'))

        if file.filename == '':
            flash("No file selected for upload.", 'error')
            return redirect(url_for('admin_issue_document'))

        if not allowed_file(file.filename):
            flash(f"Invalid file type. Allowed types are: {', '.join(app.config['ALLOWED_EXTENSIONS'])}", 'error')
            return redirect(url_for('admin_issue_document'))

        cur = mysql.connection.cursor()
        filepath = None # Initialize filepath for potential cleanup
        try:
            # Check if recipient user exists and has 'user' role
            if recipient_user_id.isdigit() and len(recipient_user_id) == 12: # Assume Aadhaar if 12 digits
                cur.execute("SELECT id FROM users WHERE aadhar = %s AND role = 'user'", (recipient_user_id,))
            else: # Otherwise assume username
                cur.execute("SELECT id FROM users WHERE username = %s AND role = 'user'", (recipient_user_id,))
            
            user_exists = cur.fetchone()
            if not user_exists:
                flash(f"Recipient User (ID: {recipient_user_id}) not found or is not a 'user' role. Please ensure the user is registered and has the 'user' role.", 'error')
                cur.close()
                return redirect(url_for('admin_issue_document'))

            # Securely save the uploaded file
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            # Generate SHA-256 hash of the document
            with open(filepath, 'rb') as f:
                token = hashlib.sha256(f.read()).hexdigest()

            # Check if a document with this hash (content) already exists
            cur.execute("SELECT id FROM documents WHERE token = %s", (token,))
            if cur.fetchone():
                flash("This document (based on its content hash) is already registered in the system.", 'info')
                os.remove(filepath) # Remove the uploaded file if it's a duplicate
                cur.close()
                return redirect(url_for('admin_issue_document'))
            
            # Simulate Blockchain Transaction ID and Timestamp
            # In a real application, this would involve interaction with a blockchain network
            blockchain_tx_id = hashlib.sha256(os.urandom(16)).hexdigest() # Dummy TX ID
            blockchain_timestamp_on_chain = datetime.now() # Dummy Timestamp

            # Insert document record into database (initially with 'Pending' status)
            cur.execute("INSERT INTO documents (user_id, filename, token, status, timestamp, blockchain_tx_id, blockchain_timestamp_on_chain) VALUES (%s, %s, %s, %s, NOW(), %s, %s)",
                        (recipient_user_id, filename, token, 'Pending', blockchain_tx_id, blockchain_timestamp_on_chain))
            mysql.connection.commit()
            cur.close()

            flash(f"Document '{filename}' issued for User ID '{recipient_user_id}'. Token generated. It is now pending verifier approval.", 'success')
            # Redirect to a success page that shows the token and TX ID
            return render_template('document_issued_successfully.html', token=token, blockchain_tx_id=blockchain_tx_id)

        except Exception as e:
            mysql.connection.rollback()
            flash(f"An error occurred during document issuance: {e}", 'error')
            app.logger.error(f"Admin document issuance error: {e}")
            if filepath and os.path.exists(filepath): # Clean up partial upload on error
                os.remove(filepath)
            return redirect(url_for('admin_issue_document'))

    return render_template('admin_issue_document.html')

@app.route('/admin/manage_users', methods=['GET', 'POST']) # Allow POST for user actions
def admin_manage_users():
    # Enforce admin role for access
    if not is_logged_in('admin'):
        flash("Access Denied: You must be logged in as an administrator.", 'error')
        return redirect(url_for('login'))
    
    cur = mysql.connection.cursor()

    if request.method == 'POST':
        user_id_to_modify = request.form.get('user_id')
        action = request.form.get('action')

        if not user_id_to_modify:
            flash("User ID not provided for action.", 'error')
            return redirect(url_for('admin_manage_users'))

        try:
            # Get the logged-in admin's actual DB ID to prevent self-modification
            current_admin_identifier = session['id'] # This is the username of the logged-in admin
            cur.execute("SELECT id FROM users WHERE username = %s AND role = 'admin'", (current_admin_identifier,))
            current_admin_db_id = cur.fetchone()[0] if cur.fetchone() else None

            # Check if the user being modified is the current logged-in admin
            if int(user_id_to_modify) == current_admin_db_id:
                flash("You cannot modify or delete your own account.", 'error')
                return redirect(url_for('admin_manage_users'))

            if action == 'set_role':
                new_role = request.form.get('new_role')
                if new_role and new_role in ['admin', 'verifier', 'user']:
                    # Prevent demoting the last admin account
                    if new_role != 'admin':
                        cur.execute("SELECT role FROM users WHERE id = %s", (user_id_to_modify,))
                        target_user_role = cur.fetchone()
                        if target_user_role and target_user_role[0] == 'admin':
                            cur.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
                            num_admins = cur.fetchone()[0]
                            if num_admins <= 1:
                                flash("Cannot demote the last administrator account.", 'error')
                                return redirect(url_for('admin_manage_users'))

                    cur.execute("UPDATE users SET role = %s WHERE id = %s", (new_role, user_id_to_modify))
                    mysql.connection.commit()
                    flash(f"User ID {user_id_to_modify} role updated to '{new_role}'.", 'success')
                else:
                    flash("Invalid role selected.", 'error')
            elif action == 'delete_user':
                # Prevent deleting the last admin account
                cur.execute("SELECT role FROM users WHERE id = %s", (user_id_to_modify,))
                target_user_role = cur.fetchone()
                if target_user_role and target_user_role[0] == 'admin':
                    cur.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
                    num_admins = cur.fetchone()[0]
                    if num_admins <= 1:
                        flash("Cannot delete the last administrator account.", 'error')
                        return redirect(url_for('admin_manage_users'))

                cur.execute("DELETE FROM users WHERE id = %s", (user_id_to_modify,))
                mysql.connection.commit()
                flash(f"User ID {user_id_to_modify} deleted successfully.", 'success')
            else:
                flash("Invalid action provided.", 'error')
        except Exception as e:
            mysql.connection.rollback()
            flash(f"An error occurred during user management: {e}", 'error')
            app.logger.error(f"Manage users action error: {e}")
        
        return redirect(url_for('admin_manage_users'))

    # GET request logic (display users)
    cur.execute("SELECT id, aadhar, username, role, created_at FROM users ORDER BY created_at DESC")
    users_data = cur.fetchall()
    cur.close()
    
    display_users = []
    for user_row in users_data:
        user_id = user_row[0]
        identifier = user_row[1] if user_row[1] else user_row[2] # Identifier (Aadhaar or Username)
        role = user_row[3]
        created_at = user_row[4]
        display_users.append((user_id, identifier, role, created_at.strftime('%Y-%m-%d %H:%M:%S')))
        
    return render_template('manage_users.html', users=display_users)

@app.route('/admin/settings')
def admin_settings():
    # Enforce admin role for access
    if not is_logged_in('admin'):
        flash("Access Denied: You must be logged in as an administrator.", 'error')
        return redirect(url_for('login'))
    
    return render_template('admin_settings.html')

# --- Document Details (Accessible to Admin, Verifier, User if owner) ---
@app.route('/document_details/<int:doc_id>')
def document_details(doc_id):
    # Ensure user is logged in
    if not ('role' in session and session['id']):
        flash("Please log in to view document details.", 'error')
        return redirect(url_for('login'))

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    # Fetch all details for the document
    cur.execute("SELECT id, user_id, filename, token, status, timestamp, blockchain_tx_id, blockchain_timestamp_on_chain FROM documents WHERE id = %s", (doc_id,))
    document = cur.fetchone()
    cur.close()

    if not document:
        flash("Document not found.", 'error')
        # Redirect based on the user's role if document not found
        if session['role'] == 'admin':
            return redirect(url_for('admin_view_documents'))
        elif session['role'] == 'user':
            return redirect(url_for('user_dashboard'))
        elif session['role'] == 'verifier':
            return redirect(url_for('verifier_dashboard'))
        else:
            return redirect(url_for('home'))

    # Authorization check: Admin or Verifier can see any doc details, User can only see their own
    if session['role'] == 'admin' or \
       session['role'] == 'verifier' or \
       (session['role'] == 'user' and session['id'] == document['user_id']):
        
        # Format timestamps for display
        document['timestamp_str'] = document['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
        if document['blockchain_timestamp_on_chain']:
            document['blockchain_timestamp_on_chain_str'] = document['blockchain_timestamp_on_chain'].strftime('%Y-%m-%d %H:%M:%S')
        else:
            document['blockchain_timestamp_on_chain_str'] = 'N/A'

        # Generate Blockchain Explorer URL
        if document['blockchain_tx_id']:
            document['blockchain_explorer_url'] = f"https://sepolia.etherscan.io/tx/{document['blockchain_tx_id']}"
        else:
            document['blockchain_explorer_url'] = None

        return render_template('document_details.html', document=document)
    else:
        flash("Unauthorized: You do not have permission to view this document.", 'error')
        return redirect(url_for(f"{session['role']}_dashboard")) # Redirect to their own dashboard

# --- Document Download ---
@app.route('/download_document/<string:filename>')
def download_document(filename):
    # Ensure user is logged in
    if not ('role' in session and session['id']):
        flash("Please log in to download documents.", 'error')
        return redirect(url_for('login'))

    cur = mysql.connection.cursor()
    # Find the document by filename to check its owner and status
    cur.execute("SELECT user_id, id, status FROM documents WHERE filename = %s", (filename,))
    doc_info = cur.fetchone()
    cur.close()

    if not doc_info:
        flash("Document not found in system records.", 'error')
        # Redirect based on the user's role if document not found
        if session['role'] in ['admin', 'verifier', 'user']:
            return redirect(url_for(f"{session['role']}_dashboard"))
        return redirect(url_for('home'))

    doc_owner_id = doc_info[0]
    doc_status = doc_info[2]

    # Authorization check: Admin/Verifier can download any, User only their own and if status allows
    if session['role'] == 'admin' or \
       session['role'] == 'verifier' or \
       (session['role'] == 'user' and session['id'] == doc_owner_id and doc_status in ['Verified', 'Issued']):
        try:
            # Serve the file from the secure UPLOAD_FOLDER
            return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
        except FileNotFoundError:
            flash("File not found on server storage. It might have been deleted.", 'error')
            app.logger.error(f"File download failed: {filename} not found in {app.config['UPLOAD_FOLDER']}.")
            if 'HTTP_REFERER' in request.headers: # Try to go back to previous page
                return redirect(request.headers['HTTP_REFERER'])
            return redirect(url_for('home'))
    else:
        flash("Unauthorized: You do not have permission to download this file or its status does not permit download.", 'error')
        return redirect(url_for(f"{session['role']}_dashboard"))


# --- Verifier Routes ---
@app.route('/verifier', methods=['GET', 'POST'])
def verifier_dashboard():
    # Enforce verifier role for access
    if not is_logged_in('verifier'):
        flash("Access Denied: You must be logged in as a verifier.", 'error')
        return redirect(url_for('login'))

    cur = mysql.connection.cursor()
    if request.method == 'POST':
        doc_id = request.form['document_id']
        action = request.form['action']
        
        # Determine new status based on action
        if action == 'Approve':
            new_status = 'Verified'
        elif action == 'Reject':
            new_status = 'Rejected'
        else:
            flash("Invalid action for document.", 'error')
            return redirect(url_for('verifier_dashboard')) 
        
        try:
            # Update document status in the database
            cur.execute("UPDATE documents SET status = %s WHERE id = %s", (new_status, doc_id))
            mysql.connection.commit()
            flash(f"Document ID {doc_id} has been {new_status}.", 'success')
        except Exception as e:
            mysql.connection.rollback()
            flash(f"Failed to update document status: {e}", 'error')
            app.logger.error(f"Verifier action error: {e}")
        return redirect(url_for('verifier_dashboard')) # Redirect to refresh dashboard

    # Fetch documents with 'Pending' status for approval (GET request)
    cur.execute("SELECT id, filename, token, status FROM documents WHERE status = 'Pending' ORDER BY timestamp DESC")
    documents = cur.fetchall()
    cur.close()

    return render_template('verifier_dashboard.html', identifier=session['id'], documents=documents)

@app.route('/verifier/verify-token', methods=['GET', 'POST'])
def verify_token():
    # Enforce verifier role for access
    if not is_logged_in('verifier'):
        flash("Access Denied: You must be logged in as a verifier.", 'error')
        return redirect(url_for('login'))

    result_message = None
    if request.method == 'POST':
        # Retrieve uploaded file and the digitoken from the form
        uploaded_file = request.files.get('file')
        input_digitoken = request.form.get('digitoken')

        # Basic validation
        if not uploaded_file or uploaded_file.filename == '':
            flash("No document file selected for verification.", 'error')
            return redirect(url_for('verify_token'))
        
        if not input_digitoken:
            flash("Please enter the Document Digitoken (SHA-256 Hash).", 'error')
            return redirect(url_for('verify_token'))

        if not allowed_file(uploaded_file.filename):
            flash(f"Invalid file type. Allowed types are: {', '.join(app.config['ALLOWED_EXTENSIONS'])}", 'error')
            return redirect(url_for('verify_token'))

        try:
            # Generate SHA-256 hash of the uploaded file
            file_content = uploaded_file.read()
            uploaded_file_hash = hashlib.sha256(file_content).hexdigest()

            cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor) # Use DictCursor
            # Look up document in database using the provided digitoken
            cur.execute("SELECT id, filename, user_id, status, blockchain_tx_id, blockchain_timestamp_on_chain FROM documents WHERE token = %s", (input_digitoken,))
            match = cur.fetchone()
            cur.close()

            if match:
                # Document found by token. Now compare hashes.
                if uploaded_file_hash == match['token']: # Compare uploaded file's hash with stored token
                    flash(f"✅ VERIFIED! Document hash matches official record.", 'success')
                    
                    # Prepare display message with full details
                    explorer_link = ""
                    if match['blockchain_tx_id']:
                        explorer_url = f"https://sepolia.etherscan.io/tx/{match['blockchain_tx_id']}"
                        explorer_link = f"<br><a href='{explorer_url}' target='_blank' style='color: var(--accent-blue); text-decoration: none;'>View on Blockchain Explorer <i class='fas fa-external-link-alt'></i></a>"

                    result_message = (
                        f"**Document ID:** {match['id']}<br>"
                        f"**Filename:** '{match['filename']}'<br>"
                        f"**Issued For User ID:** '{match['user_id']}'<br>"
                        f"**Official Status:** '{match['status']}'"
                        f"{explorer_link}"
                    )
                    # Add button to view full details
                    result_message += f"<br><br><a href='{url_for('document_details', doc_id=match['id'])}' class='btn' style='background-color: var(--secondary-blue);'><i class='fas fa-info-circle'></i> View Full Details</a>"

                else:
                    flash("❌ TAMPERED! Document hash does NOT match the provided digitoken. The document may have been altered.", 'error')
                    result_message = (
                        "**Verification Failed:** The uploaded document's hash does not match the official digitoken. "
                        "This indicates potential tampering or an incorrect file/token combination."
                    )
            else:
                flash("❓ DIGITOKEN NOT FOUND. The provided digitoken is not registered in the system. Possible unregistered document or invalid token.", 'warning')
                result_message = (
                    "**Verification Failed:** The provided digitoken does not correspond to any official document record. "
                    "Please ensure the token is correct and the document was officially issued."
                )
        except Exception as e:
            flash(f"An unexpected error occurred during verification: {e}", 'error')
            app.logger.error(f"File verification error: {e}")
            result_message = "Error during verification. Please try again."
    
    return render_template('verify_token.html', result_message=result_message)

@app.route('/verifier/activity-logs')
def verifier_activity_logs():
    # Enforce verifier role for access
    if not is_logged_in('verifier'):
        flash("Access Denied: You must be logged in as a verifier.", 'error')
        return redirect(url_for('login'))
    
    cur = mysql.connection.cursor()
    # Fetch recent document status changes by verifiers (Verified, Rejected, Tampered)
    cur.execute("SELECT user_id, filename, token, status, timestamp, blockchain_tx_id FROM documents WHERE status IN ('Verified', 'Rejected', 'Tampered') ORDER BY timestamp DESC LIMIT 20")
    recent_verifications = cur.fetchall()

    # Fetch recent verifier login history
    cur.execute("SELECT user_identifier, user_role, login_time FROM logins WHERE user_role = 'verifier' ORDER BY login_time DESC LIMIT 10")
    verifier_logins_data = cur.fetchall()

    recent_verifications_display = []
    for rv_entry in recent_verifications:
        user_id, filename, token, status, timestamp, blockchain_tx_id = rv_entry
        recent_verifications_display.append((user_id, filename, token, status, timestamp.strftime('%Y-%m-%d %H:%M:%S'), blockchain_tx_id))

    verifier_logins_display = []
    for vl_entry in verifier_logins_data:
        identifier, role, login_time = vl_entry
        verifier_logins_display.append((identifier, role, login_time.strftime('%Y-%m-%d %H:%M:%S')))
    
    cur.close()

    return render_template('verifier_activity_logs.html',
                           recent_verifications=recent_verifications_display,
                           verifier_logins=verifier_logins_display)

# --- User Routes ---
@app.route('/user')
def user_dashboard():
    # Enforce user role for access
    if not is_logged_in('user'):
        flash("Access Denied: You must be logged in as a user.", 'error')
        return redirect(url_for('login'))
    
    cur = mysql.connection.cursor()
    # Fetch documents specifically issued to the logged-in user (by Aadhaar)
    cur.execute("SELECT id, filename, token, status, timestamp, blockchain_tx_id FROM documents WHERE user_id = %s ORDER BY timestamp DESC", (session['id'],))
    documents_data = cur.fetchall()
    cur.close()

    documents_display = []
    for doc_row in documents_data:
        doc_id, filename, token, status, timestamp, blockchain_tx_id = doc_row
        documents_display.append((doc_id, filename, token, status, timestamp.strftime('%Y-%m-%d %H:%M:%S'), blockchain_tx_id))

    return render_template('user_dashboard.html', identifier=session['id'], documents=documents_display)

@app.route('/upload', methods=['GET', 'POST'])
def upload_document():
    # This route is explicitly disabled for general users as per your new logic
    if not is_logged_in('user'):
        flash("Access Denied: You must be logged in as a user.", 'error')
        return redirect(url_for('login'))
    
    if request.method == 'GET':
        flash("To view official documents issued to you, please check your dashboard. Document issuance is handled by administrators.", 'info')
        return redirect(url_for('user_dashboard'))

    # If a POST request somehow makes it here (e.g., direct form submission without GET first)
    flash("Unauthorized action: Users cannot upload official documents directly. Please check your dashboard for issued documents.", 'error')
    return redirect(url_for('user_dashboard'))

if __name__ == '__main__':
    # Initial setup for UPLOAD_FOLDER
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])


    app.run(debug=True) 