from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
CORS(app)
app.secret_key = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

@app.route('/login', methods=['GET', 'POST', 'OPTIONS'])
def login():
    if request.method == 'OPTIONS':
        response = jsonify({'message': 'Preflight request successful'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        return response

    if request.method == 'POST':
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.fullname
            return jsonify({'success': True, 'message': 'Sikeres bejelentkezés'})
        else:
            return jsonify({'success': False, 'message': 'Hibás bejelentkezési adatok'}), 401
    return jsonify({'error': 'Method not allowed'}), 405

@app.route('/register', methods=['GET', 'POST', 'OPTIONS'])
def register():
    if request.method == 'OPTIONS':
        response = jsonify({'message': 'Preflight request successful'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        return response

    if request.method == 'POST':
        data = request.get_json()
        fullname = data.get('fullname')
        email = data.get('email')
        password = data.get('password')
        confirm_password = data.get('confirm_password')
        
        if password != confirm_password:
            return jsonify({'success': False, 'message': 'A jelszavak nem egyeznek'}), 400
        
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({'success': False, 'message': 'Ez az email cím már regisztrálva van'}), 400
        
        hashed_password = generate_password_hash(password)
        new_user = User(fullname=fullname, email=email, password=hashed_password)
        
        db.session.add(new_user)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Sikeres regisztráció'})
    return jsonify({'error': 'Method not allowed'}), 405

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('http://127.0.0.1:5500/index.html')
    # Opcionálisan visszatérhetünk egy dashboard template-tel is
    return redirect('http://127.0.0.1:5500/index.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)