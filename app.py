# No importa session y el orden de importar es necesario
from flask import Flask, request, redirect, url_for, render_template, session
from argon2 import PasswordHasher
import os
import sqlite3

app = Flask (__name__)

#error set la llave de session afuera del app == main
app.secret_key = os.urandom(16)
ph = PasswordHasher(hash_len=32, salt_len=16, time_cost=2, memory_cost=102400)

# funciones de hashing y salado
def generate_salt():
     return os.urandom(16)

# error de parametros
def hash_password(password, salt): 
     pepper = b'MySuperSecretPepper'
     password_peppered = password.encode() + pepper
     # es una concatenación
     return ph.hash(password_peppered + salt)

# Rutas
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        salt = generate_salt()
        password_hash = hash_password(password, salt)         # error de falta de parametros
        db.execute('INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)',(username, password_hash, salt))
        db.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
      
        ''' error if user and ph.verify(user['password_hash'], password.encode() + b'MySuperSecretPepper'):
        TypeError: tuple indices must be integers or slices, not str

           error Le falto la sal igual para poder acceder al hash
        '''
        if user and ph.verify(user[2], (password.encode() + b'MySuperSecretPepper') + user[3]):
            session['user_id'] = user[1]
            return redirect(url_for('dashboard'))
        else:
           print('Incorrect username or password')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user_id = session['user_id']
        user = db.execute('SELECT * FROM users WHERE username = ?', (user_id,)).fetchone()
        print(user_id)
        # error accede a una variable NONE
        return render_template('dashboard.html', username=user[1])
    else:
        return redirect(url_for('/'))

# Configuración de la base de datos

db = sqlite3.connect('password.db', check_same_thread=False) # Otro error. Threads 
db.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password_hash TEXT, salt TEXT)')
db.commit()
if __name__ == '__main__':
    app.run(debug=True)

