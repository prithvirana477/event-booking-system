from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    event = db.Column(db.String(100), nullable=False)
    tickets = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    date = db.Column(db.String(50), nullable=False)
    location = db.Column(db.String(100), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('admin_panel'))
        else:
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/events')
def events():
    events = Event.query.all()
    return render_template('events.html', events=events)

@app.route('/booking', methods=['GET', 'POST'])
@login_required
def booking():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        event_name = request.form.get('event')
        tickets = request.form.get('tickets')
    
        new_booking = Booking(name=name, email=email, event=event_name, tickets=tickets, user_id=current_user.id)
        db.session.add(new_booking)
        db.session.commit()
    
        return render_template('success.html', name=name, email=email, event=event_name, tickets=tickets)
    
    events = Event.query.all()
    return render_template('booking.html', events=events)

@app.route('/my_bookings')
@login_required
def my_bookings():
    bookings = Booking.query.filter_by(user_id=current_user.id).all()
    return render_template('my_bookings.html', bookings=bookings)

@app.route('/all_bookings')
@login_required
def all_bookings():
    bookings = Booking.query.all()
    return render_template('all_bookings.html', bookings=bookings)

@app.route('/event_list')
def event_list():
    events = Event.query.all()
    return render_template('event_list.html', events=events)

@app.route('/admin')
@login_required
def admin_panel():
    return render_template('admin_add_event.html')

@app.route('/admin/add_event', methods=['POST'])
@login_required
def add_event():
    name = request.form.get('name')
    date = request.form.get('date')
    location = request.form.get('location')
    
    new_event = Event(name=name, date=date, location=location)
    db.session.add(new_event)
    db.session.commit()
    
    return redirect(url_for('events'))

@app.route('/admin/events')
@login_required
def admin_events():
    events = Event.query.all()
    return render_template('admin_events.html', events=events)

@app.route('/admin/delete_event/<int:event_id>')
@login_required
def delete_event(event_id):
    event_to_delete = Event.query.get_or_404(event_id)
    try:
        db.session.delete(event_to_delete)
        db.session.commit()
        return redirect(url_for('admin_events'))
    except:
        return 'There was a problem deleting that event'

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/about')
def about():
    return render_template('about.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)