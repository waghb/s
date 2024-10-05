from flask import Flask,render_template,redirect,url_for,flash,get_flashed_messages
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import SearchField,StringField,SubmitField,PasswordField,IntegerField
from flask_login import LoginManager,login_user,logout_user,UserMixin,current_user,login_required
from wtforms.validators import DataRequired,Length,ValidationError
app=Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///shoe.db'
app.config['SECRET_KEY'] = '19a2ece37732347b99435c59'  


db=SQLAlchemy(app)
bcrypt=Bcrypt(app)
login_manager = LoginManager(app)



class User(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    balance = db.Column(db.Integer, nullable=False, default=0)
    pro = db.relationship('Product', backref='owner', lazy=True)

    @property
    def password_plaintext(self):
        raise AttributeError('Password is not a readable attribute.')

    @password_plaintext.setter
    def password_plaintext(self, plain_text_password):
        self.password = bcrypt.generate_password_hash(plain_text_password).decode('utf-8')

    def check_password(self, attempted_password):
        return bcrypt.check_password_hash(self.password, attempted_password)
    

class Product(db.Model):
    #child class -----have id and foreign key
    id = db.Column(db.Integer(), primary_key=True)
    price = db.Column(db.Integer())
    prodname = db.Column(db.String(50))
    
    owner_id = db.Column(db.Integer(), db.ForeignKey('user.id'))
    category=db.Column(db.String(50),nullable=False)
    image_url = db.Column(db.String(255), nullable=True)


class Register(FlaskForm):
    def validate_name(self, name_to_check):
        user = User.query.filter_by(name=name_to_check.data).first()
        if user:
            raise ValidationError('Username already exists! Please try a different username.')

    name = StringField(label='Name', validators=[Length(min=2, max=10), DataRequired()])
    password = PasswordField(label='Password', validators=[DataRequired()])
    submit = SubmitField(label='Submit')

class LoginForm(FlaskForm):  # Renamed to LoginForm
    name = StringField(label='Name', validators=[Length(min=2, max=10), DataRequired()])
    password = PasswordField(label='Password', validators=[DataRequired()])
    submit = SubmitField(label='Submit')






@app.route('/')
def index():
    return render_template('index.html',user=User)

@app.route('/products')
def products():
    product_list = Product.query.all()  # Fetch all products from the database
    return render_template('products.html', products=product_list)


@app.route('/product/<int:product_id>')
def detail(product_id):
    product = Product.query.get_or_404(product_id)  # Fetch the product based on the ID
    return render_template('product_detail.html', product=product)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()  # Updated form class to LoginForm
    if form.validate_on_submit():
        attempted_user = User.query.filter_by(name=form.name.data).first()
        if attempted_user and attempted_user.check_password(form.password.data):
            login_user(attempted_user)
            flash(f"Success! You are logged in as {attempted_user.name}", category='success')
            return redirect(url_for('index'))
        else:
            flash('Login failed. Please check your username and password.', category='danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = Register()
    if form.validate_on_submit():
        new_user = User(
            name=form.name.data,
            password_plaintext=form.password.data  # Fixed typo here
        )
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful!', category='success')
        return redirect(url_for('index'))  # Changed to redirect after registration
    
    if form.errors:
        for err in form.errors.values():
            flash(f'Error: {err}', category='danger')
    
    return render_template('register.html', form=form)  # Added return statement


@app.route('/account')
@login_required
def account():
    # Pass the current_user object to the account template to display user info
    return render_template('account.html', user=current_user)


@app.route('/purchase/<int:product_id>', methods=['POST'])
@login_required
def purchase(product_id):
    
    product = Product.query.get_or_404(product_id)

 
    if current_user.balance >= product.price:
        
        current_user.balance -= product.price
        product.owner = current_user
        db.session.commit()
        
     
        flash('Purchase successful!', 'success')
    else:
      
        flash('Insufficient balance.', 'danger')

   
    return redirect(url_for('products'))



@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))



if __name__ == '__main__':
    with app.app_context():
       db.create_all()
    app.run(debug=True, port=5000)