from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime 
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from sqlalchemy.orm import defaultload
from wtforms import StringField, PasswordField, SubmitField
from wtforms.fields.core import IntegerField
from wtforms.validators import InputRequired, Length , ValidationError
from flask_bcrypt import Bcrypt, bcrypt
app = Flask(__name__)
bcrypt= Bcrypt(app) #for encroption of password note that the password stored in db will be in encripted format
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hotel.db'
app.config['SECRET_KEY']="TOKYO_12"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager= LoginManager() #This object is used to hold the settings used for logging in. Instances of LoginManager are *not* bound to specific apps, so you can create one in the main body of your code and then bind it to your app in a factory function.
login_manager.init_app(app) #configure app for api call
login_manager.login_view="login"
@login_manager.user_loader #user_loaderThis sets the callback for reloading a user from the session. The function you set should take a user ID (a unicode) and return a user object, or None if the user does not exist.
def load_user(user_id):
    return User.query.get(int(user_id))

#this is User table definition for db table
class User(db.Model, UserMixin):
    id =db.Column(db.Integer, nullable=False, primary_key=True)
    username=db.Column(db.String(200), nullable=False, unique= True)
    password=db.Column(db.String(200), nullable=False)
# this is purely for register form
class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(),Length(min=4, max=30)], render_kw={"placeholder": "Username"}) #check if it is input string field not empty
    password = PasswordField(validators=[InputRequired(),Length(min=4, max=30)], render_kw={"placeholder": "Password"}) #passwordfield make sure it is not empty and masked
   
    submit = SubmitField("Register") #submit for saving the details check the syntax in html

    def validate_user(self, username):
        existing_username = User.query.filter_by(username=username.data).first() #check user like this exists if yes then error 
        if existing_username:
            raise ValidationError(
                "This user for this mail id already exist Please choose different mail id")


#class for validation
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(),
    Length(min=4, max=30)], render_kw={"placeholder": "Username"}) #the value entered should not be empty and string
    password = PasswordField(validators=[InputRequired(),
    Length(min=4, max=30)], render_kw={"placeholder": "Password"}) #password masked field

    submit= SubmitField("Login")

@app.route("/", methods=['GET','POST'])
def BasePage():     
    return render_template('base.html')

@app.route("/register", methods=['GET','POST'])
def Register():
    form= RegisterForm() # contains the data posted by enduser by post request
    if form.validate_on_submit(): #validate only if the form is submitted. 
        hashed_password=bcrypt.generate_password_hash(form.password.data) #hash the password using byscript
        new_username=User(username=form.username.data, password=hashed_password)
        db.session.add(new_username) #add the details in USer table
        db.session.commit() #commit the changes
        return redirect('/login') #once Register successful ask him to login hence redirect to login
    return render_template('register.html', form=form) #if something goes wrong then render the same page again
@app.route("/login", methods=['GET','POST'])
def login():
    form=LoginForm()
    if form.validate_on_submit():
        user= User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect("/hotel")

    return render_template('login.html', form=form)
  
class Hotel(db.Model):
    sno=db.Column(db.Integer, primary_key=True)
    hotelname = db.Column(db.String(200), nullable=False)
    City =db.Column(db.String(200),nullable=False)
    number_of_guests = db.Column(db.Integer,nullable=False)
    Year_Visited= db.Column(db.Integer)
    date_created= db.Column(db.DateTime, default=datetime.utcnow)
    Services_provided = db.Column(db.String(2000),nullable=False)
    Country =db.Column(db.String(100), nullable=False)
    Address = db.Column(db.String(3000), nullable=False)
    review=db.Column(db.String(20000), nullable=False)
    reviewerName=db.Column(db.String(2000), nullable=False)
    rating=db.Column(db.Integer, nullable=False)

@app.route("/hotel", methods=['GET','POST'])
def HelloWorld():
    if request.method=="POST":
        hotelname=request.form['hotelname']
        City=request.form['City']
        number_of_guests=request.form['number_of_guests']
        Year_Visited=request.form['Year_Visited']
        Services_provided=request.form['Services_provided']
        Country=request.form['Country']
        Address=request.form['Address']
        review=request.form['review']
        reviewerName=request.form['reviewerName']
        rating=request.form['rating']
        hotel=Hotel(hotelname=hotelname, City=City,number_of_guests=number_of_guests,Year_Visited=Year_Visited, Services_provided=Services_provided,Country=Country,Address=Address,review=review,reviewerName=reviewerName,rating=rating)
        print(hotel)
        db.session.add(hotel)
        db.session.commit()
    allhotel=Hotel.query.all()

    return render_template('index.html', allhotel=allhotel)
@app.route('/logout',methods=['GET','POST'])
@login_required #If you decorate a view with this, it will ensure that the current user is logged in and authenticated before calling the actual view. (If they are not, it calls the LoginManager.unauthorized callback.
def logout():
    logout_user()
    return redirect('/login')   
@app.route("/update/<int:sno>", methods=['GET','POST'])
def update(sno):
    if request.method=="POST":
        hotelname=request.form['hotelname']
        City=request.form['City']
        number_of_guests=request.form['number_of_guests']
        Year_Visited=request.form['Year_Visited']
        Services_provided=request.form['Services_provided']
        Country=request.form['Country']
        Address=request.form['Address']
        review=request.post['review']
        reviewerName=request.form['reviewerName']
        rating=request.form['rating']
        hotel=Hotel.query.filter_by(sno=sno).first()
        hotel.hotelname=hotelname
        hotel.City=City
        hotel.number_of_guests=number_of_guests
        hotel.Year_Visited=Year_Visited
        hotel.Services_provided=Services_provided
        hotel.Country=Country
        hotel.Address=Address
        hotel.review=review
        hotel.reviewerName=reviewerName
        hotel.rating=rating
        db.session().add(hotel)
        db.session.commit()
        return redirect("/hotel")
    hotel=Hotel.query.filter_by(sno=sno).first()
    return render_template('update.html', hotel=hotel)
@app.route("/delete/<int:sno>")
def delete(sno):
    hotel=Hotel.query.filter_by(sno=sno).first()
    db.session().delete(hotel)
    db.session.commit()
    return redirect("/hotel")
from flask import g
from flask.sessions import SecureCookieSessionInterface
from flask_login import user_loaded_from_header

class CustomSessionInterface(SecureCookieSessionInterface):
    """Prevent creating session from API requests."""
    def save_session(self, *args, **kwargs):
        if g.get('login_via_header'):
            return
        return super(CustomSessionInterface, self).save_session(*args, **kwargs)

app.session_interface = CustomSessionInterface()

@user_loaded_from_header.connect
def user_loaded_from_header(self, user=None):
    g.login_via_header = True

if __name__ == "__main__":
    app.run(debug=True)
