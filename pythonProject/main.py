from flask import Flask, render_template, request, redirect, flash
from flask_mysqldb import MySQL
import yaml
from flask_login import UserMixin, LoginManager, login_user, login_required, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
import secrets, os, time, hashlib
from werkzeug.utils import secure_filename

secret = secrets.token_urlsafe(32)
app = Flask(__name__)
app.secret_key = secret #no funciona
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'#tampoco funciona

#inicio sqlalchemy
@app.shell_context_processor
def make_shell_context():
    return { 'db': db, 'User': User}

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:1234Omega!@localhost/raventhree'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    type = db.Column(db.String(1), nullable=False)

class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    password = db.Column(db.String(120), unique=False, nullable=False)

    def __repr__(self):
        return '<User %r>' % self.username



#fin sqlalchemy

db.create_all()

#admin = User(username='admin', email='admin@example.com')
#guest = User(username='guest', email='guest@example.com')

#db.session.add(admin)
#db.session.add(guest)
#db.session.commit()
User.query.all()

@app.route('/', methods=['GET', 'POST'])
def index():

    return render_template('index.html')
@app.route('/users')
def users():
    users = User.query.all()

    for user in users:
        print(user.username)
        print(f"<id={user.id}, username={user.username}>")
    return(render_template('users.html'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        userDetails = request.form
        name = userDetails['name']
        email = userDetails['email']
        password = userDetails['password']
        type = userDetails['type']
        #DELETE ALL
        #users = User.query.all()
        #passes = Password.query.all()
        # for user in users:
        #     db.session.delete(user)
        # for pas in passes:
        #     db.session.delete(pas)

        user = User(username=name, email=email, type=type)
        pas = Password(password=password)

        db.session.add(user)
        db.session.add(pas)
        db.session.commit()
        #return 'success'
        return redirect('/users')
    return(render_template('register.html'))

@app.route('/login', methods=['GET', 'POST'])
def login():

        if request.method == "POST":
            user = User.query.filter_by(email=request.form.get('email'))
            pas =  Password.query.filter_by(password=request.form.get('password'))
            if user[0].id == pas[0].id:
                login_user(user[0])
                flash('Logged in successfully')
                next = request.args.get('next')
                return redirect(next or app.url_for('dashboard'))
            else:
                flash('Wrong login')
        return render_template('login.html')


if os.name == 'nt':
    path = "C:/SGDF"
    if not os.path.exists(path):
        os.makedirs(path)
    app.config["IMAGE_UPLOADS"] = path
    print("windows")
else:
    path = "/opt/SGDF"
    if not os.path.exists(path):
        os.makedirs(path)
    app.config["IMAGE_UPLOADS"] = path
    print("linux")
app.config["ALLOWED_IMAGE_EXTENSIONS"] = ["JPEG", "JPG", "PNG", "GIF", "PPT", "PPTX", "DOC", "DOCX", "TXT"]
app.config["MAX_IMAGE_FILESIZE"] = 0.5 * 1024 * 1024

def allowed_image(filename):
    if not "." in filename:
        return False
    ext = filename.rsplit(".", 1)[1]
    if ext.upper() in app.config["ALLOWED_IMAGE_EXTENSIONS"]:
        return True
    else:
        return False


def allowed_image_filesize(filesize):
    if int(filesize) <= app.config["MAX_IMAGE_FILESIZE"]:
        return True
    else:
        return False


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        if request.files:
            if "filesize" in request.cookies:
                if not allowed_image_filesize(request.cookies["filesize"]):
                    print("Filesize exceeded maximum limit")
                    return redirect(request.url)
                image = request.files["image"]
                print(image.filename)
                if image.filename == "":
                    print("No filename")
                    return redirect(request.url)
                if allowed_image(image.filename):
                    filename = secure_filename(image.filename)
                    image.save(os.path.join(app.config["IMAGE_UPLOADS"], filename))
                    print("Image saved")
                    return redirect(request.url)
                else:
                    print("That file extension is not allowed")
                    return redirect(request.url)
        else:
            print("fail")
    return render_template("upload.html")

def make_tree(path):
    tree=[]

    nameList = os.listdir(path)
    for name in nameList:
        statinfo = os.stat(path+"/"+name)
        fileSize = statinfo.st_size
        sha256_hash = hashlib.sha256()
        with open(path+"/"+name, "rb") as f:
            # Read and update hash string value in blocks of 4K
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
            sha=sha256_hash.hexdigest()
        ph=("Filename: "+name+" filesize:"+ str(fileSize)+ "Bytes" + " sha256: " + sha + " last modified: %s" % time.ctime(os.path.getmtime(path+"/"+name)))
        print(ph)
        tree.append(ph)
    return tree



@app.route('/list')
def dirtree():
    return render_template('list.html', tree=make_tree(path))

@app.route('/delete', methods=["GET", "POST"])
def delete():
    if request.method == "POST":
        print("*"+str(request.form.get('name')))
        filee=request.form.get('name')
        if os.path.exists(filee) and os.path.realpath(filee).startswith(path): #para que no se borren ficheros indeseados
            os.remove(filee)
        else:
            print("The file does not exist")
            print(filee)
        return render_template('success')



if __name__ == '__main__':
    app.run(debug=True)

