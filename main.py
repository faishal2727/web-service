from crypt import methods
from flask import Flask, render_template, current_app, make_response, request
from flask_mail import Mail, Message
from flask_restx import Resource, Api, reqparse
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash,check_password_hash

import jwt

app = Flask(__name__)
api = Api(app)

app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:@127.0.0.1:3306/capstone"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True

app.config['JWT_SECRET_KEY'] = "Rahasia"
app.config['MAIL_SERVER'] = "smtp.googlemail.com"
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = "corolautjawa@gmail.com"
app.config['MAIL_PASSWORD'] = "jrqwpwlfqzrwbeim"
app.config['JSON_SORT_KEYS'] = False

db = SQLAlchemy(app)

mail = Mail(app)




class Gas(db.Model):
    id = db.Column(db.Integer(),primary_key=True,nullable=False)
    gasName = db.Column(db.String(100),nullable=False)
    noHp = db.Column(db.String(100),nullable=False)
    minStock = db.Column(db.String(100),nullable=False)
    size = db.Column(db.String(100),nullable=False)
    def serialize(row):
        return {
            "id" : str(row.id),
            "gasName" : row.gasName,

        } 


parser4ListGas = reqparse.RequestParser()
parser4ListGas.add_argument('gasName', type=str, help='gasName', location='json', required=True)
parser4ListGas.add_argument('noHp', type=str, help='noHp', location='json', required=True)
parser4ListGas.add_argument('minStock', type=str, help='minStock', location='json', required=True)
parser4ListGas.add_argument('size', type=str, help='size', location='json', required=True)

@api.route('/list/gas')
class NewGas(Resource):
    @api.expect(parser4ListGas)
    def post(self):
        args = parser4ListGas.parse_args()
        gasName = args['gasName']
        noHp = args['noHp']
        minStock = args['minStock']
        size = args['size']

        try:
            gas = Gas(gasName=gasName, noHp=noHp, minStock=minStock, size=size)

            db.session.add(gas)
            db.session.commit()

            return {
                'message' : "Succes"
            }, 201
        except Exception as e:
            print(e)
            return {
                'message' : f"Error {e}"
            }, 500


# parser4Gas = reqparse.RequestParser()
# parser4Gas.add_argument('Authorization', type=str, help='', location='headers', required=True) 

@api.route("/gas")
class GetAllGass(Resource):
    def get(self):
        # args = parser4Gas.parse_args()
        # bearerAuth = args['Authorization']
        # jwtToken = bearerAuth[7:]

        # payload = jwt.decode(jwtToken,"Faizal",algorithms=['HS256'])
        # user = db.session.execute(db.select(Auth).filter_by(email=payload["email"])).first()
        # if not user:
        #     return {
        #         "message" : "Whats??"
        #     },400
        
        try:
            
            student = db.session.execute(db.select(Gas)
            .order_by(Gas.id))

            students = Gas.query.all()
            studentx = [Gas.serialize(x) for x in students]
            
            return make_response(
                {
                    "message":"Success",
                    "data": studentx
                },200
            )
               
        except Exception as e:
            print(f"{e}")
            return {'message': f'Failed {e}'}, 400



class User(db.Model):
    id = db.Column(db.Integer(),primary_key=True,nullable=False)
    name = db.Column(db.String(255),nullable=False)
    email = db.Column(db.String(255),unique=True,nullable=False)
    password = db.Column(db.String(255),nullable=False)
    is_verify = db.Column(db.Integer(),nullable=False)

parser4SignUp = reqparse.RequestParser()
parser4SignUp.add_argument('name', type=str, help='Fullname', location='json', required=True)
parser4SignUp.add_argument('email', type=str, help='Email Address', location='json', required=True)
parser4SignUp.add_argument('password', type=str, help='Password', location='json', required=True)
parser4SignUp.add_argument('re_password', type=str, help='Retype Password', location='json', required=True)

@api.route('/user/signup')
class Registration(Resource):
    @api.expect(parser4SignUp)
    def post(self):
        args = parser4SignUp.parse_args()
        name = args['name']
        email = args['email']
        password = args['password']
        rePassword = args['re_password']

        if(password != rePassword):
            return {'message' : 'Password is not match'}, 400

        user = db.session.execute(db.select(User).filter_by(email=email)).first()

        if(user):
            return {'message' : 'Your email address has been used'}, 409

        try:
            user = User(email=email, name=name, password=generate_password_hash(password), is_verify=False)

            db.session.add(user)
            db.session.commit()

            user_id = user.id
            jwt_secret_key = current_app.config.get("JWT_SECRET_KEY", "Rahasia")

            email_token = jwt.encode({"id": user_id}, jwt_secret_key, algorithm="HS256").decode("utf-8")

            url = f"https://127.0.0.1:5000/user/verify-account/{email_token}"

            data = {
                'name': name,
                'url': url
            }

            sender = "noreply@app.com"
            msg = Message(subject="Verify your email", sender=sender, recipients=[email])
            msg.html = render_template("verify-email.html", data=data)

            mail.send(msg)
            return {
                'message' : "Success create account, check email to verify"
            }, 201
        except Exception as e:
            print(e)
            return {
                'message' : f"Error {e}"
            }, 500

@api.route("/user/verify-account/<token>")
class VerifyAccount(Resource):
    def get(self, token):
        try:
            decoded_token = jwt.decode(token, key="Rahasia", algorithms=["HS256"])
            user_id = decoded_token["id"]
            user = db.session.execute(db.select(User).filter_by(id=user_id)).first()[0]
            
            if not user:
                return {"message": "User not found"}, 404

            if user.is_verify:
                response = make_response(render_template('response.html', success=False, message='Account has been verified'), 400)
                response.headers['Content-Type'] = 'text/html'

                return response

            user.is_verify = True
            db.session.commit()

            response = make_response(render_template('response.html', success=True, message=' your account has been verified!'), 200)
            response.headers['Content-Type'] = 'text/html'

            return response

        except jwt.exceptions.ExpiredSignatureError:
            return {"message": "Token has expired."}, 401

        except (jwt.exceptions.InvalidTokenError, KeyError):
            return {"message": "Invalid token."}, 401

        except Exception as e:
            return {"message": f"Error {e}"}, 500



parser4SignIn = reqparse.RequestParser()
parser4SignIn.add_argument('email', type=str, help='Email Address', location='json', required=True)
parser4SignIn.add_argument('password', type=str, help='Password', location='json', required=True)

@api.route('/user/signin')
class Login(Resource):
    @api.expect(parser4SignIn)
    def post(self):
        args = parser4SignIn.parse_args()
        email = args['email']
        password = args['password']

        if not email or not password :
            return { "message" : "Please type email and passowrd" }, 400

        user = db.session.execute(db.select(User).filter_by(email=email)).first()
        
        if not user :
            return { "message" : "User not found, please do register" }, 400

        if not user[0].is_verify :
            return { "message" : "Accunt not actived, check email for verify" }, 401

        if check_password_hash(user[0].password, password):
            payload = {
                'id' : user[0].id,
                'name' : user[0].name,
                'email' : user[0].email
            }

            jwt_secret_key = current_app.config.get("JWT_SECRET_KEY", "Rahasia")
            print(f"INFO {jwt_secret_key}")
            token = jwt.encode(payload, jwt_secret_key, algorithm="HS256").decode("utf-8")
            return{ 'token' : token }, 200

        else:
            return { "message" : "Wrong password" }


@api.route('/user/current')
class WhoIsLogin(Resource):
    def get(self):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        try:
            decoded_token = jwt.decode(token, key="Rahasia", algorithms=["HS256"])
            user_id = decoded_token["id"]
            user = db.session.execute(db.select(User).filter_by(id=user_id)).first()
            
            if not user:
                return {'message': 'User not found'}, 404

            user = user[0]

            return {
                'status': "Success", 
                'data': {
                    'id': user.id,
                    'name': user.name,
                    'email': user.email
                }
            }, 200

        except jwt.ExpiredSignatureError:
            return {'message': 'Token is expired'}, 401

        except jwt.InvalidTokenError:
            return {'message': 'Invalid token'}, 401



user_parser = reqparse.RequestParser()
user_parser.add_argument('name', type=str, help='Fullname', location='json', required=True)
user_parser.add_argument('email', type=str, help='Email Address', location='json', required=True)

@api.route('/user/update')
class UpdateUser(Resource):
    def put(self):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        try:
            decoded_token = jwt.decode(token, key="Rahasia", algorithms=["HS256"])
            user_id = decoded_token["id"]
            user = db.session.execute(db.select(User).filter_by(id=user_id)).first()
            
            if not user:
                return {'message': 'User not found'}, 404

            user = user[0]

            args = user_parser.parse_args()

            user.name = args['name']
            user.email = args['email']

            db.session.commit()

            try:
                db.session.commit()
                return {'message': 'Profile updated successfully'}, 200
            except:
                db.session.rollback()
                return {'message': 'Profile update failed'}, 400

        except jwt.ExpiredSignatureError:
            return {'message': 'Token is expired'}, 401

        except jwt.InvalidTokenError:
            return {'message': 'Invalid token'}, 401



user_parser = reqparse.RequestParser()
user_parser.add_argument('name', type=str, help='Fullname', location='json', required=True)
user_parser.add_argument('email', type=str, help='Email Address', location='json', required=True)

@api.route('/user/update')
class UpdateUser(Resource):
    def put(self):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        try:
            decoded_token = jwt.decode(token, key="Rahasia", algorithms=["HS256"])
            user_id = decoded_token["id"]
            user = db.session.execute(db.select(User).filter_by(id=user_id)).first()
            
            if not user:
                return {'message': 'User not found'}, 404

            user = user[0]

            args = user_parser.parse_args()

            user.name = args['name']
            user.email = args['email']

            db.session.commit()

            try:
                db.session.commit()
                return {'message': 'Profile updated successfully'}, 200
            except:
                db.session.rollback()
                return {'message': 'Profile update failed'}, 400

        except jwt.ExpiredSignatureError:
            return {'message': 'Token is expired'}, 401

        except jwt.InvalidTokenError:
            return {'message': 'Invalid token'}, 401

forgot_password_parser = reqparse.RequestParser()
forgot_password_parser.add_argument('email', type=str, help='Email Address', location='json', required=True)

@api.route('/user/forgot-password')
class ForgetPassword(Resource):
    def post(self):
        try:
            args = forgot_password_parser.parse_args()
            email = args['email']

            user = db.session.execute(db.select(User).filter_by(email=email)).first()

            if not user:
                return {'message': 'Email does not match any user'}, 404

            jwt_secret_key = current_app.config.get("JWT_SECRET_KEY", "Rahasia")

            email_token = jwt.encode({"id": user[0].id}, jwt_secret_key, algorithm="HS256").decode("utf-8")

            url = f"https://127.0.0.1:5000/user/reset-password/{email_token}"

            sender = "noreply@app.com"
            msg = Message(subject="Reset your password", sender=sender, recipients=[email])
            msg.html = render_template("reset-password.html", url=url)

            mail.send(msg)
            return {'message' : "Success send request, check email to verify"}, 200

        except Exception as e:
            return {"message": f"Error {e}"}, 500


@api.route('/user/reset-password/<token>')
class ViewResetPassword(Resource):
    def get(self, token):
        try:
            decoded_token = jwt.decode(token, key="Rahasia", algorithms=["HS256"])
            user_id = decoded_token["id"]
            user = db.session.execute(db.select(User).filter_by(id=user_id)).first()
            
            if not user:
                return {"message": "User not found"}, 404

            response = make_response(render_template('form-reset-password.html', id=user[0].id), 200)
            response.headers['Content-Type'] = 'text/html'

            return response

        except jwt.exceptions.ExpiredSignatureError:
            return {"message": "Token has expired."}, 401

        except (jwt.exceptions.InvalidTokenError, KeyError):
            return {"message": "Invalid token."}, 401

        except Exception as e:
            return {"message": f"Error {e}"}, 500




reset_password_parser = reqparse.RequestParser()
reset_password_parser.add_argument('id', type=int, required=True, help='User ID is required')
reset_password_parser.add_argument('password', type=str, required=True, help='New password is required')
reset_password_parser.add_argument('confirmPassword', type=str, required=True, help='Confirm password is required')

@api.route('/user/reset-password', methods=['PUT', 'POST'])
class ResetPassword(Resource):
    def post(self):
        args = reset_password_parser.parse_args()
        password = args['password']

        user = db.session.execute(db.select(User).filter_by(id=args['id'])).first()
        if not user:
            return {'message': 'User not found'}, 404

        if password != args['confirmPassword']:
            return {'message': 'Passwords do not match'}, 400

        user[0].password = generate_password_hash(password)

        try:
            db.session.commit()
            response = make_response(render_template('response.html', success=True, message='Password has been reset successfully'), 200)
            response.headers['Content-Type'] = 'text/html'
            return response

        except:
            db.session.rollback()
            response = make_response(render_template('response.html', success=False, message='Reset password failed'), 400)
            response.headers['Content-Type'] = 'text/html'
            return response



            
if __name__ == '__main__':
    app.run(ssl_content='adhoc', debug=True)

