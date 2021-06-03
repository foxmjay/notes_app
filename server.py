from bottle import route, run, template ,static_file, redirect , request, response
import os
import json
from pymongo import MongoClient
from bson.objectid import ObjectId
import hashlib
import jwt
import os
import datetime
os.environ['TZ'] = 'Africa/Casablanca'

client = MongoClient()
db=client.notes_app

SECRET_KEY = "hkBxrbZ9Td4QEwgRewV6gZSVH4q78vBia4GBYuqd09SsiMsIjH"

def token_required(func):
    def wrapper():
        try:
            if "TOKEN" in request.query and "USERID" in request.query :
                token = request.query['TOKEN']
                userid = request.query['USERID']
                try:
                    data = jwt.decode(token,SECRET_KEY, algorithms=['HS256'])
                    user=db.users.find_one({"token":token,"_id":ObjectId(userid)})
                    if user :
                        return func()
                    else :
                        return_data = {"error": "1","message": "Invalid Token for the user" }
                        response.content_type="application/json"
                        response.status=401
                except jwt.exceptions.ExpiredSignatureError:
                    return_data = { "error": "1","message": "Token has expired" }
                    response.content_type="application/json"
                    response.status=401
                except:  
                    return_data = {"error": "2", "message": "Invalid Token" }
                    response.content_type="application/json"
                    response.status=401
            else:
                return_data = {"error" : "3", "message" : "TOKEN and USERID are required"}
                response.content_type="application/json"
                response.status=401
        except Exception as e:
            return_data = { "error" : "4","message" : "An error occured" }
            response.content_type="application/json"
            response.status=500

        return json.dumps(return_data)
    return wrapper

def password_hash(password):

    salt= os.urandom(32)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'),salt,100000)
    return salt+key
    
def verif_password_hash(password,key):
    hash_key = hashlib.pbkdf2_hmac('sha256',password.encode('utf-8'),key[:32],100000)
    return key[32:] == hash_key


@route('/')
def home():
    user_id = request.get_cookie("user_id")
    username = request.get_cookie("username")
    token = request.get_cookie("token")
    if user_id and username and token :
        user_details = {'token':token,'username':username, 'user_id':user_id }
        return template('dashboard.html',user_details)
    else :
        redirect("/login")

@route('/static/<filepath:path>')
def callback(filepath):
    static_path = os.path.dirname(os.path.realpath(__file__))
    return static_file(filepath, root=os.path.join(static_path,"static"))

@route('/login')
def login():  
    return template('login.html')


@route('/authentication', method='POST')
def authentication():
    username = request.json['username']
    password = request.json['password']

    user=db.users.find_one({"username":username})
    if user :        
        if verif_password_hash(password,user['password']) :
            timeLimit= datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
            
            payload = {"user_id": username,"exp":timeLimit}
            token = jwt.encode(payload,SECRET_KEY,algorithm="HS256")
            db.users.update_one(user,{"$set" : {"token":token}})

            response.set_cookie("username",user['username'],domain="localhost",expires=timeLimit)
            response.set_cookie("user_id",str(user['_id']),domain="localhost",expires=timeLimit)
            response.set_cookie("token",token,domain="localhost",expires=timeLimit)

            return_data = {
                 "error": "0",
                 "message": "Success",
                 "token": token,
                 "expire_time": f"{timeLimit}"
            }
        else :
            return_data = {"error": "1", "message": "Fail", "token": "","expire_time": ""}
    else :
        return_data = {"error": "2", "message": "User doesn't exist","token": "","expire_time": ""}        
    return json.dumps(return_data)


@route('/logout')
def logout():
    user_id = request.get_cookie("user_id")
    user=db.users.find_one({"_id":ObjectId(user_id)})
    db.user.update_one(user,{"$set" : {"token":""}})

    response.delete_cookie("username")
    response.delete_cookie("user_id")
    response.set_cookie("token","")

    redirect("/login")

@route('/register')
def login():  
    return template('register.html')

@route('/register', method='POST')
def register_post():
    username = request.json['username']
    password = request.json['password']

    user=db.users.find_one({"username":username})
    if user :
        return_data = { "error": "1", "message": "User exists"}
    else :
        
        password = password_hash(password)
        db.users.insert_one({"username":username,"password":password,"token":""})
        return_data = { "error": "0", "message": "Success"}
        
    return json.dumps(return_data)



@route('/api/addnote' , method="POST")
def apiAddNote():
    user_id = request.get_cookie("user_id")
    user=db.users.find_one({"_id": ObjectId(user_id)})
    if user :
        data = request.json
        data['user_id']=ObjectId(user_id)
        db.notes.insert_one(data)
        return {"error": "0","message":"Success"}
    else :
        return {"error": "1","message":"Fail"}


@route('/api/listnotes',method="GET")
@token_required
def apiListNotes():
    user_id = request.get_cookie("user_id")
    notes=db.notes.find({'user_id':ObjectId(user_id)})
    #list_notes = list(notes)    
    list_notes = [ {'_id':str(ll['_id']),'title':ll['title'],'description':ll['description']} for ll in notes ]
    return json.dumps({"notes":list_notes})


@route('/api/updatenote' , method="POST")
def apiUpdateNote():
    data=request.json
    note=db.notes.find_one({"_id": ObjectId(data['_id'])})
    if note :
        db.notes.update_one(note,{"$set" : {"title":data['title'],"description":data['description']}})
        return {"error": "0","message":"Success"}
    else :
        return {"error": "1","message":"Fail"}


@route('/api/deletenote' , method="POST")
def apiDeleteNote():
    id=request.json['id']
    print(id)
    note=db.notes.find_one({"_id": ObjectId(id)})
    if  note :
        db.notes.delete_one(note)
        return {"error": "0","message":"Success"}
    else :
        return {"error": "1","message":"Fail"}



if __name__ == "__main__":
    run(host='localhost', port=8080, debug=True)