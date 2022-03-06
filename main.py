from re import L, U
import re
from flask_socketio import SocketIO
from flask_security import Security
from flask import session as ses
from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask.wrappers import Request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exc
from sqlalchemy.orm import query
import sqlite3 
import json,uuid,os,sqlite3
from flask import jsonify
import io
from applications.validation import No_cards_error,Invalid_error
from werkzeug.exceptions import HTTPException
from sqlalchemy.orm import session
import time ,flask_login
from datetime import datetime 
from flask_bcrypt import Bcrypt
from flask_login import UserMixin, login_user, LoginManager,login_required ,logout_user, current_user 


basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///flashcard.sqlite3'
app.config['SECRET_KEY'] = 'secretkey'
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
socketio = SocketIO(app)




login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
@login_manager.user_loader
def user_loader(user_id):
    user = User.query.filter_by(id=user_id).first()
    if user:
        return user
    return None


class deck_info(db.Model):
    Deck_id = db.Column(db.String, primary_key = True, nullable = False)
    Deck_name = db.Column(db.String, nullable = False)
    Deck_location = db.Column(db.String, nullable = False)
    db.UniqueConstraint(Deck_id,Deck_name)

class User(db.Model ,UserMixin):
    id = db.Column(db.Integer, primary_key = True, autoincrement = True, nullable = False)
    Username = db.Column(db.String, nullable = False)
    Password = db.Column(db.String,nullable = False)
    db.UniqueConstraint(id,Username)
    authenticated = db.Column(db.Boolean, default=False)
    last_login = db.Column(db.String)

    def is_authenticated(self):
     return self._authenticated
    

class Dashboard_info(db.Model):
    id = db.Column(db.Integer, primary_key = True, autoincrement = True,nullable = False)
    User_id = db.Column(db.Integer, db.ForeignKey(User.id),nullable = False)
    Deck_id = db.Column(db.String, db.ForeignKey('deck_info.Deck_id'), nullable = False)
    Score = db.Column(db.Integer)
    LastReviewTime = db.Column(db.String)

@app.route('/dashboard')
@login_required
def dashboard(): 
    User_id = ses["User_id"]
    dash = Dashboard_info.query.all()
    Decks = {}
    creds = User.query.get(User_id)
    name = creds.Username
    for d in dash:
        decks = deck_info.query.get(d.Deck_id)
        Decks[d.Deck_id] = decks.Deck_name
    return render_template('dashboard.html', dashboard = dash, User_id = User_id,Username = name, decks=Decks)



@app.route('/login', methods = ['GET','POST'])
def login():
    if(request.method == 'GET'):
        return render_template('login.html')
    else:
        uname = request.form['username']
        password = request.form['password']
        now = datetime.now()
        now = now.strftime("%d/%m/%Y %H:%M:%S")
        try :
         user = db.session.query(User).filter(User.Username == uname).first()
        except Exception as e:
          print(e)
        if user:
            if bcrypt.check_password_hash(user.Password,password):
                ses.permanent = True
                ses["User_id"] = user.id
                # s = '/dashboard'
                User.last_login = now
                db.session.commit()
                if request.form.get('remember'):
                   login_user(user, remember= True)
                else :     
                   login_user(user)
                return redirect(url_for('dashboard'))
            else:
                return redirect('/login/invalid')
        return render_template('invalid.html', argument = 'user')

@app.route('/logout')
def logout():
  logout_user()
  return redirect(url_for('login'))

@app.route('/login/invalid')
def InvalidLogin():
  return render_template('invalid.html', argument = 'login')

@app.route('/invalid/<string:argument>/')
def Invalid(argument):
    User_id = ses["User_id"]
    return render_template('invalid.html', argument = argument)

@app.route('/about.html')
def about():
    return render_template('about.html')

@app.route('/API_documentation.yaml')
def API():
    return render_template('API_documentation.yaml')


@app.route('/signup', methods = ['GET','POST'])
def signup():
    if(request.method == 'GET'):
        return render_template('signup.html')
    else:
        uname = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password)
        creds = User(Username = uname, Password = hashed_password )
        db.session.add(creds)
        db.session.commit()

        return redirect(url_for('login'))

@app.route('/update/<int:User_id>/<string:deck_id>',methods=['PUT'])
def Update(deck_id,User_id):
    if(request.method== 'PUT'):
        data=request.json
        try:
            Dashboard_info.query.filter(Dashboard_info.Deck_id==deck_id ,Dashboard_info.User_id==User_id).one()
        except exc.SQLAlchemyError:
            raise Invalid_error("USER ID", status_code=400)
        if data:
           
            try:
                deck_records= deck_info.query.filter(deck_info.Deck_id==deck_id).one()
           
                location=deck_records.Deck_location
           
                deck_name=deck_records.Deck_name
           
            except exc.SQLAlchemyError:
                raise Invalid_error('Deck_id',status_code=400)
            data_json = io.open(location,'r',encoding='UTF-8').read()
            data_dic=json.loads(data_json)
            for keys in data:
                data_dic["cards"][keys]= data[keys]
            with open(location, "w") as outfile:
                json.dump(data_dic, outfile, indent = 4)
            return data_dic
        else: 
            raise No_cards_error()


@app.route('/update', methods = ['GET','POST'])
def Update_deck():
    if(request.method == 'GET'):
        User_id = ses["User_id"]
        try:
            User.query.filter(User.id==User_id).one()
        except exc.SQLAlchemyError:
            return render_template("Invalid_deck.html",data= "USER ID/DECK ID")
        creds = User.query.get(User_id)
        name = creds.Username        
        return render_template('updatedeck1.html',Username = name)
    else:
        deckId = request.form['deckId']
        cardNo  = request.form['cardno']
        url = '/updatedeck/' + deckId + '/' + str(cardNo)
        return redirect(url)

@app.route('/updatedeck/<string:deckId>/<int:cardNo>', methods = ['GET','POST'])    
def Update_card(deckId,cardNo):
    if(request.method == 'GET'):
        User_id = ses["User_id"]
        try:
            Dashboard_info.query.filter(Dashboard_info.Deck_id==deckId ,Dashboard_info.User_id==User_id).one()
        except exc.SQLAlchemyError:
            return render_template('Invalid_deck.html', data = "USER ID/DECK ID")
        try:
            deck_records= deck_info.query.filter(deck_info.Deck_id==deckId).one()
        except exc.SQLAlchemyError:
                return render_template('Invalid_deck.html', data = "DECK ID")
        deckName=deck_records.Deck_name
        creds = User.query.get(User_id)
        name = creds.Username
        return render_template('updatedeck2.html',cardNo=cardNo,deckName=deckName,Username = name)
    else:
        r = request.form
        r = str(r)
        r = r[20:-2]
        data = str2tupleList(r, cardNo)
        User_id = ses["User_id"]
        if data=={'':''}:
            return render_template('NoCards.html')
        deck_records= deck_info.query.filter(deck_info.Deck_id==deckId).one_or_none()
        if deck_records is not None:
            location=deck_records.Deck_location
            deckName=deck_records.Deck_name
            data_json = io.open(location,'r',encoding='UTF-8').read()
            data_dic=json.loads(data_json)
            for keys in data:
                data_dic["cards"][keys]= data[keys]
            with open(location, "w") as outfile:
                json.dump(data_dic, outfile, indent = 4)
            creds = User.query.get(User_id)
            name = creds.Username    
            return render_template('showDeck.html',Username=name,deckName=deckName,deckId=deckId,cards=data_dic['cards'],User_id=User_id)
        else :
            return render_template('Invalid_deck.html', data = "DECK ID")

@app.route('/delete/<int:User_id>/<string:deck_id>',methods=['PUT'])
def Delete(deck_id,User_id):    
    if(request.method=='PUT'):
        try:
            Dashboard_info.query.filter(Dashboard_info.Deck_id==deck_id ,Dashboard_info.User_id==User_id).one()
        except exc.SQLAlchemyError:
            raise Invalid_error('USER ID/DECK ID,this deck for this user', status_code=400)
        deck_records= deck_info.query.filter(deck_info.Deck_id==deck_id).one()
        location=deck_records.Deck_location
        os.remove(location)
        deck=deck_info.query.filter(deck_info.Deck_id==deck_id).delete()
        db.session.commit()
        dash=Dashboard_info.query.filter(Dashboard_info.Deck_id==deck_id).delete()
        db.session.commit()
        return jsonify("Deck Removed")

@app.route('/delete',methods=['POST','GET'])
def Delete_deck():
    User_id = ses["User_id"]
    if(request.method=='GET'):
        try:
            User.query.filter(User.id==User_id).one()
        except exc.SQLAlchemyError:
            return render_template("Invalid_deck.html",data= "USER ID")
        creds = User.query.get(User_id)
        name = creds.Username    
        return render_template('deleteDeck1.html',Username=name)
    else:
        deckId = request.form['deckId']   
        try:
            deck_records= deck_info.query.filter(deck_info.Deck_id==deckId).one()
        except exc.SQLAlchemyError:
            return render_template('Invalid_deck.html', data = "DECK ID")
        location=deck_records.Deck_location
        os.remove(location)
        deck_info.query.filter(deck_info.Deck_id==deckId).delete()
        db.session.commit()
        Dashboard_info.query.filter(Dashboard_info.Deck_id==deckId).delete()
        db.session.commit()
        creds = User.query.get(User_id)
        name = creds.Username
        return render_template('deleteDeck2.html',User_id=User_id,Username=name)

@app.route('/remove/<int:User_id>/<string:deck_id>/<string:card_name>',methods=['PUT'])
def Remove_card_info(deck_id,card_name,User_id):
    if(request.method== 'PUT'):
        try:
            Dashboard_info.query.filter(Dashboard_info.Deck_id==deck_id ,Dashboard_info.User_id==User_id).one()
        except exc.SQLAlchemyError:
            raise Invalid_error("USER ID/DECK ID,this deck for this user", status_code=400)
        try:
            deck_records= deck_info.query.filter(deck_info.Deck_id==deck_id).one()
        except exc.SQLAlchemyError:
            raise Invalid_error('Deck_id')   
        location=deck_records.Deck_location
        deck_name=deck_records.Deck_name
        data_json = io.open(location,'r',encoding='UTF-8').read()
        data_dic=json.loads(data_json)
        try:
            del data_dic["cards"][card_name]
        except KeyError:
            raise Invalid_error('card_name',status_code=404)    
        with open(location, "w") as outfile:
            json.dump(data_dic, outfile, indent = 4)
        return data_dic 


@app.route('/remove',methods=['GET','POST'])
def remove_card():
    User_id = ses["User_id"]
    if(request.method == 'GET'):
        try:
            User.query.filter(User.id==User_id).one()
        except exc.SQLAlchemyError:
            return render_template("Invalid_deck.html",data= "USER ID")
        creds = User.query.get(User_id)
        name = creds.Username    
        return render_template('remove1.html',Username = name)
    elif(request.method =='POST'):
        deckId = request.form['deckId']
        url = '/remove/'+deckId
        return redirect(url)

@app.route('/remove/<string:deckId>',methods=['GET','POST'])
def remove_card2(deckId):
    User_id = ses["User_id"]
    if(request.method=='GET'):
        try:
            Dashboard_info.query.filter(Dashboard_info.Deck_id==deckId ,Dashboard_info.User_id==User_id).one()
        except exc.SQLAlchemyError:
            return render_template('Invalid_deck.html', data = "USER ID/DECK ID")
        deck_records= deck_info.query.filter(deck_info.Deck_id==deckId).one()   
        location=deck_records.Deck_location
        deckName=deck_records.Deck_name
        data_json = io.open(location,'r',encoding='UTF-8').read()
        data_dic=json.loads(data_json)
        data_dic=dict(data_dic)
        creds = User.query.get(User_id)
        name = creds.Username
        return render_template('remove2.html',cards=data_dic['cards'],Username =name)
    elif(request.method=='POST'):
        cardName = request.form['front']
        try:
            deck_records= deck_info.query.filter(deck_info.Deck_id==deckId).one()
        except exc.SQLAlchemyError:
            return render_template('Invalid_deck.html', data = "DECK ID")
        location=deck_records.Deck_location
        deckName=deck_records.Deck_name
        data_json = io.open(location,'r',encoding='UTF-8').read()
        data_dic=json.loads(data_json)
        try:
            del data_dic["cards"][cardName]
        except KeyError:
            return render_template('No_such_card.html') 
        with open(location, "w") as outfile:
            json.dump(data_dic, outfile, indent = 4)
        creds = User.query.get(User_id)
        name = creds.Username    
        return render_template('showDeck.html',deckName=deckName,Username=name,deckId=deckId,cards=data_dic['cards'],User_id=User_id)    


@app.route('/getuserid/<string:Username>/<string:password>')
def getuserid(Username, password):
    
        cred = User.query.filter(User.Username == Username, User.Password == password).one_or_none()

        if(cred):
            p = cred.id
            dic  = {}
            dic['User_id'] = p
    
            return jsonify(dic)

        else:
            raise Invalid_error('Username/password', status_code = 400)
        
@app.route('/new/<int:User_id>/<string:deck_name>',methods=['POST'])
def New_deck(deck_name,User_id):
    if(request.method == 'POST'):
        data=request.json
        try:
            User.query.filter(User.id==User_id).one()
        except exc.SQLAlchemyError:
            raise Invalid_error("USER ID",status_code=400)
        if data :
            deckId = str(uuid.uuid4())[:8]
            dic = {"Deck_name":deck_name, "Deck_id":deckId,"cards":data}
            MyJson = json.dumps(dic, indent = 4)
            deck_location = str(os.path.join(basedir, "json/"+deck_name+".json"))
            F =open(deck_location, 'w')
            with open( deck_location, "w") as outfile:
                outfile.write(MyJson)  
            cards = deck_info(Deck_id=deckId,Deck_name=deck_name,Deck_location=deck_location)
            db.session.add(cards)
            db.session.commit()
            dash = Dashboard_info(Deck_id = deckId, User_id = User_id, Score = 0, LastReviewTime = '0')
            db.session.add(dash)
            db.session.commit()
            return jsonify(dic)
        else :
            raise No_cards_error(status_code=400)


@app.route('/new', methods = ['GET','POST'])
def new_deckfunc():
    User_id = ses["User_id"]
    if(request.method == 'GET'):
        try:
            User.query.filter(User.id==User_id).one()
        except exc.SQLAlchemyError:
            return render_template("Invalid_deck.html",data= "USER ID")
        creds = User.query.get(User_id)
        name = creds.Username
        return render_template('createdeck1.html',Username = name)
    else:      
        deckName = request.form['deckname']
        cardNo  = request.form['cardno']
        url = '/setdeck/' + deckName + '/' + str(cardNo)
        return redirect(url)
              
@app.route('/setdeck/<string:deckName>/<int:cardNo>', methods = ['GET','POST'])
def create(deckName, cardNo):
    User_id = ses["User_id"]
    if(request.method == 'GET'):
        try:
            User.query.filter(User.id==User_id).one()
        except exc.SQLAlchemyError:
            return render_template("Invalid_deck.html",data= "USER ID")
        creds = User.query.get(User_id)
        name = creds.Username    
        return render_template('createdeck2.html',Username=name,cardno = cardNo, deckname = deckName)
    else:
        r = request.form
        r = str(r)
        r = r[20:-2]
        data = str2tupleList(r, cardNo)
        if data!= { '': ''}:
            deckId = str(uuid.uuid4())[:8]
            dic = {"Deck_name":deckName, "Deck_id":deckId,"cards":data}
            MyJson = json.dumps(dic, indent = 4)
            deckLocation = str(os.path.join(basedir, "json/"+deckName+".json"))
            F =open(deckLocation, 'w')
            with open( deckLocation, "w") as outfile:
                outfile.write(MyJson)  
            cards = deck_info(Deck_id=deckId,Deck_name=deckName,Deck_location=deckLocation)
            db.session.add(cards)
            db.session.commit()
            dash = Dashboard_info(Deck_id = deckId, User_id = User_id, Score = 0, LastReviewTime = '0')
            db.session.add(dash)
            db.session.commit()
            creds = User.query.get(User_id)
            name = creds.Username
            return render_template('showDeck.html',deckName=deckName,deckId=deckId,cards=dic["cards"],User_id=User_id,Username=name)
        else : 
            return render_template('NoCards.html')

def str2tupleList(s, cardNo):
    r = eval( "[%s]" % s )
    dic = {}
    for i in range(0,cardNo):
        dic[r[i][1]] = r[i+cardNo][1]
    return dic 

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/dashboard/<string:Deck_id>/<int:card>/<int:score>')
def card_detail(card, Deck_id,score):
    User_id = ses["User_id"]
    Deck_details = deck_info.query.filter(deck_info.Deck_id == Deck_id).one()
    Deck_Name = Deck_details.Deck_name
    SITE_ROOT = os.path.realpath(os.path.dirname(__file__))
    Filename= Deck_Name +'.json'
    json_url = os.path.join(SITE_ROOT, "json/", Filename)
    data = json.load(open(json_url))
    li = list(data['cards'].keys())

    if(card!=0):
        dash= Dashboard_info.query.filter((Dashboard_info.User_id == User_id) & (Dashboard_info.Deck_id == Deck_id)).one()
        dash.Score += int(score)
        now = datetime.now()
        now = now.strftime("%d/%m/%Y %H:%M:%S")
        dash.LastReviewTime = now
        db.session.commit()

       
    if(card >= len(li)):
        url = '/dashboard'
        return redirect(url)
    
    else:
        
        front = li[card]
        back = data['cards'][front]

        return render_template('review.html', User_id = User_id, Deck_id = Deck_id, Deck_Name = Deck_Name, card = card+1, front = front, back = back)

@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect('/login?next=' + request.path)



if __name__ == "__main__":
    app.run(debug = True)