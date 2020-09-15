import hashlib, binascii, os, sys
import smtplib
from flask_mail import Mail, Message
from email.message import EmailMessage
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)
import time
import re
import sqlalchemy
import sqlalchemy.ext.automap
import sqlalchemy.orm
import sqlalchemy.schema
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine, desc
import json
import collections
from urllib.parse import quote_plus
from email.mime.multipart import MIMEMultipart
from string import Template
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.image import MIMEImage

from flask_cors import CORS
import importlib.util
from flask import Flask, render_template, jsonify, request, session, redirect, Blueprint, url_for, g, abort
from datetime import datetime
from flask_session import Session

from google.oauth2 import id_token
from google.auth.transport import requests

spec = importlib.util.spec_from_file_location(
    "ecpay_payment_sdk",    
    "ecpay_payment_sdk.py"   

)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

app=Flask(__name__)


app.config['SECRET_KEY'] = 'fuck'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:ntumir409@127.0.0.1:3306/userb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_ECHO'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PROT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'sovia@dwave.cc'
app.config['MAIL_PASSWORD'] = 'ntumir409dw'


mail = Mail(app)
db = SQLAlchemy(app)
auth = HTTPBasicAuth()
CORS(app)
db.init_app(app)



#GOOGLE_OAUTH2_CLIENT_ID = '251293359822-mbi2reulhh20mq042ctno0e3r80qrqdc.apps.googleusercontent.com'
class Transaction(db.Model):
	__tablename__ = 'Transaction'
	account = db.Column(db.String(64), primary_key=True)
	price = db.Column(db.INTEGER())
	pay_type = db.Column(db.String(45))
	pay_time = db.Column(db.String(64))
	tid = db.Column(db.String(64))
	status = db.Column(db.String(64))
	orderNo = db.Column(db.String(64))
class User(db.Model):
	__tablename__ = 'user'
	account = db.Column(db.String(64), primary_key=True)
	password = db.Column(db.String(255))
	u_email = db.Column(db.String(100), index=True)
	u_time = db.Column(db.String(100), index=True)
	confirm = db.Column(db.Boolean)
	coin = db.Column(db.INTEGER())
	app = Flask(__name__)
	db = SQLAlchemy(app)
	auth = HTTPBasicAuth()
	def hash_password(password):
		salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
		pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), 
	                                salt, 100000)
		pwdhash = binascii.hexlify(pwdhash)
		return (salt + pwdhash).decode('ascii')
	def verify_password(stored_password, provided_password):
		salt = stored_password[:64]
		stored_password = stored_password[64:]
		pwdhash = hashlib.pbkdf2_hmac('sha512', 
	                                  provided_password.encode('utf-8'), 
	                                  salt.encode('ascii'), 
	                                  100000)
		pwdhash = binascii.hexlify(pwdhash).decode('ascii')
		return pwdhash == stored_password
	#寄信
	def tmail(r,account,url,u_mail):
		content = MIMEMultipart()
		content["subject"] = "SOVIA Confirm Mail"
		content["from"] = "sovia@dwave.cc"
		content["to"] = u_mail
		template = Template(Path(r).read_text())
		body = template.substitute({ "user": account , "url": url})
		content.attach(MIMEText(body, "html"))

		with smtplib.SMTP(host="smtp.gmail.com", port="587") as smtp:
			try:
				smtp.ehlo()
				smtp.starttls()
				smtp.login("sovia@dwave.cc", "ntumir409dw")
				smtp.send_message(content)
				print(u_mail+"--mail is sent!")
			except Exception as e:
				print("Error message: ", e)

	#def send_async_email(app, msg):
	#	with app.app_context():
	#		mail.send(msg)
	#create token
	def create_confirm_token(self, expiration=600):
		s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
		return s.dumps({'account': self.account})
	@staticmethod
	def validate_confirm_token(token):
		s = Serializer(app.config['SECRET_KEY'])
		try:
			data = s.loads(token)
		except SignatureExpired:
			return False  
		except BadSignature:
			return False  
		#user = User.query.get(data['account'])
		return data
#@app.route("/")
#def reg():
#	return render_template("reg.html")
#@app.route("/login")
#def logtest():
#	return render_template("login.html")
#@app.route("/pay")
#def pay():
#        return render_template("pay.html")
#@app.route("/forget_password")
#def forget_password():
#        return render_template("foget.html")
#@app.route("/reset_pw")
#def reset_pw():
#	return render_template("reset_pw.html")

#@app.route("/g_login")
#def g_login():
#       return render_template("g_login.html", google_oauth2_client_id=GOOGLE_OAUTH2_CLIENT_ID)

@app.route("/set_ss", methods={'GET', 'POST'})
def set_ss(uname):
	session[uname] = True
	return jsonify({'set':'000'})
@app.route("/get_ss", methods={'GET', 'POST'})
def get_ss(uname):
	return jsonify('uname':session.get(uname))
@app.route("/del_ss", methods={'GET', 'POST'})
def del_ss(uname):
	session[uanme] = False
	return jsonify({'del':'000'})


@app.route("/ss", methods={'GET', 'POST'})
def ss():
	if request.form.get('order')== 'set':
		session[request.form.get('account')] = True
		return jsonify({'set':'000'})
	if request.form.get('order')== 'del':
		session[request.form.get('account')] = True
		return jsonify({'del':'000'})
	if request.form.get('order')== 'get':
		session.get(request.form.get('account'))
		return jsonify({'get':'000'})


@app.route('/user_confirm/<token>')
def user_confirm(token):
	user = User()
	data = user.validate_confirm_token(token)
	#print(data)
	if data:
		user = User.query.filter_by(account=data.get('account')).first()
		user.confirm = True
		db.session.add(user)
		db.session.commit()
		#return jsonify({'success':'account is activate'})
		return render_template("confirm.html")
	else:
		return render_template("confirm.html")
@app.route('/forget_confirm/<token>')
def forget_confirm(token):
	user = User()
	data = user.validate_confirm_token(token)
	#print(data)
	if data:
		user = User.query.filter_by(account=data.get('account')).first()
		#db.session.add(user)
		#db.session.commit()
		print(user.account+', email confirm')
		return render_template("reset_pw.html", user_email = user.u_email)
	else:
		return render_template("jump.html")
@app.route('/new_user', methods=['POST'])
def new_user():
	engine = sqlalchemy.create_engine("mysql+pymysql://root:ntumir409@127.0.0.1:3306/userb",
					encoding='utf-8', echo=True)
	DB_Session = sessionmaker(bind=engine)
	session = DB_Session()
	
	account = request.form.get('r_account') 
	password = request.form.get('r_password')
	u_mail = request.form.get('r_email')
	p = re.compile(r"[^@]+@[^@]+\.[^@]+")
	if not p.match(u_mail):
		print(u_mail)
		return jsonify({'errorMsg':'202'})
	a_check = "~!@#$%^&*()+*/<>,[]\/"
	p_check = "~!@#$%^&*()_+-*/<>,.[]\/"
	for i in a_check:
		if i in account:
			return jsonify({'errorMsg':'202'})
	for i in p_check:
		if i in password:
			return jsonify({'errorMsg':'202'})
	if ' ' in account:
		return jsonify({'errorMsg':'201'})
	elif len(account)>12 or len(account)<6 :
		return jsonify({'errorMsg':'203'})
	elif len(password)>12 or len(password)<6:
		return jsonify({'errorMsg':'204'})
	elif User.query.filter_by(account=account).first() is not None:
		return jsonify({'errorMsg':'208'})
	elif User.query.filter_by(u_email=u_mail).first() is not None:
		return jsonify({'errorMsg':'209'})
		#sys.exit()
	else:
		hash_password=User.hash_password(password)
		time = datetime.now().strftime("%Y%m%d%H%M%S")
		user = User( account = account, password = hash_password,u_email = u_mail, u_time = time, coin = 0)
		token = user.create_confirm_token()
		
		url = url_for('user_confirm',token = token,  _external=True)
		db.session.add(user)
		db.session.commit()
		db.session.close()
		r = "templates/mail.html"
		User.tmail(r,account,url,u_mail)
		return jsonify({'success':'000'})
		
		#	return jsonify({'success':'410'})
@app.route('/reg_resent', methods=['POST'])
def reg_resent():
	account = request.form.get('account')
	user = User.query.filter_by(account=account).first()
	if user: 
		if user.confirm == None:
			u_mail = user.u_email
			user = User(account = account,u_email = u_mail)
			token = user.create_confirm_token()
			url = url_for('user_confirm',token = token,  _external=True)
			r = "templates/mail.html"
			User.tmail(r,account,url,u_mail)
			return jsonify({'success':'000'})
		else:
			return jsonify({'errorMsg': '410'})
	else:
		return jsonify({'errorMsg': '405'})
@app.route('/login', methods=['POST'])
def login():
	print('1')	
	engine = sqlalchemy.create_engine("mysql+pymysql://root:ntumir409@127.0.0.1:3306/userb",
                              encoding='utf-8', echo=True)
	DB_Session = sessionmaker(bind=engine)
	session = DB_Session()
	account = request.form.get('account')
	password = request.form.get('password')
	a_check = "~!#$%^&*()+*/<>,[]\/"
	p_check = "~!@#$%^&*()+-*/<>,.[]\/"
	for i in a_check:
		if i in account:
			return jsonify({'errorMsg':'102'})
	for i in p_check:
		if i in password:
			return jsonify({'errorMsg':'102'})
	if ' ' in account:
		return jsonify({'errorMsg':'101'})
	elif '@' in account:
		data = session.query(User).filter_by(u_email = account).first()
		if data:
			if data.confirm ==None:
				return jsonify({'errorMsg':'106'})
			elif User.verify_password(data.password, password) == False:
				return jsonify({'errorMsg': '107'})
			else:
				print (account+'--log in')	
				return jsonify({'account':data.account})
		else:
			return jsonify({'errorMsg': '105'})
	else:
		data = session.query(User).filter_by(account = account).all()
		if data:
			if data[0].confirm ==None:
				return jsonify({'errorMsg':'106'})
			if User.verify_password(data[0].password, password) == False:
				return jsonify({'errorMsg':'107'})
			else: 
				print (account+'--login')
				return jsonify({'account':account})
		else:
			return jsonify({'errorMsg': '105'})

@app.route('/google_sign_in', methods=['POST'])
def google_sign_in():
    token = request.json['id_token']
    
    try:
        id_info = id_token.verify_oauth2_token(
            token,
            requests.Request(),
            GOOGLE_OAUTH2_CLIENT_ID
        )
        if id_info['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            raise ValueError('Wrong issuer.')
    except ValueError:
        # Invalid token
        raise ValueError('Invalid token')
 
    print('登入成功')
    return jsonify({}), 200

#forget password send mail
@app.route('/forget', methods=['POST'])
def forget():
	email = request.form.get('email')
	print(email+',email forget')
	engine = sqlalchemy.create_engine("mysql+pymysql://root:ntumir409@127.0.0.1:3306/userb",
                              encoding='utf-8', echo=True)
	DB_Session = sessionmaker(bind=engine)
	session = DB_Session()
	u = User.query.filter_by(u_email=email).first()
	if u:
		account = u.account
		user = User(account = account, u_email = email)
		token = user.create_confirm_token()
		url = url_for('forget_confirm',token = token,  _external=True)
		r = "templates/forget.html"
		User.tmail(r,account, url, u_mail= email)
		return jsonify({'success':'000'})
	else:
		return jsonify({'success':'405'})
@app.route('/change_password', methods=['POST'])
def change_password():
	email = request.form.get('email')
	password = request.form.get('password')
	new_password=User.hash_password(password)	
	db.session.query(User).filter_by(u_email=email).update({'password': new_password})
	return jsonify({'success': '000'})
@app.route("/refresh", methods=['POST'])
def refresh():
	account = request.form.get('account')
	engine = sqlalchemy.create_engine("mysql+pymysql://root:ntumir409@127.0.0.1:3306/userb",
                              encoding='utf-8', echo=True)
	DB_Session = sessionmaker(bind=engine)
	session = DB_Session()
	user = User.query.filter_by(account=account).first()
	return jsonify({'coin':user.coin})

# 登入後獲取token
@app.route('/api/token')
@auth.login_required
def get_auth_token():
	# 設定token過期時間
	token = g.user.generate_auth_token(600)
	return jsonify({'token': token.decode('ascii'), 'duration': 600})

# 可以通過token或者賬號密碼登入
@app.route('/api/resource')
@auth.login_required
def get_resource():
	# 如果token有效的話就返回username
	return jsonify({'data': 'Hello, %s!' % g.user.username})

	# 有@auth.login_required標誌的都要呼叫這個方法,傳token或者傳賬號和密碼
@auth.verify_password
def verify_password(username_or_token, password):
	# 首先驗證token
	user = User.verify_auth_token(username_or_token)
	if not user:
		user = User.query.filter_by(username=username_or_token).first()
	if not user or not user.verify_password(password):
		return False
	g.user = user
	return True

# 環境參數
class Params:
	def __init__(self):
		web_type = 'official'
		if web_type == 'official':
		# 正式環境
			self.params = {
                'MerchantID': '3190716',
                'HashKey': '3iymOeTivd1VXSpz',
                'HashIV': 'n1hJ0c8W2QZf4Jzk',
                'action_url':
                'https://payment.ecpay.com.tw/Cashier/AioCheckOut/V5'
		}
		else:
            	# 測試環境
			self.params = {
                'MerchantID':
                '2000132',
                'HashKey':
                '5294y06JbISpM5x9',
                'HashIV':
                'v77hoKGq4kWxNNIS',
                'action_url':
                'https://payment-stage.ecpay.com.tw/Cashier/AioCheckOut/V5'
		}
			
	@classmethod
	def get_params(cls):
		return cls().params

        # 驗證綠界傳送的檢查碼 check_mac_value 值是否正確
	@classmethod
	def get_mac_value(cls, get_request_form):

		params = dict(get_request_form)
		if params.get('CheckMacValue'):
			params.pop('CheckMacValue')

		ordered_params = collections.OrderedDict(
			sorted(params.items(), key=lambda k: k[0].lower()))

		HahKy = cls().params['HashKey']
		HashIV = cls().params['HashIV']

		encoding_lst = []
		encoding_lst.append('HashKey=%s&' % HahKy)
		encoding_lst.append(''.join([
			'{}={}&'.format(key, value)
			for key, value in ordered_params.items()
		]))
		encoding_lst.append('HashIV=%s' % HashIV)

		safe_characters = '-_.!*()'

		encoding_str = ''.join(encoding_lst)
		encoding_str = quote_plus(str(encoding_str),
                                  safe=safe_characters).lower()

		check_mac_value = ''
		check_mac_value = hashlib.sha256(
			encoding_str.encode('utf-8')).hexdigest().upper()

		return check_mac_value


@app.route("/ecpay", methods=['POST','GET'])
def ecpay():
	
	account = request.form.get('account')
	host_name = request.host_url
	print(account+'----------------------------')
	product = request.form.get('product_name')
	#print(product)
	j = json.loads(product)
	
	pr, co = 0, 0
	for key in j:
		print(str(key)+'.case:'+str(j[key]))
		pr=pr+int(j[key]['price'])*int(j[key]['quantity'])
		if j[key]['price']=='90':
			#j[key]['price'] = '1'
			#add = {"coin":"1"}
			#j[key].update(add)
			j[key].setdefault('coin','1')
		elif j[key]['price']=='120':
			#j[key]['price'] = '5'
			#add = {"coin":"5"}
			#j[key].update(add)
			j[key].setdefault('coin','5')
		elif j[key]['price']=='190':
			#j[key]['price'] = '10'
			#add = {"coin": "10"}
			#j[key].update(add)
			j[key].setdefault('coin','10')
		elif j[key]['price']=='290':
			#j[key]['price'] = '20'
			#add = {"coin": "20"}
			#j[key].update(add)
			j[key].setdefault('coin','20')
		else:
			break
		#print(j[key])
		print(str(key)+'.coin:'+str(j[key]))
		co=co+int(j[key]['coin'])*int(j[key]['quantity'])
	#print(j['1'].keys())
	print('cal_coin: '+str(co))
	print('cal_price: '+str(pr))
	coin = co
	price = request.form.get('price')
	print('post total price:'+str(price)+'---------------')
	
	#測試用價錢
	price = 5
	coin = 10
	#測試

	# 建立交易編號 tid
	date = time.time()
	tid = str(date) + 'sovia' + str(account)
	status = 'not pay '

	# 新增 Transaction 訂單資料
	orderNo = datetime.now().strftime("NO%Y%m%d%H%M%S")
	T = Transaction(account=account, tid=tid, price=price, status=status, orderNo=orderNo)
	db.session.add(T)
	db.session.commit()

	#params = Params.get_params()

	# 設定傳送給綠界參數
	order_params = {
		'MerchantTradeNo': datetime.now().strftime("NO%Y%m%d%H%M%S"),
		'StoreID': 'SOVIA',
		'MerchantTradeDate': datetime.now().strftime("%Y/%m/%d %H:%M:%S"),
		'PaymentType': 'aio',
		'TotalAmount': price,
		'TradeDesc': 'ToolsFactory',
		'ItemName': str(coin)+'SOVIA coin',
		'ReturnURL': host_name + 'receive_result',
		'ChoosePayment': 'ALL',
		'ClientBackURL': 'http://dwave.cc:9051/',
		'Remark': '',
		'ChooseSubPayment': '',
		'OrderResultURL': host_name + 'receive',
		'NeedExtraPaidInfo': 'Y',
		'DeviceSource': '',
		'IgnorePayment': '',
		'PlatformID': '',
		'InvoiceMark': 'N',
		'CustomField1': str(tid),
		'CustomField2': str(coin),
		'CustomField3': '',
		'CustomField4': '',
		'EncryptType': 1,
	}

	extend_params_1 = {
		'BindingCard': 0,
		'MerchantMemberID': '',
	}

	extend_params_2 = {
		'Redeem': 'N',
		'UnionPay': 0,
	}

	inv_params = {
        # 'RelateNumber': 'Tea0001', # 特店自訂編號
        # 'CustomerID': 'TEA_0000001', # 客戶編號
        # 'CustomerIdentifier': '53348111', # 統一編號
        # 'CustomerName': '客戶名稱',
        # 'CustomerAddr': '客戶地址',
        # 'CustomerPhone': '0912345678', # 客戶手機號碼
        # 'CustomerEmail': 'abc@ecpay.com.tw',
        # 'ClearanceMark': '2', # 通關方式
        # 'TaxType': '1', # 課稅類別
        # 'CarruerType': '', # 載具類別
        # 'CarruerNum': '', # 載具編號
        # 'Donation': '1', # 捐贈註記
        # 'LoveCode': '168001', # 捐贈碼
        # 'Print': '1',
        # 'InvoiceItemName': '測試商品1|測試商品2',
        # 'InvoiceItemCount': '2|3',
        # 'InvoiceItemWord': '個|包',
        # 'InvoiceItemPrice': '35|10',
        # 'InvoiceItemTaxType': '1|1',
        # 'InvoiceRemark': '測試商品1的說明|測試商品2的說明',
          # 'DelayDay': '0', # 延遲天數
        # 'InvType': '07', 
	}
	
	ecpay_payment_sdk = module.ECPayPaymentSdk(MerchantID='3190716',
                                               HashKey='3iymOeTivd1VXSpz',
                                               HashIV='n1hJ0c8W2QZf4Jzk')

	#ecpay_payment_sdk = module.ECPayPaymentSdk(MerchantID='2000132',
	#					HashKey='5294y06JbISpM5x9',
	#					HashIV='v77hoKGq4kWxNNIS')





        # 合併延伸參數
	order_params.update(extend_params_1)
	order_params.update(extend_params_2)

        # 合併發票參數
	order_params.update(inv_params)

	try:
        # 產生綠界訂單所需參數
		final_order_params = ecpay_payment_sdk.create_order(order_params)

        # 產生 html 的 form 格式
		action_url = 'https://payment.ecpay.com.tw/Cashier/AioCheckOut/V5' #正式
		#action_url = 'https://payment-stage.ecpay.com.tw/Cashier/AioCheckOut/V5'
		html = ecpay_payment_sdk.gen_html_post_form(action_url,final_order_params)
		return html

	except Exception as error:
		print('An exception happened:'  + str(error))
		return('error')

@app.route('/receive_result', methods=['POST'])
def end_return():

	result = request.form['RtnMsg']
	#tid = request.form['CustomField1']
	#trade_detail = sql.Transaction.query.filter_by(tid=tid).first()
	#trade_detail.status = '交易成功 sever post'
	#db.session.add(trade_detail)
	#db.session.commit()
	if result == 'Succeeded':
		return '1|OK'
	else :
		return jsonify({'errorMsg':'error'})
@app.route('/receive', methods=['POST'])
def end_page():

	#if request.method == 'GET':
	#	return redirect(url_for('http://dwave.cc:9051/'))

	if request.method == 'POST':
		check_mac_value = Params.get_mac_value(request.form)

		if request.form['CheckMacValue'] != check_mac_value:
			return jsonify({'errorMsg':'something wrong,please contact engineer'})

		engine = sqlalchemy.create_engine("mysql+pymysql://root:ntumir409@127.0.0.1:3306/userb",
                              encoding='utf-8', echo=True)
		DB_Session = sessionmaker(bind=engine)
		session = DB_Session()

                # 接收 ECpay 刷卡回傳資訊
		result = request.form['RtnMsg']
		tid = request.form['CustomField1']
		pay_type = request.form['PaymentType']
		pay_time = request.form['PaymentDate']
		account = session.query(Transaction.account).filter_by(tid=tid).first()
		price = request.form['TradeAmt']
		coin = int(request.form['CustomField2'])
		
		user = User.query.filter_by(account=account).first()
                #用session.query(Transaction.account).filter_by(tid=tid).first()會報錯 不懂..
		user_coin = user.coin
		new_coin = int(coin + user_coin)
		
		

		
        # 取得交易使用者資訊
		#uid = trade_detail.uid

		#trade_client_detail = {
            #'name': trade_detail.trade_name,
            #'phone': trade_detail.trade_phone,
            #'county': trade_detail.trade_county,
            #'district': trade_detail.trade_district,
            #'zipcode': trade_detail.trade_zipcode,
            #'trade_address': trade_detail.trade_address
	#	}

		if result == 'Succeeded':
			#
			db.session.query(Transaction).filter_by(tid = tid).update({'status': 'pay success'})
			db.session.query(Transaction).filter_by(tid = tid).update({'pay_type':pay_type})
			db.session.query(Transaction).filter_by(tid = tid).update({'pay_time':pay_time})
			db.session.query(User).filter_by(account = account).update({'coin':new_coin})
			#db.session.add(T)
			#session.flush()
			db.session.commit()
			db.session.close()
			return render_template("jump.html")
			#return jsonify({'account':account, 'price':price, 'coin':new_coin})
			#return '1|OK'
			#commit_list = []
			
			
                # 移除 AddToCar (狀態：Y 修改成 N)
			#carts = sql.AddToCar.query.filter_by(uid=uid, state='Y')
			#for cart in carts:
				#price = cart.product.price
				#quan = cart.quantity
				#cart.state = 'N'
                # 新增 Transaction_detail 訂單細項資料
				#Td = sql.Transaction_detail(tid, cart.product.pid, quan, price)
				#commit_list.append(Td)
				#commit_list.append(cart)

			#db.session.add_all(commit_list)
			#db.session.commit()

            # 讀取訂單細項資料
			#trade_detail_items = sql.Transaction_detail.query.filter_by(
                        #tid=tid)
			
			#return ('pay success')
			#return render_template('/payment/trade_success.html',
                        #           shopping_list=trade_detail_items,
                        #           total=trade_detail.total_value)

        # 判斷失敗
		else:
			#carts = sql.AddToCar.query.filter_by(uid=uid, state='Y')
			#trade_detail = sql.Transaction.query.filter_by(tid=tid).first()

			return ('false')
			#return render_template('/payment/trade_fail.html',
                         #          shopping_list=carts,
                          #         total=trade_detail.total_value,
                            #       trade_client_detail=trade_client_detail)

if __name__ == '__main__':
	db.create_all()
	app.run(host="0.0.0.0", port="11002", debug=True)
