import json
import os
import time
from datetime import datetime, timedelta

import yaml
import pymysql
from flask import Flask, render_template, request, jsonify
import uuid
import stomp

from gevent import pywsgi
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (JWTManager, jwt_required, create_access_token, get_jwt_identity, set_access_cookies,
                                create_refresh_token, unset_jwt_cookies, decode_token)

from flask_apscheduler import APScheduler

from response_code import Response

app = Flask(__name__)

with open(os.path.expanduser("./config.yaml"), "r") as config:
    cfg = yaml.safe_load(config)

db_user = cfg['mysql']['user']
db_password = cfg['mysql']['password']
db_host = cfg['mysql']['host']
db_port = cfg['mysql']['port']
db_database = cfg['mysql']['database']
app.config["SQLALCHEMY_DATABASE_URI"] \
    = f"mysql+pymysql://{db_user}:{db_password}@{db_host}:{db_port}/{db_database}?charset=utf8"
db = SQLAlchemy(app)

app.config['JWT_SECRET_KEY'] = 'twei3131'
app.config["JWT_TOKEN_LOCATION"] = ["headers", "cookies", "json", "query_string"]
jwt = JWTManager(app)

mq_host = cfg['message']['host']
mq_port = int(cfg['message']['port'])
mq_conn = stomp.Connection([(mq_host, mq_port)])
mq_conn.connect()

app.config['SCHEDULER_API_ENABLED'] = True
scheduler = APScheduler()
scheduler.init_app(app)


class User(db.Model):
    __tablename__ = 't_user'

    id = db.Column('ID', db.Integer, primary_key=True)
    mobile = db.Column('Mobile', db.String)
    name = db.Column('Name', db.String)
    employee_id = db.Column('Eid', db.String)
    wechat_id = db.Column('Wx_id', db.String)
    department = db.Column('Department', db.Integer)
    role = db.Column('Role', db.Integer)


class Department(db.Model):
    __tablename__ = 't_department'

    id = db.Column('ID', db.Integer, primary_key=True)
    name = db.Column('Name', db.String)


class Role(db.Model):
    __tablename__ = 't_role'

    id = db.Column('ID', db.Integer, primary_key=True)
    name = db.Column('Name', db.String)


class Login(db.Model):
    __tablename__ = 't_login'

    id = db.Column('ID', db.Integer, primary_key=True)
    user = db.Column('User', db.Integer)
    access_token = db.Column('AccessToken', db.String)
    refresh_token = db.Column('RefreshToken', db.String)
    state = db.Column('State', db.String)
    access_time = db.Column('AccessTime', db.DateTime)
    refresh_time = db.Column('RefreshTime', db.DateTime)
    device = db.Column('Device', db.String)
    queue_listener = db.Column('QueueListener', db.String)


@app.route('/', endpoint='index_page')
def index():
    stomp_config = {
        'host': mq_host,
        'port': 61614,
        'user': 'admin',
        'passcode': 'admin'
    }
    return render_template('./index.html', stomp_config=stomp_config)


@app.route('/user/page/login', endpoint='login_page')
def login():
    return render_template('./login.html')


@app.route('/user/check_login_state', methods=['POST'], endpoint='/user/check_login_state')
@jwt_required(locations=["headers"])
def get_login_state_by_access_token():
    identity = get_jwt_identity()
    uid = identity.get('uid')
    device = identity.get('device')

    login_list = db.session.query(Login).filter(Login.user == uid, Login.device == device).all()

    if len(login_list) == 0:
        return jsonify(code=Response.not_found_user)

    # 若登录状态为logout,则直接返回
    _login = login_list[0]
    if _login.state == 'logout':
        return jsonify(code=Response.logout)
    elif _login.state == 'expire':
        return jsonify(code=Response.expire)
    elif _login.state == 'online':
        return jsonify(code=Response.online)

    return jsonify(code=Response.online)


@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    sub = jwt_payload['sub']
    uid, device = sub['uid'], sub['device']

    # 将设备踢下线
    _login = db.session.query(Login).filter(Login.user == uid, Login.device == device).first()
    _login.state = 'logout'
    _login.access_token = ''
    _login.refresh_token = ''
    db.session.commit()

    mq_conn.send(_login.queue_listener, 'keep')

    return jsonify(code=Response.keep_alive)


@app.route('/user/get_access_token', methods=['POST'], endpoint='/user/get_access_token')
def get_access_token():
    data = request.get_data()
    data = json.loads(data)

    eid = data['eid']
    device = data['device']

    user_list = db.session.query(User).filter(User.employee_id == eid).all()
    if len(user_list) == 0:
        return jsonify(code=Response.not_found_user)

    device = 'Laptop' if device == 0 else 'Mobile'

    uid = user_list[0].id

    access_token = create_access_token(
        identity={"uid": uid, "device": device},
        expires_delta=timedelta(hours=2)
    )
    # 当access_token失效时,通过refresh_token进行刷新
    refresh_token = create_refresh_token(
        identity={"uid": uid, "device": device},
        expires_delta=timedelta(hours=48)
    )

    # 注册使用设备列表
    login_list = db.session.query(Login).filter(Login.user == uid, Login.device == device).all()
    if len(login_list) == 0:
        # 向设备列表注册
        _login = Login(
            user=uid,
            access_token=access_token,
            refresh_token=refresh_token,
            device=device,
            queue_listener=uuid.uuid1(),
            state='online',
            access_time=datetime.now()
        )
        db.session.add(_login)
        db.session.commit()

        response = jsonify(
            {
                'code': Response.ok,
                'access_token': access_token,
                'refresh_token': refresh_token,
                'queue_listener': _login.queue_listener
            }
        )
    else:
        queue_listener = login_list[0].queue_listener

        # 若相同类型设备的状态为online,则将其踢下线
        if login_list[0].state == 'online' and login_list[0].device == device:
            # 将旧设备踢下线
            mq_conn.send(f'{queue_listener}', 'logout')
        # 新设备上线
        _login = db.session.query(Login).filter(Login.id == login_list[0].id).first()
        _login.state = 'online'
        _login.queue_listener = uuid.uuid1()
        _login.access_token = access_token
        _login.refresh_token = refresh_token
        _login.access_time = datetime.now()
        db.session.commit()

        response = jsonify(
            {
                'code': Response.ok,
                'access_token': access_token,
                'refresh_token': refresh_token,
                'queue_listener': _login.queue_listener
            }
        )
    return response


@app.route('/user/logout', methods=['POST'], endpoint='/user/logout')
@jwt_required(locations=["headers"])
def logout():
    identity = get_jwt_identity()
    uid = identity.get('uid')
    device = identity.get('device')

    # 获取uid
    user = db.session.query(User).filter(User.id == uid).first()

    # 将设备踢下线
    _login = db.session.query(Login).filter(Login.user == user.id, Login.device == device).first()
    _login.state = 'logout'
    _login.access_token = ''
    _login.refresh_token = ''
    db.session.commit()

    mq_conn.send(_login.queue_listener, 'logout')

    return jsonify(code=Response.ok)


@app.route('/user/force_logout', methods=['GET'], endpoint='/user/force_logout')
def force_logout():
    queue_listener = request.args.get("queue_listener")

    _login = db.session.query(Login).filter(Login.queue_listener == queue_listener)
    if _login is not None:
        _login = _login.first()
        _login.state = 'logout'
        _login.access_token = ''
        _login.refresh_token = ''
        db.session.commit()

        mq_conn.send(_login.queue_listener, 'logout')

    return jsonify(code=Response.ok)


@app.route('/user/page/404', methods=['GET'], endpoint='404_page')
def logout_page():
    return render_template("./404.html")


@app.route('/user/refresh', methods=['POST'], endpoint='/user/refresh')
@jwt_required(refresh=True, locations=["json"])
def refresh():
    identity = get_jwt_identity()

    # 刷新
    access_token = create_access_token(identity=identity, expires_delta=timedelta(hours=2))

    decoded = decode_token(encoded_token=access_token)
    uid = decoded['sub']['uid']
    device = decoded['sub']['device']

    # 写入数据库
    _login = db.session.query(Login).filter(Login.user == uid, Login.device == device).first()
    if _login.state != 'logout':
        _login.access_token = access_token
        _login.refresh_time = datetime.now()
        db.session.commit()
        return jsonify(access_token=access_token)
    return jsonify(access_token=str(-1))


if __name__ == '__main__':
    port = int(cfg['server']['port'])
    server = pywsgi.WSGIServer(('0.0.0.0', port), app)
    server.serve_forever()
