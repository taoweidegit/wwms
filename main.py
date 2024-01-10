import json
import os
import time
from datetime import datetime, timedelta

import yaml
import requests
from flask import Flask, render_template, request, jsonify
import stomp

from gevent import pywsgi
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (JWTManager, jwt_required, create_access_token, get_jwt_identity, set_access_cookies,
                                create_refresh_token, unset_jwt_cookies, decode_token)
from sqlalchemy import text

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
    rank = db.Column('Rank', db.Integer)


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


class WareHouse(db.Model):
    __tablename__ = 't_warehouse'

    id = db.Column('ID', db.Integer, primary_key=True)
    name = db.Column('Name', db.String)
    position = db.Column('Position', db.String)


class AdministratorOfWareHouse(db.Model):
    __tablename__ = 't_warehouse_administrator'

    id = db.Column('ID', db.Integer, primary_key=True)
    administrator = db.Column('Administrator', db.Integer)
    role = db.Column('Role', db.String)
    warehouse = db.Column('Warehouse', db.String)
    is_master = db.Column('IS_Master', db.String)


def send_message_with_logout(queue_listener):
    requests.get(f'http://127.0.0.1:8080/queue/sendMessage?queueName={queue_listener}&&message=logout')


def send_message_with_keep_alive(queue_listener):
    requests.get(f'http://127.0.0.1:8080/queue/sendMessage?queueName={queue_listener}&&message=keep')


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

    # mq_conn.send(_login.queue_listener, 'keep')
    send_message_with_keep_alive(_login.queue_listener)

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
            queue_listener=f'channel_{str(uid)}_{device}',
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
            send_message_with_logout(queue_listener)
        # 新设备上线
        _login = db.session.query(Login).filter(Login.id == login_list[0].id).first()
        _login.state = 'online'
        _login.queue_listener = f'channel_{str(uid)}_{device}'
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

    # mq_conn.send(_login.queue_listener, 'logout')
    send_message_with_logout(_login.queue_listener)

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
    # if _login.state != 'logout':
    _login.access_token = access_token
    _login.refresh_time = datetime.now()
    db.session.commit()
    return jsonify(access_token=access_token)
    # return jsonify(access_token=str(-1))


@app.route('/user/getInfo', methods=['POST'], endpoint='/user/getInfo')
@jwt_required(locations=["headers"])
def get_user_by_token():
    identity = get_jwt_identity()
    uid = identity.get('uid')

    user = db.session.query(User).filter(User.id == uid).first()
    if user is None:
        return jsonify(code=Response.not_found_user)

    return jsonify(code=Response.ok, name=user.name)


@app.route('/user/page/user', methods=['GET'], endpoint='user_page')
def user_page():
    department_list = db.session.query(Department).all()
    lst = []
    for department in department_list:
        lst.append({
            'id': department.id,
            'name': department.name
        })
    return render_template("./user_management.html", department_list=lst)


@app.route('/user/pages', endpoint="get_page_list")
@jwt_required(locations=["query_string"])
def get_page_list():
    identity = get_jwt_identity()
    uid = identity.get('uid')

    result = {
        "homeInfo": {
            "title": "首页",
            "href": "static/layui/page/welcome-1.html?t=1"
        },
        "logoInfo": {
            "title": "三电仓库",
            "image": "static/layui/images/logo.png",
            "href": ""
        }
    }

    user = db.session.query(User).filter(User.id == uid).first()
    role = db.session.query(Role).filter(Role.id == user.role).first()
    rank = role.rank
    if rank <= 2:
        pages = ['user/all', 'spare/all', 'stock/all']
    elif rank == 3:
        pages = ['spare/query', 'stock/apply']
    else:
        pages = []

    menuInfo = []
    for item in pages:
        classify, sys_it = item.split('/')[0], item.split('/')[1]
        if classify == 'user':
            menuInfo_child = {
                "title": "用户管理",
                "icon": "fa fa-user-circle",
                "href": "",
                "target": "_self",
                "child": [
                    {
                        "title": "用户列表",
                        "href": f"{request.host_url}user/page/user",
                        "icon": "fa fa-user-circle",
                        "target": "_self"
                    }
                ]
            }
            menuInfo.append(menuInfo_child)

        if classify == "spare":
            menuInfo_child = {
                "title": "备件管理",
                "icon": "fa fa-lemon-o",
                "href": "",
                "target": "_self",
                "child": []
            }

            menuInfo_child["child"].append({
                "title": "备件查询",
                "href": "page/icon-picker.html",
                "icon": "fa fa-adn",
                "target": "_self"
            })
            menuInfo_child["child"].append({
                "title": "盘库",
                "href": "page/icon-picker.html",
                "icon": "fa fa-adn",
                "target": "_self"
            })

            if sys_it == "all":
                menuInfo_child["child"].append({
                    "title": "备件录入",
                    "href": "page/icon.html",
                    "icon": "fa fa-dot-circle-o",
                    "target": "_self"
                })
            menuInfo.append(menuInfo_child)

        if classify == "stock":
            menuInfo_child = {
                "title": "库存管理",
                "icon": "fa fa-slideshare",
                "href": "",
                "target": "_self",
                "child": [
                    {
                        "title": "备件使用申请",
                        "href": "page/error.html",
                        "icon": "fa fa-superpowers",
                        "target": "_self"
                    }
                ]
            }

            if sys_it == "all":
                menuInfo_child["child"].append({
                    "title": "仓库管理",
                    "href": "",
                    "icon": "fa fa-meetup",
                    "target": "_self"
                })
                menuInfo_child["child"].append({
                    "title": "货架管理",
                    "href": "",
                    "icon": "fa fa-meetup",
                    "target": "_self"
                })

                warehouse_page_list = []
                warehouse_list = db.session.query(WareHouse).all()
                if len(warehouse_list) != 0:
                    if rank <= 2:
                        for warehouse in warehouse_list:
                            warehouse_page_list.append({
                                "title": warehouse.name,
                                "href": "",
                                "icon": "fa fa-meetup",
                                "target": "_self"
                            })
                    elif rank == 3:
                        res = db.session.execute(f"SELECT warehouse.* "
                                                 "FROM t_warehouse_administrator administrator_of_warehouse "
                                                 "JOIN t_warehouse warehouse "
                                                 "ON administrator_of_warehouse.Warehouse = warehouse.ID "
                                                 f"WHERE administrator_of_warehouse.Administrator = {uid}")
                        for it in res:
                            warehouse_page_list.append({
                                "title": it[1],
                                "href": "",
                                "icon": "fa fa-meetup",
                                "target": "_self"
                            })

                menuInfo_child["child"].append({
                    "title": "出入库管理",
                    "href": "page/error.html",
                    "icon": "fa fa-superpowers",
                    "target": "_self",
                    "child": warehouse_page_list
                })
            menuInfo.append(menuInfo_child)

    result["menuInfo"] = menuInfo

    return jsonify(result)


@app.route('/department/get', endpoint="get_department_list")
def get_department_list():
    department_list = db.session.query(Department).all()
    response = []
    for department in department_list:
        response.append({
            'id': department.id,
            'name': department.name
        })
    return jsonify(response)


@app.route('/user/getUserList', endpoint="get_user_list")
def get_user_list():
    page = 1 if request.args.get("page") is None else int(request.args.get("page"))
    limit = 10 if request.args.get("limit") is None else int(request.args.get("limit"))

    if request.args.get("searchParams") is None:
        department_id = None
        user_name = None
    else:
        data = json.loads(request.args.get("searchParams"))
        department_id = data["department"]
        user_name = data["username"]

    if department_id == '':
        department_id = None
    if user_name == '':
        user_name = None

    user_list = list()

    sql = ('SELECT u.ID AS id, '
           'u.`Name` as name, '
           'u.Eid as eid, '
           'u.Wx_id as wx_id, '
           'department.`Name` as department, '
           'role.`Name` as role '
           'FROM t_user u '
           'JOIN t_department department ON u.Department = department.ID '
           'JOIN t_role role ON u.Role = role.ID')

    # 是否添加 WHERE 和 AND
    temp = [department_id, user_name]
    is_add_and = False
    count = 0
    for i in range(len(temp)):
        if temp[i] is not None:
            count += 1
    if count > 0:
        sql += ' WHERE '
    if count > 1:
        is_add_and = True

    if department_id is not None:
        sql += f'department.ID = {department_id}'

    if user_name is not None:
        if is_add_and:
            sql += ' AND '
        sql += f"u.`Name` = '{user_name}'"

    sql = text(sql)
    result = db.session.execute(sql)
    for it in result:
        user = {
            "id": it[0],
            "name": it[1],
            "employee_id": it[2],
            "wechat_id": it[3],
            "department_name": it[4],
            "role_name": it[5]
        }

        user_list.append(user)

    # 分页
    total = len(user_list)
    num_pages = int(total / limit) + 1
    start = (page - 1) * limit
    end = min(page * limit, total)
    page_data = user_list[start:end]

    response = {
        "code": 0,
        "msg": "",
        "count": num_pages,
        "data": page_data
    }

    return jsonify(response)


@app.route('/user/page/adding', endpoint="adding_user_page")
def user_adding_page():
    return render_template("./add_or_edit_user.html")


if __name__ == '__main__':
    port = int(cfg['server']['port'])
    server = pywsgi.WSGIServer(('0.0.0.0', port), app)
    server.serve_forever()
