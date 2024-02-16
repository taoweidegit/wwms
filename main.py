import json
import os
from datetime import datetime, timedelta
from urllib.parse import quote_plus as urlquote
from gevent import pywsgi

import oss2
import requests
import stomp
import yaml
from flask import Flask, render_template, request, jsonify, send_file
from flask_jwt_extended import (JWTManager, jwt_required, create_access_token, get_jwt_identity, create_refresh_token,
                                decode_token)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text, desc

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
    = f"mysql+pymysql://{db_user}:{urlquote(db_password)}@{db_host}:{db_port}/{db_database}?charset=utf8"
db = SQLAlchemy(app)

app.config['JWT_SECRET_KEY'] = 'twei3131'
app.config["JWT_TOKEN_LOCATION"] = ["headers", "cookies", "json", "query_string"]
jwt = JWTManager(app)

mq_host = cfg['message']['host']
mq_port = int(cfg['message']['port'])
mq_conn = stomp.Connection([(mq_host, mq_port)])
mq_conn.connect()

wechat_mini_program_app_id = cfg['wx']['app_id']
wechat_mini_program_app_secret = cfg['wx']['app_secret']


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
    is_delete = db.Column('IS_Delete', db.String)


class Ware(db.Model):
    __tablename__ = 't_ware'

    id = db.Column('ID', db.Integer, primary_key=True)
    name = db.Column('Name', db.String)
    model = db.Column('Model', db.Integer)
    kind = db.Column('Kind', db.Integer)
    item_number = db.Column('ItemNumber', db.String)


class WareKind(db.Model):
    __tablename__ = 't_ware_kind'

    id = db.Column('ID', db.Integer, primary_key=True)
    name = db.Column('Name', db.String)
    pid = db.Column('Pid', db.Integer)


class Unit(db.Model):
    __tablename__ = 't_unit'

    id = db.Column('ID', db.Integer, primary_key=True)
    name = db.Column('Name', db.String)


class Company(db.Model):
    __tablename__ = 't_company'

    id = db.Column('ID', db.Integer, primary_key=True)
    name = db.Column('Name', db.String)


class _Model(db.Model):
    __tablename__ = 't_model'

    id = db.Column('ID', db.Integer, primary_key=True)
    kind = db.Column('Kind', db.Integer)
    name = db.Column('Name', db.String)
    company = db.Column('Company', db.Integer)
    unit = db.Column('Unit', db.Integer)


class Apply(db.Model):
    __tablename__ = 't_apply'

    id = db.Column('ID', db.Integer, primary_key=True)
    applicant = db.Column('Applicant', db.Integer)
    ware_quantity = db.Column('WareQuantity', db.Integer)
    application_time = db.Column('ApplicationTime', db.DateTime)
    state = db.Column('State', db.String)
    warehousing_time = db.Column('WarehousingTime', db.DateTime)
    ware = db.Column('Ware', db.Integer)
    apply_quantity = db.Column('ApplyQuantity', db.Integer)
    warehouse = db.Column('Warehouse', db.Integer)
    apply_id = db.Column('ApplyId', db.String)
    apply_start_id = db.Column('ApplyStartId', db.Integer)


class ApplyStart(db.Model):
    __tablename__ = 't_apply_start'

    id = db.Column('ID', db.Integer, primary_key=True)
    name = db.Column('Name', db.String)
    start_date = db.Column('StartDate', db.DateTime)
    end_date = db.Column('EndDate', db.DateTime)


class Inventory(db.Model):
    __tablename__ = 't_inventory'

    id = db.Column('ID', db.Integer, primary_key=True)
    model = db.Column('Model', db.Integer)
    state = db.Column('State', db.String)
    shelve = db.Column('Shelve', db.Integer)
    production_number = db.Column('ProductionNumber', db.String)
    _apply = db.Column('Apply', db.Integer)
    using_place = db.Column('UsingPlace', db.Integer)
    process_id = db.Column('Process', db.String)


def send_message_with_logout(queue_listener):
    requests.get(f'http://127.0.0.1:8080/queue/sendMessage?queueName={queue_listener}&&message=logout')


def send_message_with_keep_alive(queue_listener):
    requests.get(f'http://127.0.0.1:8080/queue/sendMessage?queueName={queue_listener}&&message=keep')


@app.route('/', endpoint='index_page')
def index():
    print('hello')
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
    _login.state = 'online'
    db.session.commit()

    # send_message_with_login(_login.queue_listener)

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
        pages = ['spare/query']
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

            # menuInfo_child["child"].append({
            #     "title": "备件查询",
            #     "href": "page/icon-picker.html",
            #     "icon": "fa fa-adn",
            #     "target": "_self"
            # })
            menuInfo_child["child"].append({
                "title": "备件申请记录",
                "href": f'{request.host_url}ware/page/management',
                "icon": "fa fa-adn",
                "target": "_self"
            })

            if sys_it == "all":
                menuInfo_child["child"].append({
                    "title": "备件采购管理",
                    "href": f"{request.host_url}plan/page/management?jwt={request.values.get('jwt')}",
                    "icon": "fa fa-cubes",
                    "target": "_self"
                })
            menuInfo.append(menuInfo_child)

        if classify == "stock":
            menuInfo_child = {
                "title": "库存管理",
                "icon": "fa fa-slideshare",
                "href": "",
                "target": "_self",
                "child": []
            }

            if sys_it == "all":
                menuInfo_child["child"].append({
                    "title": "备件入库",
                    "href": f"{request.host_url}stock/page/instock",
                    "icon": "fa fa-superpowers",
                    "target": "_self"
                })
                menuInfo_child["child"].append({
                    "title": "仓库管理",
                    "href": f'{request.host_url}warehouse/page/warehouse?jwt={request.values.get("jwt")}',
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
                                                 f"FROM t_warehouse_administrator administrator_of_warehouse "
                                                 f"JOIN t_warehouse warehouse "
                                                 f"ON administrator_of_warehouse.Warehouse = warehouse.ID "
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


@app.route('/department/get', endpoint="/department/get_department_list")
def get_department_list():
    department_list = db.session.query(Department).all()
    response = []
    for department in department_list:
        response.append({
            'id': department.id,
            'name': department.name
        })
    return jsonify(response)


@app.route('/user/getUserList', endpoint="/user/get_user_list")
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
    uid = request.values.get("uid")

    mode = 'add' if uid is None else 'edit'

    department_list = db.session.query(Department).all()
    department_item = []
    for it in department_list:
        department_item.append({
            "id": it.id,
            "name": it.name,
            "selected": ""
        })

    role_list = db.session.query(Role).all()
    role_item = []
    for it in role_list:
        role_item.append({
            "id": it.id,
            "name": it.name,
            "selected": ""
        })

    if uid is not None:
        user = db.session.query(User).filter(User.id == uid).first()
        user_response = {
            "name": user.name,
            "mobile": user.mobile,
            "eid": user.employee_id
        }
        for i in range(len(department_item)):
            if int(department_item[i]["id"]) == int(user.department):
                department_item[i]["selected"] = "selected"
                break
        for i in range(len(role_item)):
            if int(role_item[i]["id"]) == int(user.role):
                role_item[i]["selected"] = "selected"
                break
    else:
        user_response = {
            "name": "",
            "mobile": "",
            "eid": ""
        }
    return render_template("./add_or_edit_user.html",
                           mode=mode,
                           user_response=user_response,
                           department_list=department_item,
                           role_list=role_item)


@app.route('/warehouse/get', endpoint="/warehouse/get_warehouse_list")
def get_warehouse():
    warehouse_list = db.session.query(WareHouse).all()
    data = list()
    for warehouse in warehouse_list:
        data.append({
            "id": warehouse.id,
            "name": warehouse.name,
            "place": warehouse.position
        })

    response = {
        "code": 0,
        "msg": "",
        "count": len(data),
        "data": data
    }
    return jsonify(response)


@app.route('/user/add', methods=["POST"], endpoint="/user/add_or_edit_user")
def add_user():
    username = request.json.get("username")
    phone = request.json.get("phone")
    eid = request.json.get("eid")
    department = int(request.json.get("department"))
    role = int(request.json.get("role"))
    is_warehouse_admin = request.json.get("is_warehouse_admin")
    warehouse = request.json.get("warehouse")

    user = db.session.query(User).filter(User.employee_id == eid).first()

    is_add = user is None
    if user is None:
        user = User()

    user.employee_id = eid
    user.mobile = phone
    user.name = username
    user.role = role
    user.department = department

    if is_add:
        db.session.add(user)
    db.session.commit()

    if is_warehouse_admin is not None:
        if is_warehouse_admin == 'on':
            admin_of_warehouse = (db.session.query(AdministratorOfWareHouse)
                                  .filter(AdministratorOfWareHouse.administrator == user.id).all())
            managed_warehouse_id = [int(it.id) for it in admin_of_warehouse]
            for it in warehouse:
                if int(it) in managed_warehouse_id:
                    continue
                aw = AdministratorOfWareHouse()
                aw.warehouse = it
                aw.administrator = user.id
                aw.role = 'outbound'
                aw.is_master = 'N'
                aw.is_delete = 'N'
                db.session.add(aw)
                db.session.commit()

    return jsonify(code=Response.ok)


@app.route('/warehouse/page/warehouse', methods=['GET'], endpoint='warehouse_page')
@jwt_required(locations=["query_string"])
def warehouse_page():
    identity = get_jwt_identity()
    uid = identity.get('uid')

    result = (User.query.join(Role, Role.id == User.role).filter(User.id == uid)
              .with_entities(Role.rank).all())

    mode = ""

    for rank in result:
        if rank[0] <= 0:
            mode = "add_warehouse"
            break

    return render_template("./warehouse_management.html", mode=mode)


@app.route('/warehouse/page/adding', methods=['GET'], endpoint='adding_warehouse_page')
def warehouse_adding_page():
    return render_template("./add_warehouse.html")


@app.route('/warehouse/add', methods=['POST'], endpoint='/warehouse/add_warehouse')
def warehouse_adding_page():
    name = request.json.get("name")
    place = request.json.get("place")

    warehouse = db.session.query(WareHouse).filter(WareHouse.name == name).first()
    if warehouse is not None:
        return jsonify(code=Response.repeat_warehouse)

    warehouse = WareHouse()
    warehouse.name = name
    warehouse.position = place

    db.session.add(warehouse)
    db.session.commit()

    # 添加计量专员为仓库入库管理员
    metrology_specialist = (db.session.query(User)
                            .join(Role, User.role == Role.id)
                            .filter(Role.name == '计量专员')
                            .first())
    new_admin_of_warehouse = AdministratorOfWareHouse()
    new_admin_of_warehouse.warehouse = warehouse.id
    new_admin_of_warehouse.role = 'Inbound'
    new_admin_of_warehouse.is_delete = 'N'
    new_admin_of_warehouse.is_master = 'Y'
    new_admin_of_warehouse.administrator = metrology_specialist.id
    db.session.add(new_admin_of_warehouse)
    db.session.commit()

    return jsonify(code=Response.ok)


@app.route('/warehouse/page/administrator', methods=['GET'], endpoint='administrator_warehouse_page')
def administrator_management():
    warehouse_id = request.values.get("warehouse")

    warehouse_admin_list = (db.session.query(AdministratorOfWareHouse)
                            .filter(AdministratorOfWareHouse.warehouse == warehouse_id,
                                    AdministratorOfWareHouse.is_delete == 'N')
                            .all())

    warehouse_admin_uid_list_str = ''
    i = 0
    total_count = 0
    for _ in warehouse_admin_list:
        total_count += 1

    for warehouse_admin in warehouse_admin_list:
        warehouse_admin_uid_list_str += str(warehouse_admin.administrator)
        i += 1
        if i < total_count:
            warehouse_admin_uid_list_str += ','

    return render_template("./warehouse_administrator.html",
                           warehouse_id=warehouse_id,
                           warehouse_admin_uid=warehouse_admin_uid_list_str)


@app.route('/warehouse/administrator/get', methods=['GET'], endpoint='/warehouse/get_warehouse_administrator')
def get_warehouse_administrator():
    warehouse_id = request.values.get("warehouse")
    sql = text(
        f"SELECT "
        f"USER.`Name` AS name, "
        f"User.ID AS uid, "
        f"wa.ID AS warehouse_id, "
        f"USER.Eid AS employee_id, "
        f"department.`Name` AS department, "
        f"role.`Name` AS role, "
        f"wa.IS_Master AS is_master, "
        f"wa.Role AS type, "
        f"wa.ID as warehouse_administrator_id "
        f"FROM t_warehouse_administrator wa "
        f"JOIN t_user USER ON wa.Administrator = USER.ID "
        f"JOIN t_role role ON USER.Role = role.ID "
        f"JOIN t_department department ON department.ID = USER.Department "
        f"WHERE wa.Warehouse = {warehouse_id} AND wa.IS_Delete = 'N'"
    )
    result = db.session.execute(sql)

    warehouse_admin_list = []
    for it in result:
        warehouse_admin_list.append({
            "name": it[0],
            "uid": it[1],
            "employee_id": it[3],
            "department_name": it[4],
            "role_name": it[5],
            "is_master": it[6],
            "type": it[7],
            "id": it[8]
        })

    response = {
        "code": 0,
        "msg": "",
        "count": len(warehouse_admin_list),
        "data": warehouse_admin_list
    }
    return jsonify(response)


@app.route('/warehouse/administrator/add', methods=['POST'], endpoint='/warehouse/add_warehouse_administrator')
def add_warehouse_administrator():
    data = request.json.get("data")
    warehouse_id = request.json.get("warehouse")

    add_count = 0

    for it in data:
        warehouse_admin = (db.session.query(AdministratorOfWareHouse)
                           .filter(AdministratorOfWareHouse.administrator == it,
                                   AdministratorOfWareHouse.warehouse == str(warehouse_id))
                           .first())
        if warehouse_admin is None:
            new_warehouse_admin = AdministratorOfWareHouse()
            new_warehouse_admin.administrator = it
            new_warehouse_admin.warehouse = warehouse_id
            new_warehouse_admin.role = 'Outbound'
            new_warehouse_admin.is_master = 'N'
            new_warehouse_admin.is_delete = 'N'
            db.session.add(new_warehouse_admin)
            db.session.commit()
            add_count += 1
        else:
            if warehouse_admin.is_delete == 'Y':
                warehouse_admin.is_delete = 'N'
                db.session.commit()
                add_count += 1
            else:
                pass
    if add_count == 0:
        return jsonify(code=Response.repeat_warehouse_admin)
    return jsonify(code=Response.ok)


@app.route('/warehouse/administrator/remove', methods=['POST'], endpoint='/warehouse/remove_warehouse_administrator')
def remove_warehouse_administrator():
    warehouse_administrator_id = request.values.get("id")
    warehouse_administrator = (db.session.query(AdministratorOfWareHouse)
                               .filter(AdministratorOfWareHouse.id == warehouse_administrator_id)
                               .first())
    if warehouse_administrator is not None:
        if warehouse_administrator.role == 'Outbound':
            warehouse_administrator.is_delete = 'Y'
            db.session.commit()
    return jsonify(code=Response.ok)


@app.route('/ware/page/management', methods=['GET'], endpoint='ware_management_page')
def ware_management_page():
    if db.session.query(ApplyStart).count() == 0:
        has_start_plan = False
    else:
        starting_plan = db.session.query(ApplyStart).filter(ApplyStart.end_date == None).first()
        has_start_plan = starting_plan is not None

    return render_template("./ware_management.html", has_start_plan=has_start_plan)


@app.route('/ware/application', methods=['POST'], endpoint='ware/get_application')
@jwt_required(locations=["query_string"])
def get_ware_application():
    page = int(request.form.get("page"))
    limit = int(request.form.get("limit"))

    identity = get_jwt_identity()
    uid = identity.get('uid')

    search_params = request.form.get("searchParams")
    apply_state = 'pending'
    if search_params is not None:
        apply_state = json.loads(search_params)['apply_state']

    user = db.session.query(User).filter(User.id == uid).first()

    data = []

    apply_list = (db.session.query(Apply)
                  .filter(Apply.applicant == uid, Apply.state == apply_state)
                  .order_by(desc(Apply.application_time))
                  .paginate(page=page, per_page=limit)
                  .items)
    for apply in apply_list:
        applicant_user = user.name
        apply_id = apply.id

        apply_quantity = str(apply.apply_quantity) if apply.apply_quantity is not None else ''
        ware_quantity = str(apply.ware_quantity) if apply.ware_quantity is not None else '0'
        # warehousing_time = apply.warehousing_time
        apply_time = apply.application_time.strftime("%Y-%m-%d %H:%M:%S")

        ware = db.session.query(Ware).filter(Ware.id == apply.ware).first()
        if ware.model is not None:
            _model = db.session.query(_Model).filter(_Model.id == ware.model).first()
            kind = db.session.query(WareKind).filter(WareKind.id == ware.kind).first()
            ware_model = _model.name
            ware_kind = kind.name

            if _model.company is not None:
                company = db.session.query(Company).filter(Company.id == _model.company).first()
                ware_company = company.name
            else:
                ware_company = "无"

            if _model.unit is not None:
                unit = db.session.query(Unit).filter(Unit.id == _model.unit).first()
                _unit = unit.name
            else:
                _unit = "件"
        else:
            ware_model = "无"
            ware_company = "无"
            _unit = "件"
            ware_kind = ""

        ware_number = ware.item_number if ware.item_number is not None else '-'

        warehouse_id = apply.warehouse
        if warehouse_id is not None:
            warehouse = db.session.query(WareHouse).filter(WareHouse.id == warehouse_id).first()
            warehouse_name = warehouse.name
        else:
            warehouse_name = '无'

        state = apply.state

        data.append({
            "id": apply_id,
            "applicant": applicant_user,
            "ware_quantity": ware_quantity,
            "apply_quantity": apply_quantity,
            "time": apply_time,
            "model": ware_model,
            "company": ware_company,
            "item_number": ware_number,
            "unit_name": _unit,
            "warehouse": warehouse_name,
            "state": state,
            "ware_kind": ware_kind
        })

    response = {
        "code": 0,
        "msg": "",
        "count": len(data),
        "data": data
    }
    return jsonify(response)


@app.route('/ware/page/apply', methods=['GET'], endpoint='ware_apply_page')
def apply_page():
    return render_template("./ware_apply.html")


@app.route('/kind/top/get', methods=['GET'], endpoint='/kind/get_top_kind')
def get_kind():
    response = []
    ware_kind_list = db.session.query(WareKind).filter(WareKind.pid == 0).all()
    for top_kind in ware_kind_list:
        response.append({
            "id": top_kind.id,
            "name": top_kind.name
        })
    return jsonify(response)


@app.route('/kind/child/get', methods=['POST'], endpoint='/kind/get_child_kind')
def get_child_kind():
    top_kind_id = request.json.get("top")

    response = []
    child_kind_list = db.session.query(WareKind).filter(WareKind.pid == top_kind_id).all()
    for child_kind in child_kind_list:
        response.append({
            "id": child_kind.id,
            "name": child_kind.name
        })
    return jsonify(response)


@app.route('/model/kind/get', methods=['POST'], endpoint='/kind/get_model_by_kind')
def get_model_by_kind():
    kind = request.json.get('kind')

    lst = []

    kind_entity = db.session.query(WareKind).filter(WareKind.id == kind).first()
    top_kind_entity = db.session.query(WareKind).filter(WareKind.id == kind_entity.pid).first()

    model_list = db.session.query(_Model).filter(_Model.kind == kind).all()
    if len(model_list) == 0:
        kind = top_kind_entity.id
        model_list = db.session.query(_Model).filter(_Model.kind == kind).all()

    for _model in model_list:
        item = {
            "id": _model.id,
            "name": _model.name,
            "company": {},
            "unit": {}
        }
        if _model.company is not None:
            company = db.session.query(Company).filter(Company.id == _model.company).first()
            item["company"] = {
                "id": company.id,
                "name": company.name
            }

        if _model.unit is not None:
            _unit = db.session.query(Unit).filter(Unit.id == int(_model.unit)).first()
            item["unit"] = {
                "id": _unit.id,
                "name": _unit.name
            }
        lst.append(item)

    return jsonify(lst)


@app.route('/ware/apply', methods=['POST'], endpoint='/ware/apply')
@jwt_required()
def apply_ware():
    child_type = request.json.get("child_type")
    mod = request.json.get("model")
    quantity = request.json.get("quantity")

    state = 'pending'

    identity = get_jwt_identity()
    uid = identity.get('uid')

    apply = Apply()
    apply.apply_quantity = quantity
    apply.applicant = uid
    apply.state = state
    apply.application_time = datetime.now()

    ware = db.session.query(Ware).filter(Ware.model == mod).first()
    apply.ware = ware.id

    db.session.add(apply)
    db.session.commit()

    post_data = {
        "uid": uid,
        "form": apply.id
    }

    try:
        headers = {'Content-Type': 'application/json'}
        requests.post(url='http://127.0.0.1:8080/process/model/apply/start', headers=headers,
                      data=json.dumps(post_data))
    except:
        _apply = db.session.query(Apply).filter(Apply.id == apply.id).first()
        db.session.delete(_apply)
        db.session.commit()
        return jsonify(code=Response.error)

    return jsonify(code=Response.ok)


@app.route('/plan/page/management', methods=['GET'], endpoint='plan_management_page')
@jwt_required(locations=["query_string"])
def plan_management_page():
    identity = get_jwt_identity()
    uid = identity.get('uid')

    user = db.session.query(User).filter(User.id == uid).first()
    if user is None:
        return render_template("./404.html")

    role = db.session.query(Role).filter(Role.id == user.role).first()
    if role.rank > 1:
        return render_template("./404.html")

    if db.session.query(ApplyStart).count() != 0:
        starting_plan = db.session.query(ApplyStart).filter(ApplyStart.end_date == None).first()
        has_starting_plan = starting_plan is not None
    else:
        has_starting_plan = False

    return render_template("./buying_plan_management.html", has_starting_plan=has_starting_plan)


@app.route('/plan/get', methods=['GET'], endpoint='/plan/get_plan')
def get_plan_list():
    plan_list = (
        db.session.query(ApplyStart).filter(ApplyStart.start_date >= datetime.now() - timedelta(days=90)).all())
    dlist = []
    i = 1
    for plan in plan_list:
        start_date, end_date = None, None
        if plan.start_date is not None:
            start_date = plan.start_date.strftime("%Y-%m-%d")
        if plan.end_date is not None:
            end_date = plan.end_date.strftime("%Y-%m-%d")

        apply_list = db.session.query(Apply).filter(Apply.apply_start_id == plan.id).all()
        dlist.append({
            "id": i,
            "_id": plan.id,
            "name": start_date if plan.end_date is None else f"{start_date}/{end_date}",
            "applicant": "",
            "eid": "",
            "type": "",
            "apply_num": "",
            "parentId": 0,
            "is_pass": "none"
        })
        parent_id = i

        i += 1

        for apply in apply_list:
            ware = db.session.query(Ware).filter(Ware.id == apply.ware).first()
            _model = db.session.query(_Model).filter(_Model.id == ware.model).first()
            user = db.session.query(User).filter(User.id == apply.applicant).first()
            kind = db.session.query(WareKind).filter(WareKind.id == _model.kind).first()

            is_pass = 'none'

            # 获取flowable状态
            try:
                r = requests.get(f'http://127.0.0.1:8080/process/model/apply/state?form={apply.id}')
                if r.content.decode() == '200':
                    # 同意
                    is_pass = 'yes'
                elif r.content.decode() == '202':
                    is_pass = 'none'
                    # 未抵达计量专员
                elif r.content.decode() == '203':
                    # 抵达计量专员,未处理
                    is_pass = 'uncheck'
                elif r.content.decode() == '201':
                    # 拒绝
                    is_pass = 'no'
            except:
                pass

            dlist.append({
                "id": i,
                "_id": apply.id,
                "name": _model.name,
                "applicant": user.name,
                "eid": user.employee_id,
                "apply_num": apply.apply_quantity,
                "type": kind.name if kind is not None else "",
                "parentId": parent_id,
                "is_pass": is_pass
            })
            i += 1

    response = {
        "code": Response.ok,
        "msg": "",
        "data": dlist,
        "count": len(dlist)
    }
    return jsonify(response)


@app.route('/plan/start', methods=['POST'], endpoint='/plan/start_plan')
def start_plan():
    apply_start = ApplyStart()
    apply_start.start_date = datetime.now()
    db.session.add(apply_start)
    db.session.commit()

    return jsonify(code=200)


@app.route('/plan/end', methods=['POST'], endpoint='/plan/end_plan')
def end_plan():
    plan = db.session.query(ApplyStart).filter(ApplyStart.end_date == None).first()
    if plan is not None:
        apply_start_id = plan.id
        wait_approval_apply_list = (
            db.session.query(Apply).filter(Apply.apply_start_id == apply_start_id, Apply.state == 'pending').all())
        id_list = []
        for wait_approval_apply in wait_approval_apply_list:
            id_list.append(wait_approval_apply.apply_id)

        try:
            post_data = {
                "data": id_list
            }
            headers = {'Content-Type': 'application/json'}
            requests.post(url='http://127.0.0.1:8080/process/plan/apply/end', headers=headers,
                          data=json.dumps(post_data))
        except:
            return jsonify(code=Response.error)

        # 下载各个备件申请的excel表格
        try:
            requests.get(f'http://127.0.0.1:8080/process/plan/end/excel?planId={apply_start_id}')
        except:
            return jsonify(code=Response.error)

        plan.end_date = datetime.now()
        db.session.commit()

    return jsonify(code=Response.ok)


@app.route('/ware/application/accept', methods=['POST'], endpoint='/ware/accept')
def accept_apply():
    apply_id = request.json.get('apply')

    apply = db.session.query(Apply).filter(Apply.id == apply_id).first()
    if apply is not None:
        try:
            requests.get(f'http://127.0.0.1:8080/process/model/apply/accept?applyId={apply.id}')
        except:
            return jsonify(code=Response.error)

    return jsonify(code=Response.ok)


@app.route('/ware/application/reject', methods=['POST'], endpoint='/ware/reject')
def reject_apply():
    apply_id = request.json.get('apply')

    apply = db.session.query(Apply).filter(Apply.id == apply_id).first()
    if apply is not None:
        try:
            requests.get(f'http://127.0.0.1:8080/process/model/apply/reject?applyId={apply.id}')
        except:
            return jsonify(code=Response.error)

    return jsonify(code=Response.ok)


@app.route('/plan/download', methods=['GET'], endpoint='/plan/download')
def download_excel_plan():
    access_key_id = 'LTAI5tFL2ZNX4etwRnV65GkJ'
    access_key_secret = 'pCSMAFuTbLKbGmBvr7Ad0OXJsKZx97'
    auth = oss2.Auth(access_key_id=access_key_id, access_key_secret=access_key_secret)

    endpoint = 'https://oss-cn-hangzhou.aliyuncs.com'
    bucket = oss2.Bucket(auth, endpoint, 'wmms')
    download_file_path = './采购计划.xlsx'
    bucket.get_object_to_file('采购计划.xlsx', download_file_path)

    return send_file(download_file_path, as_attachment=True)


@app.route('/stock/page/instock', methods=['GET'], endpoint='/in_stock_page')
def in_stock_page():
    return render_template('./in_stock.html')


@app.route('/stock/applicant/get', methods=['GET'], endpoint='/stock/get_stock_applicant')
def get_stock_applicant():
    apply_list = (
        db.session.query(Apply)
        .filter(Apply.application_time >= datetime.now() - timedelta(days=30 * 6), Apply.state == 'approving')
        .all())
    applicant_list = list()
    for apply in apply_list:
        user = db.session.query(User).filter(User.id == apply.applicant).first()
        if user.id in [item["id"] for item in applicant_list]:
            continue
        applicant_list.append({"id": user.id, "name": user.name})
    return jsonify(applicant_list)


@app.route('/stock/type/get', methods=['GET'], endpoint='/stock/get_type_by_applicant')
def get_type_by_applicant():
    applicant = request.values.get('applicant')
    apply_list = (db.session.query(Apply)
                  .filter(Apply.applicant == applicant,
                          Apply.state == 'approving',
                          Apply.application_time >= datetime.now() - timedelta(days=30 * 6))
                  .all())
    type_list = []
    for apply in apply_list:
        ware = db.session.query(Ware).filter(Ware.id == apply.ware).first()
        ware_kind = db.session.query(WareKind).filter(WareKind.id == ware.kind).first()
        if ware_kind.id in [item["id"] for item in type_list]:
            continue
        type_list.append({"id": ware_kind.id, "name": ware_kind.name})
    return jsonify(type_list)


@app.route('/stock/instock/apply', methods=['GET'], endpoint='/stock/get_apply_by_applicant_and_type')
def get_apply_by_applicant_and_type():
    page = 1 if request.args.get("page") is None else int(request.args.get("page"))
    limit = 10 if request.args.get("limit") is None else int(request.args.get("limit"))

    data = []

    if request.args.get("searchParams") is None:
        apply_list = (
            db.session.query(Apply)
            .filter(
                Apply.application_time >= datetime.now() - timedelta(days=30 * 6),
                Apply.state == 'approving'
            )
            .order_by(desc(Apply.application_time))
            .paginate(page=page, per_page=limit)
            .items)
    else:
        json_obj = json.loads(request.args.get("searchParams"))
        kind = db.session.query(WareKind).filter(WareKind.id == json_obj['type']).first()
        ware_list = db.session.query(Ware).filter(Ware.kind == kind.id).all()
        apply_list = []
        for ware in ware_list:
            apply_items = (
                db.session.query(Apply)
                .filter(
                    Apply.application_time >= datetime.now() - timedelta(days=30 * 6),
                    Apply.state == 'approving',
                    Apply.applicant == json_obj['applicant'],
                    Apply.ware == ware.id
                )
                .order_by(desc(Apply.application_time))
                .paginate(page=page, per_page=limit)
                .items)
            for apply_item in apply_items:
                apply_list.append(apply_item)

    for apply in apply_list:
        ware = db.session.query(Ware).filter(Ware.id == apply.ware).first()
        kind = db.session.query(WareKind).filter(WareKind.id == ware.kind).first()
        user = db.session.query(User).filter(User.id == apply.applicant).first()
        department = db.session.query(Department).filter(Department.id == user.department).first()
        model = db.session.query(_Model).filter(_Model.id == ware.model).first()

        company_name = ''
        if model.company is not None and model.company != '':
            company = db.session.query(Company).filter(Company.id == model.company).first()
            company_name = company.name

        data.append({
            "id": apply.id,
            "applicant_name": user.name,
            "applicant_id": user.id,
            "department": department.name,
            "kind": kind.name,
            "model_name": model.name,
            "model_id": model.id,
            "quantity": apply.apply_quantity,
            "company": company_name
        })

    return jsonify({
        "code": 0,
        "msg": "",
        "count": len(data),
        "data": data
    })


@app.route('/stock/instock/process/start', methods=['POST'], endpoint='/stock/process/start')
def start_instock_process():
    # 备件申请Id
    apply_id = request.json.get('apply_id')
    ware_count = request.json.get('ware_count')
    if apply_id is None:
        # 无申请人申请备件的情况，入库
        model_id = request.json.get('model_id')
        post_data = {
            "apply_id": "",
            "model_id": model_id,
            "ware_count": ware_count,
            "applicant_id": request.json.get('applicant_id')
        }
    else:
        # 之前有备件申请的情况，入库
        apply = db.session.query(Apply).filter(Apply.id == apply_id).first()
        ware = db.session.query(Ware).filter(Ware.id == apply.ware).first()
        model = db.session.query(_Model).filter(_Model.id == ware.model).first()

        apply.state = "done"
        db.session.commit()

        model_id = model.id
        ware_count = (
            apply.apply_quantity) if int(apply.apply_quantity) < int(ware_count) else ware_count

        post_data = {
            "apply_id": apply_id,
            "model_id": model_id,
            "ware_count": ware_count,
            "applicant_id": apply.applicant
        }

    # 插入数据库
    inventory_id_list = []
    for i in range(ware_count):
        inventory = Inventory()
        inventory.model = model_id
        inventory.state = 'instock'
        if apply_id is not None:
            inventory._apply = apply_id
        db.session.add(inventory)
        db.session.commit()

        inventory_id_list.append(inventory.id)

    # 向flowable发送请求
    post_data['inventory_id'] = inventory_id_list
    post_json = json.dumps(post_data)
    headers = {'Content-Type': 'application/json'}
    try:
        requests.post('http://127.0.0.1:8080/process/instock/apply/start', headers=headers, data=post_json)
    except:
        for inventory_id in inventory_id_list:
            _inventory = db.session.query(Inventory).filter(Inventory.id == inventory_id).first()
            db.session.delete(_inventory)
            db.session.commit()
        return jsonify(code=Response.error)

    return jsonify(code=Response.ok)


@app.route('/stock/page/instock/form', methods=['GET'], endpoint='in_stock_without_apply_page')
def in_stock_page():
    user_list = db.session.query(User).all()
    lst = []
    for user in user_list:
        lst.append({
            "name": user.name,
            "id": user.id
        })
    return render_template('./instock_without_apply.html', applicant=lst)


@app.route('/wx/login', methods=['GET'], endpoint='/wx/login')
def wx_login():
    wx_code = request.values.get("code")
    employee_id = request.values.get("employee")

    data = None

    try:
        response = requests.get(f'https://api.weixin.qq.com/sns/jscode2session?appid={wechat_mini_program_app_id}'
                                f'&&secret={wechat_mini_program_app_secret}'
                                f'&&js_code={wx_code}'
                                f'&&grant_type=authorization_code')
        response_data = json.loads(response.content)
        err_code = int(response_data['errcode'])
        if err_code == 0:
            open_id = response_data['openid']
            session_key = response_data['session_key']
            union_id = response_data['unionid']

            data = json.dumps({
                "open_id": open_id,
                "session_key": session_key,
                "union_id": union_id})
    except:
        return jsonify(code=Response.error)

    # 自动根据wechat信息查找用户
    if employee_id == '':
        user = db.session.query(User).filter(User.wechat_id == data).first()
        if user is None:
            return jsonify(code=Response.not_found_user)

        role = db.session.query(Role).filter(Role.id == user.role).first()
        rank = role.rank
        return jsonify(code=Response.ok, rank=rank)

    # 用户工号与微信未绑定
    user = db.session.query(User).filter(User.employee_id == employee_id).first()
    if user is None:
        return jsonify(code=Response.not_found_user)

    user.wechat_id = data
    db.session.commit()

    role = db.session.query(Role).filter(Role.id == user.role).first()
    rank = role.rank

    return jsonify(code=Response.ok, rank=rank)


if __name__ == '__main__':
    port = int(cfg['server']['port'])
    server = pywsgi.WSGIServer(('0.0.0.0', 5000), app)
    server.serve_forever()
