import pandas as pd
import pymysql

data = pd.read_excel('工作标准测量设备台帐.xlsx', skiprows=[0, 1, 2])
_type = ['电子天平', '包装机', '容量瓶', '压力', '热电偶',
         '热电阻', '温度', '变送器', '液位计', '固体污染源烟气排放连续监测系统',
         '报警', '流量计', '氨氮分析仪', '尺', '百分表', '测温仪', '秤', '轨道衡',
         '物位计', '电流表', '数字显示仪', '测振仪', '电能表',
         '微型环境空气质量监测系统', '粉尘浓度测量仪', '酸度计', '温湿度计', 'DCS控制系统',
         'PLC控制系统', '量筒', '量杯', '移液管', '滴定管', '比色管', '振动监测保护仪', '测速仪']

kind = [
    {"包装机": set()},
    {"容量瓶": set()},
    {"压力表": set()},
    {"热电偶": set()},
    {"热电阻": set()},
    {"温度": set()},
    {"变送器": set()},
    {"液位计": set()},
    {"物位计": set()},
    {"固体污染源烟气排放连续监测系统": set()},
    {"报警器": set()},
    {"流量计": set()},
    {"氨氮分析仪": set()},
    {"尺": set()},
    {"百分表": set()},
    {"测温仪": set()},
    {"秤": set()},
    {"轨道衡": set()},
    {"电流表": set()},
    {"电能表": set()},
    {"数字显示仪": set()},
    {"测振仪": set()},
    {"微型环境空气质量监测系统": set()},
    {"粉尘浓度测量仪": set()},
    {"酸度计": set()},
    {"温湿度计": set()},
    {"控制系统": set()},
    {"量筒": set()},
    {"量杯": set()},
    {"移液管": set()},
    {"滴定管": set()},
    {"比色管": set()},
    {"振动监测保护仪": set()},
    {"测速仪": set()},
    {"电压表": set()},
    {"分析仪": set()},
    {"照度计": set()},
    {"功率因数表": set()},
    {"频率表": set()},
    {"压力控制器": set()},
]

for t in data.iterrows():
    name = t[1][1]
    model = t[1][2]

    flag = False

    if '苯' in name or '报警器' in name or '报警仪' in name:
        kind[10]['报警器'].add(name)
        flag = True
    elif '红外热相仪' in name:
        kind[5]['温度'].add(name)
        flag = True
    elif '振动监视器' in name:
        kind[21]['测振仪'].add(name)
        flag = True
    elif '料位仪' in name:
        kind[8]['物位计'].add(name)
        flag = True
    elif '水位计' in name:
        kind[7]['液位计'].add(name)
        flag = True
    elif '变送器' in name:
        kind[6]['变送器'].add(name)
        flag = True
    elif '数字压力显示仪' in name or '压力计' in name:
        kind[2]['压力表'].add(name)
        flag = True
    elif '电子天平' in name:
        kind[16]['秤'].add(name)
        flag = True
    else:
        i = 0
        for k in kind:
            top_type = list(k.keys())[0]
            if top_type in name:
                kind[i][top_type].add(name)
                flag = True
                break
            i += 1

    if not flag:
        print(name)

conn = pymysql.connect(
    host="127.0.0.1",
    port=3306,
    user="root",
    password="19951017i",
    database="wmms"
)
cursor = conn.cursor()

company = set()

for t in data.iterrows():
    name = t[1][1]
    model = t[1][2]
    company = t[1][7]

    name = name.replace('（', '(').replace('）', ')')

    sql = f'SELECT * FROM t_company WHERE `Name` = "{company}"'
    cursor.execute(sql)
    result = cursor.fetchone()
    company_id = result[0]

    sql = f'SELECT * FROM t_ware_kind WHERE `Name` = "{name}"'
    cursor.execute(sql)
    kind_result = cursor.fetchone()
    kind_id = kind_result[0]

    if name != 'ALTAIR 2X':
        sql = f"SELECT * FROM t_model WHERE `Name` = '{model}' AND Company = '{company_id}'"
        cursor.execute(sql)
        model_result = cursor.fetchone()
        if model_result is None:
            sql = f"INSERT INTO t_model(Kind, `Name`, Company, Unit) VALUES({kind_id}, '{model}', {company_id}, 1)"
            print(sql)
            cursor.execute(sql)
            conn.commit()

    print(name, model, company, company_id, kind_id)

# for company_name in company:
#     if company_name != 'MSA':
#         sql = f"INSERT INTO t_company(`Name`) VALUES('{company_name}')"
#         cursor.execute(sql)
#         conn.commit()

# for i in range(len(kind)):
#     sql = f"INSERT INTO t_ware_kind(`Name`, Pid) VALUES('{list(kind[i].keys())[0]}', 0)"
#     cursor.execute(sql)
#     conn.commit()
#     pid = cursor.lastrowid
#     for s in list(kind[i].values())[0]:
#         sql = f"INSERT INTO t_ware_kind(`Name`, Pid) VALUES('{s}', {pid})"
#         cursor.execute(sql)
#         conn.commit()

