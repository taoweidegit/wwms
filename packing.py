from PyInstaller.__main__ import run
import platform

if __name__ == '__main__':
    if platform.system() == "Windows":
        opts = ['main.py',  # 主程序文件
                '-n wmms',  # 可执行文件名称
                '-F',  # 打包单文件
                # '-w', #是否以控制台黑窗口运行
                '-y',
                '--clean',
                '--workpath=build',
                '--add-data=templates;templates',  # 打包包含的html页面
                '--add-data=static;static',  # 打包包含的静态资源
                '--distpath=build',
                '--specpath=./'
                ]

        run(opts)
    elif platform.system() == "Linux":
        opts = ['main.py',  # 主程序文件
                '-n wmms',
                '-F',  # 打包单文件
                # r'--icon=./Creeper.ico',
                '--clean',
                '--add-data=templates:templates',  # 打包包含的html页面
                '--add-data=static:static',  # 打包包含的静态资源
                ]
        run(opts)
    else:
        print(platform.system())
