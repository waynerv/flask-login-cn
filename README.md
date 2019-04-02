# Flask-Login 简体中文文档

## 版本

基于 Flask-Login 0.4.1——当前（2019.3）发布的最新版本翻译。

## 线上地址

[https://flask-login-cn.readthedocs.io/zh/latest/](https://flask-login-cn.readthedocs.io/zh/latest/)

## 制作本地文档

### Html 文档

主要步骤：

* 克隆本项目
* 创建虚拟环境（示例使用pipenv）
* 安装依赖
* 生成文档（文档生成在 docs/_bulid/html 目录下)

命令示例：

```shell
git clone git@github.com:waynerv/flask-login-cn.git
cd flask-login-cn/
pipenv install
cd docs/
make html
```

也可跳过创建虚拟环境，直接通过 `pip` 与项目根目录的 [requirements.txt](requirements.txt) 完成依赖安装：

```shell
pip install -r requirements.txt
```

### Markdown 文档

见 [Flask-Login-cn.md](Flask-Login-cn.md)


## 关于译者

由 Waynerv 出于兴趣翻译，将持续更新完善。水平有限，若有翻译不当之处敬请谅解，并欢迎指出。