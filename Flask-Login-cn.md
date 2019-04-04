# Flask-Login
Flask-Login 为 Flask 提供对用户 session 的管理。它能够处理登录，注销和长时间记住用户 session 等常用任务。

它会：

- 在 session 中存储活动用户的 ID，并让你轻松实现用户的登录和注销。
- 让你可以限制视图只对已登录用户可用。
- 处理通常会很麻烦的“记住我”功能。
- 帮助保护用户 session 不被 cookie 窃贼偷窃。
- 可与 Flask-Principal 或者其他权限认证扩展集成使用。

但是，它不会：

- 强迫你使用特定的数据库或者其他存储方式。你对如何加载用户拥有完全的自主权。
- 限定你使用用户名和密码，OpenIDs 或者任何其他的验证方法。
- 处理“已登录或未登录”之外的权限。
- 处理用户注册或者账号恢复。

***
- [Flask-Login](#flask-login)
  - [安装](#安装)
  - [配置你的应用程序](#配置你的应用程序)
  - [如何开始工作](#如何开始工作)
  - [定义用户类](#定义用户类)
  - [登录示例](#登录示例)
  - [自定义登录流程](#自定义登录流程)
  - [使用 Autherization 首部字段登录](#使用-autherization-首部字段登录)
  - [使用 Request Loader 自定义登录](#使用-request-loader-自定义登录)
  - [匿名用户](#匿名用户)
  - [记住我](#记住我)
  - [可选令牌值](#可选令牌值)
  - [“新鲜”登录](#新鲜登录)
  - [Cookie 的设置](#cookie-的设置)
  - [Session 的保护](#session-的保护)
  - [禁用 API 的 Session Cookie](#禁用-api-的-session-cookie)
  - [本地化](#本地化)
  - [API 文档](#api-文档)
    - [登录配置](#登录配置)
    - [登录机制](#登录机制)
    - [视图保护](#视图保护)
    - [用户对象辅助](#用户对象辅助)
    - [实用工具](#实用工具)
    - [信号](#信号)

***

## 安装

使用 pip 安装扩展：

```bash
$ pip install flask-login
```

## 配置你的应用程序

对于一个应用来说，使用 Flask-Login 最重要的部分是 [LoginManager](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.LoginManager) 类。你应该在代码中的某个位置为应用程序创建一个类实例，像这样：

    login_manager = LoginManager()

`login manager ` 包含让你的应用和 Flask-Login 一起工作的代码，例如如何通过 ID 加载用户，在用户需要登录时将用户跳转到何处等等。

实际的应用对象被创建之后，你能够通过以下代码配置应用的登录功能（译注：即注册扩展到应用实例）：

    login_manager.init_app(app)

默认情况下，Flask-Login 使用 session 进行身份验证。这意味着你必须在应用程序中设置密钥，否则 Flask 会向你显示一条错误消息要求你这样做。 请参阅 [Flask documentation on sessions](http://flask.pocoo.org/docs/quickstart/#sessions) 以了解如何设置密钥。

*注意*：**确保**使用"How to generate good secret keys"部分中的给定命令来生成你自己的密钥。**不要**使用示例中的密钥。

## 如何开始工作

你需要提供一个 [user_loader](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.LoginManager.user_loader) 回调函数。这个回调函数用于通过 session 中存储的用户 ID 重新加载用户对象。它应该接收用户的 **unicode** ID，并返回相应的用户对象。例如：

```python
@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)
```

如果 ID 无效，函数应该返回 [None](https://docs.python.org/3/library/constants.html#None)（**而不是唤起异常**）。（这样 ID 将从 session 中被手动移除且程序可以继续执行。）

## 定义用户类
你用来表示用户的类需要实现以下属性和方法：

`is_authenticated`
如果用户已通过认证这个属性应该返回 [True](https://docs.python.org/3/library/constants.html#True)，即用户已经提供有效的身份凭证。（只有通过认证的用户才会满足 [login_required](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.login_required) 条件。）

`is_active`
如果这是一个活跃的用户这个属性应该返回 [True](https://docs.python.org/3/library/constants.html#True)，也就是说用户除了通过验证以外，还激活了账号，且账号没有被暂停或者处于任何应用程序用来拒绝账号的状态。不活跃用户将不能登录（除非被强制登录）。（译注：关于强制登录 Api 中会有介绍）

`is_anonymous`
如果这是一个匿名用户这个属性应该返回 [True](https://docs.python.org/3/library/constants.html#True)。（实际存在的用户应该返回[False](https://docs.python.org/3/library/constants.html#False)）

`get_id()`
这个方法必须返回一个唯一标识用户的 **unicode**，并且返回的**unicode**能够在 [user_loader](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.LoginManager.user_loader) 回调函数中用来加载用户。注意返回的值**必须**是 **unicode**，如果ID本来是 [`int`](https://docs.python.org/3/library/functions.html#int)类型或者其他类型，你需要将它转换为 **unicode**。

为了让实现用户类更轻松，你可以从 [UserMixin](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.UserMixin) 类继承用户类，它提供了以上所有属性和方法的默认实现。（但这不是必需的，你可以自己实现）

## 登录示例

用户通过认证后，使用 [login_user](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.login_user) 函数将他们登录。
例如：

```python
@app.route('/login',methods=['GET','POST'])
def login():
    # 这里我们使用一个类，来表示和验证客户端表单数据
    # 例如，WTForms 库可以用来为我们处理这些工作，我们使用自定义的 LoginForm 来验证表单数据。
    form = LoginForm()
    if form.validate_on_submit():
        # 登录并且验证用户
        # 用户应该是你的`User`类的一个实例
        login_user(user)
        
        flask.flash('logged in successfully')
        
        next = flask.request.args.get('next')
        # is_safe_url 用来检查url是否可以安全的重定向
        # 有关示例，参见 http://flask.pocoo.org/snippets/62/
        if not is_safe_url(next):
            return flask.abort(400)
        
        return flask.redirect(next or flask.url_for('index'))
    return flask.render_template('login.html',form=form)
```
*注意*：你**必须**验证 `next` 参数的值。如果你没有，你的应用程序将容易受到开放重定向攻击。有关 **is_safe_url** 的实现示例，请参见 [this Flask Snippet](http://flask.pocoo.org/snippets/62/)。

就这么简单。之后你可以使用 [current_user](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.current_user) 代理对象访问已登录的用户，`current_user`可以在每个模板中直接使用：（译注：传入了模板上下文）
```
{% if current_user.is_authenticated %}
    Hi {{cuttent_user.name}}
{% endif %}
```

需要用户登录才能访问的视图可以使用 [login_required](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.login_required) 装饰器进行装饰：
```python
@app.route("/settings")
@login_required
def settings():
    pass
```

当用户需要注销时：
```python
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(somewhere)
```

用户将会被注销，并且任何保存他们 session 的 cookie 都会被清理。（译注：从 session 中删除用户 id 等字段）

## 自定义登录流程

默认情况下，当一个未登录的用户试图访问一个 [login_required](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.login_required) 的视图时，Flask-Login 将会闪现一条信息并将用户重定向到登录视图。（如果没有设置登录视图，将会报401错误）

登录视图的名称（译注：URL 或端点）可以被设置为 [LoginManager.login_view](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.LoginManager.login_view)。例如：

    login_manager.login_view = "user.login"

默认的闪现信息内容是 `Please log in to access this page`。可以通过设置 [LoginManager.login_message](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.LoginManager.login_message) 属性来自定义内容：

    login_manager.login_message = u"Bonvolu ensaluti por uzi tiun paĝon."

可以通过设置 **LoginManager.login_message_category** 属性来自定义消息类型:

    login_manager.login_message_category = "info"

重定向到登录视图后，（ 当前 URL）查询字符串中会有一个 `next` 变量，变量中保存着用户试图访问的页面地址。另外，如果 **USE_SESSION_FOR_NEXT** 配置参数为 [True](https://docs.python.org/3/library/constants.html#True)，试图访问的页面地址将会保存在 session 的 `next` 键中。

如果你想更进一步的自定义流程，用 [LoginManager.unauthorized_handler](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.LoginManager.unauthorized_handler) 来装饰处理函数：
```python
@login_manager.unauthorized_handler
def unauthorized():
    # do stuff
    return a_response
```

## 使用 Autherization 首部字段登录

>警告：
>
>这个方法将被弃用；请使用下面的 `request_loader` 作为替代。

有些场景你想使用 **Authorization** 首部字段来支持 Basic Auth 登录，比如用于 api 请求。你需要提供一个 [header_loader](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.LoginManager.header_loader) 回调函数来支持通过请求的首部字段登录。这个回调函数应该和你的 [user_loader](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.LoginManager.user_loader) 回调函数基本一样，但是它接收一个首部字段值而不是用户 id。例如：
```python
@login_manager.header_loader
def load_user_from_header(header_val):
    header_val = header_val.replace('Basic ', '', 1)
    try:
        header_val = base64.b64decode(header_val)
    except TypeError:
        pass
    return User.query.filter_by(api_key=header_val).first()
```

默认情况下 **Authorization** 首部字段的值会被传递给 [header_loader](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.LoginManager.header_loader) 回调函数。你可以通过 **AUTH_HEADER_NAME** 配置变量来更改使用的首部字段。

## 使用 Request Loader 自定义登录
有些场景你想在不使用 cookies 的情况下登录用户，例如使用请求首部或者作为查询参数传递的 api key。在这些情况下，你应该使用 **request_loader** 回调函数。这个回调函数和 [user_loader](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.LoginManager.user_loader) 回调函数基本一样，但是它接收 Flask 请求而不是用户 id。

例如，为了支持通过 url 参数和使用 **Authorization** 首部字段的 Basic Auth 进行登录：
```python
@login_manager.request_loader
def load_user_from_request(request):

    # 首先，尝试通过 api_key url查询参数进行登录
    api_key = request.args.get('api_key')
    if api_key:
        user = User.query.filter_by(api_key=api_key).first()
        if user:
            return user

    # 然后, 尝试通过 Basic Auth 进行登录
    api_key = request.headers.get('Authorization')
    if api_key:
        api_key = api_key.replace('Basic ', '', 1)
        try:
            api_key = base64.b64decode(api_key)
        except TypeError:
            pass
        user = User.query.filter_by(api_key=api_key).first()
        if user:
            return user

    # 最后，如果两种方法都不能登录用户则返回 None
    return None
```

## 匿名用户

默认情况下，当一个用户没有登录时，[current_user](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.current_user) 被设置为一个 [AnonymousUserMixin](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.AnonymousUserMixin) 对象。它有下列属性和方法：

 - `is_active` 和 `is_authenticated` 返回 [`False`](https://docs.python.org/3/library/constants.html#False)
- `is_anonymous` 返回 [`True`](https://docs.python.org/3/library/constants.html#True)
- `get_id()` 返回 [`None`](https://docs.python.org/3/library/constants.html#None)

如果你有自定义匿名用户的需求（例如，他们需要有一个权限字段），你可以使用以下方式提供一个创建匿名用户的可调用对象（类或者工厂函数）给 [LoginManager](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.LoginManager):

```python
login_manager.anonymous_user = MyAnonymousUser
```

## 记住我

默认情况下，当用户关闭浏览器时，Flask Session 会被删除，用户将被注销。“记住我” 防止用户关闭他们的浏览器时被意外注销。这**不是**用户注销后在登录表单中会记住或自动填写用户的用户名或密码的意思（译注：即不是浏览器提供的自动填充功能）。

“记住我”功能的实现可能会很麻烦。但是 Flask-Login 使该过程变得简单明了--你只需要在调用 [`login_user`](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.login_user) 时传入 `remember=True` 即可。一个 cookie 将会保存到用户的电脑，然后 Flask-Login 将会在用户 ID 不在 session 中时自动地从该 cookie 中恢复用户 ID。cookie 的过期时长可以通过 `REMEMBER_COOKIE_DURATION` 配置或者直接将时长传入 [`login_user`](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.login_user) 来设置。这个 cookie 是防篡改的，所以如果用户篡改了它（如使用别的用户ID来代替自己的），Flask-Login 将不会使用这个 cookie。

这个层级的功能将会自动运行。但是，你能够（如果你的应用将处理任何的敏感数据，则是应该）提供额外的设置来增加记住我 cookie 的安全性。

## 可选令牌值

使用用户 ID 作为”记住我“的令牌值意味着你必须更改用户 ID 来使他们的登录 session 无效。一种改进的方式是使用一个另外的用户 id 而不是用户的主 ID。例如：

```python
@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(alternative_id=user_id).first()
```

然后用户类的 **get_id** 方法也要返回另外的 id 而不是用户的主 ID：
```python
def get_id(self):
    return unicode(self.alternative_id)
```

这样，当用户更改他们的密码时，你可以将用户另外的 id 更改为一个新的随机生成值，以确保他们原来的验证 session 将不再有效。注意这个另外的 id 依然需要唯一标识用户...可以把它当成第二个用户 ID。

## “新鲜”登录

当一个用户登录时，它的登录 session 会被标记为“新鲜”（译注：在 session 中添加 _fresh 字段），表明他们实际是在该 session 中通过了身份验证。当他们的 session 被销毁然后通过“记住我” cookie 登录回来时，会被标记为“不新鲜”。[login_required](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.login_required) 不会区分新鲜状态，对大多数页面来说这样没有问题。然而，类似于更改个人信息这样的敏感操作应该需要“新鲜”登录。（而像修改密码这样的操作不管怎样应该总是需要重新输入原密码。）

[fresh_login_required](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.fresh_login_required)，除了验证用户已经登录，还将确保他们的登录为“新鲜”状态。如果不是，它会将他们重定向到一个可以重新输入凭证的页面。你可以就像自定义 [login_required](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.login_required) 的方式一样，通过设置 [LoginManager.refresh_view](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.LoginManager.refresh_view)，[needs_refresh_message](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.LoginManager.needs_refresh_message)，以及 **needs_refresh_message_category** 自定义这类行为：

```python
login_manager.refresh_view = "accounts.reauthenticate"
login_manager.needs_refresh_message = (
    u"To protect your account, please reauthenticate to access this page."
)
login_manager.needs_refresh_message_category = "info"
```

或者提供你自己的回调函数来刷新“新鲜”状态:
```python
@login_manager.needs_refresh_handler
def refresh():
    # do stuff
    return a_response
```
调用 [confirm_login](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.confirm_login)函数，会把 session 重新标记为“新鲜”。

## Cookie 的设置

Cookie 的细节可以在应用程序的配置中自定义。

| 配置变量                                 | 用途                                                         |
| ---------------------------------------- | ------------------------------------------------------------ |
| **REMEMBER_COOKIE_NAME**                 | 储存“记住我”信息的 cookie 名称。**默认值：**`remember_token` |
| **REMEMBER_COOKIE_DURATION**             | cookie 的过期时长，值为 [datetime.timedelta](https://docs.python.org/3/library/datetime.html#datetime.timedelta)对象或整数秒数。**默认值：**365天（一个非闰阳历年） |
| **REMEMBER_COOKIE_DOMAIN**               | 如果“记住我”的 cookie 要跨域，在这里设置域名值（即`.example.com`将会允许cookie用于所有`example.com`的子域名）**默认值：**[None](https://docs.python.org/3/library/constants.html#None) |
| **REMEMBER_COOKIE_PATH**                 | 限制“记住我” cookie 在一个固定的路径。**默认值：**/          |
| **REMEMBER_COOKIE_SECURE**               | 限制“记住我” cookie 仅作用于加密通道（通常是HTTPS）。**默认值：**[None](https://docs.python.org/3/library/constants.html#None) |
| **REMEMBER_COOKIE_HTTPONLY**             | 防止“记住我” cookie 被客户端脚本访问。**默认：**[False](https://docs.python.org/3/library/constants.html#False) |
| **REMEMBER_COOKIE_REFRESH_EACH_REQUEST** | 如果设置为 [`True`](https://docs.python.org/3/library/constants.html#True)  记住我 cookie 在每次请求时都会被刷新，这将延长其生命周期。 工作方式类似于 Flask 的 [`SESSION_REFRESH_EACH_REQUEST`](http://flask.pocoo.org/docs/config/#SESSION_REFRESH_EACH_REQUEST).**默认值:** [`False`](https://docs.python.org/3/library/constants.html#False) |

## Session 的保护

虽然上述功能有助于保护你的“记住我”令牌不被 cookie 窃贼偷窃，但是 session cookie依然容易受到攻击。Flask-Login 包含了 session 保护功能来防止用户的 session 被偷窃。

你可以在 [LoginManager](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.LoginManager) 和应用程序配置参数中设置 session 保护。如果启用了 session 保护，它可以运行在 `basic` 或者 `strong `模式。设置方式是在 [LoginManager](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.LoginManager) 设置 **session_protection** 属性的值为 “basic” 或者 “strong”：

```python
login_manager.session_protection = "strong"
```

停用 session 保护：

```python
login_manager.session_protection = None
```

默认情况下， session 保护被启动为 “basic” 模式。在应用程序配置中将 **SESSION_PROTECTION** 配置参数设置为 [None](https://docs.python.org/3/library/constants.html#None)，“basic” 或 “strong”，可以禁用它或更改工作模式。

当 session 保护被启用时，每个请求都会为用户的计算机生成一个标识符（主要是对IP地址和用户代理的加密 hash）。 如果 session 中没有相关联的标识符，则会将生成的标识符存储在 session 中。 如果它有一个标识符，并且与当前请求生成的标识符相匹配，则该请求正常进行。（译注：同一IP地址和用户代理生成的哈希值总是相同的）

如果标识符在 `basic` 模式下不匹配，或者当 session 是永久的，session 会被直接标记成”不新鲜“， 任何需要“”新鲜“登录的请求都会强制要求用户重新认证。（当然，你必须已经在适当的地方启用了”新鲜“登录这才会有作用。）

如果非永久 session 中的标识符在 `strong` 模式下不匹配，整个 session （以及可能存在的记住我令牌）会被删除。

## 禁用 API 的 Session Cookie

在对 API 进行认证时，你可能希望禁止设置 Flask Session cookie。 为此，可使用一个自定义的 session 接口，该接口根据你在请求中设置的标志跳过保存 session 。 例如：

```python
from flask import g
from flask.sessions import SecureCookieSessionInterface
from flask_login import user_loaded_from_header

class CustomSessionInterface(SecureCookieSessionInterface):
    """防止 API 请求创建 session。"""
    def save_session(self, *args, **kwargs):
        if g.get('login_via_header'):
            return
        return super(CustomSessionInterface, self).save_session(*args, **kwargs)

app.session_interface = CustomSessionInterface()

@user_loaded_from_header.connect
def user_loaded_from_header(self, user=None):
    g.login_via_header = True
```

这可以防止在用户使用 [header_loader](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.LoginManager.header_loader) 进行认证时设置 Flask Session cookie。

## 本地化

默认情况下，当用户需要登录时 [LoginManager](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.LoginManager) 使用 `flash` 来显示消息。这些消息是英文的。如果你需要进行本地化，请将 [LoginManager](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.LoginManager) 的 **localize_callback** 属性设置为一个在发送到`flash`之前对这些消息进行调用的函数，如`gettext`。这个函数将会对这些消息调用，调用的返回值将代替消息发送到 `flash`。

## API 文档

下列文档是从 Flask-Login 源码中自动生成的。

### 登录配置

*class* `flask_login`**.LoginManager**(*app=None*, *add_context_processor=True*)[[source\]](https://flask-login-cn.readthedocs.io/zh/latest/_modules/flask_login/login_manager.html#LoginManager)

这个对象用来保存登录需要的设置。[LoginManager](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.LoginManager) 的实例**不**限定于特定的程序实例，所以你可以在代码的主体部分创建它，然后在工厂函数中绑定到程序实例。

- **setup_app**(*app*, *add_context_processor=True*)[[source\]](https://flask-login-cn.readthedocs.io/zh/latest/_modules/flask_login/login_manager.html#LoginManager.setup_app)

  这个方法已经被弃用。请使用 `LoginManager.init_app()` 作为代替。

- **unauthorized()**[[source\]](https://flask-login-cn.readthedocs.io/zh/latest/_modules/flask_login/login_manager.html#LoginManager.unauthorized)

  这个方法会在用户被要求登录的时候调用。如果你使用 [LoginManager.unauthorized_handler](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.LoginManager.unauthorized_handler) 注册了回调函数，被调用的会是这个回调函数（译注：首先调用 unauthorized() ，然后跳过后续代码直接返回并调用该回调函数）。否则，它将执行下列行为：

  - 向用户闪现消息 [LoginManager.login_message](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.LoginManager.login_message)。
  - 如果应用使用了蓝图将通过 **blueprint_login_views** 找到当前蓝图的登录视图。如果应用没有使用蓝图或者没有指定当前蓝图的登录视图，将使用 [login_view](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.LoginManager.login_view) 的值。
  - 重定向用户到登录视图。（用户试图访问的页面地址将会被传递到查询字符串的 `next` 变量中，所以如果验证通过你会重定向到该页面而不是返回首页。作为另一选择，如果设置了 **USE_SESSION_FOR_NEXT** 配置，该页面地址将会被添加到 session 的 `next` 键中。）

  如果 [LoginManager.login_view](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.LoginManager.login_view) 未定义，该方法将直接唤起 HTTP 401（Unauthorized）错误。
  该方法应该返回自一个视图或者 before/after_request 函数，否则重定向不会生效。（译注：这样才会有有效的 `next` 值。）

- **needs_refresh()**[[source\]](https://flask-login-cn.readthedocs.io/zh/latest/_modules/flask_login/login_manager.html#LoginManager.needs_refresh)

  当用户已经登录但因为登录 session ”不新鲜“而需要重新认证时，该方法将被调用。如果你使用 [needs_refresh_handler](https://flask-login-cn.readthedocs.io/zh/latest/index.html#flask_login.LoginManager.needs_refresh_handler) 注册了回调函数，该回调函数将被调用（译注：过程同上）。否则它将执行下列行为：
   - 向用户闪现消息 [LoginManager.needs_refresh_message](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.LoginManager.needs_refresh_message)
   - 重定向用户到 [LoginManager.refresh_view](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.LoginManager.refresh_view)。（用户试图访问的页面地址将会被传递到查询字符串的 `next` 变量中，所以如果验证通过你会重定向到该页面而不是返回首页。）

  如果 [LoginManager.refresh_view](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.LoginManager.refresh_view) 未定义，该方法将直接唤起 HTTP 401（Unauthorized）错误。
  该方法应该返回自一个视图或者 before/after_request 函数，否则重定向不会生效。（译注：这样才会有有效的 `next` 值。）

**常规配置**

- **user_loader**(*callback*)[[source\]](https://flask-login-cn.readthedocs.io/zh/latest/_modules/flask_login/login_manager.html#LoginManager.user_loader)

  用来设置从 session 中重载用户的回调函数。被设置的函数应该接收一个用户 ID（`unicode`）并返回一个用户对象，如果用户不存在的话返回 `None`。

  **参数：** **callback**（[callable](https://docs.python.org/3/library/functions.html#callable)）——用来取回用户对象的回调函数。

- **header_loader**(*callback*)[[source\]](https://flask-login-cn.readthedocs.io/zh/latest/_modules/flask_login/login_manager.html#LoginManager.header_loader)

  该函数已被废弃，请使用 **LoginManager.request_loader()** 作为代替。
  用来设置通过请求头的值加载用户的回调函数。被设置的函数应该接收一个认证令牌并返回一个用户对象，如果用户不存在的话返回 `None`。

  **参数：** **callback**（[callable](https://docs.python.org/3/library/functions.html#callable)）——用来取回用户对象的回调函数。

- **anonymous_user**

  一个创建匿名用户的类或者工厂函数，在未登录时使用。

**[unauthorized](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.LoginManager.unauthorized) 配置**

- **login_view**

  当用户需要登录时要重定向到的视图的名称。（可以是一个绝对 URL，如果你的认证设施在应用程序的外部。）

- **login_message**

  当用户被重定向到登录页面时闪现的信息。

- **unauthorized_handler**(*callback*) [[source]](https://flask-login-cn.readthedocs.io/zh/latest/_modules/flask_login/login_manager.html#LoginManager.unauthorized_handler)

  为 [`unauthorized`](https://flask-login-cn.readthedocs.io/zh/latest/index.html#flask_login.LoginManager.unauthorized) 方法设置一个回调函数，这个回调函数另外还会被  [login_required](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.login_required) 所使用。它不接收参数，并且应该返回一个会被发送给用户的响应而不是普通的视图。
  
  **参数：** **callback**(*callback*)——用于未认证用户的回调函数。

**[needs_refresh](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.LoginManager.needs_refresh) 配置**

- **refresh_view**

  当用户需要重新认证时要重定向到的视图的名称。

- **needs_refresh_message**

  当用户被重定向到重新认证页面时闪现的信息。

- **needs_refresh_handler**(*callback*) [[source]](https://flask-login-cn.readthedocs.io/zh/latest/_modules/flask_login/login_manager.html#LoginManager.needs_refresh_handler)

  为 [`needs_refresh`](https://flask-login-cn.readthedocs.io/zh/latest/index.html#flask_login.LoginManager.needs_refresh) 方法设置一个回调函数，这个回调函数另外还会被 [fresh_login_required](https://flask-login-cn.readthedocs.io/zh/latest/index.html#flask_login.fresh_login_required) 所使用。它不接收参数，并且应该返回一个会被发送给用户的响应而不是普通的视图。
  
  **参数：** **callback**(*callback*)——用于未认证用户的回调函数。

### 登录机制

- **`flask_login`.current_user**

  当前用户的代理对象。

- **`flask_login`.login_fresh()**[[source\]](https://flask-login-cn.readthedocs.io/zh/latest/_modules/flask_login/utils.html#login_fresh)

  如果当前登录是“新鲜”的，返回`True`。

- **`flask_login`.login_user**(*user,remember=False,force=False,fresh=True*)[[source]](https://flask-login-cn.readthedocs.io/zh/latest/_modules/flask_login/utils.html#login_user)

  登录用户。你应该在这个方法中传入实际的用户对象。如果用户的 **is_active** 属性为 `False`，他们将不会被登录，除非方法 **force** 参数为 `True`.
  如果登录成功将返回  `True` ，如果登录失败则返回 `False` (即用户的账号为不活跃状态)。
  
  **参数：** 

   - **user**([object](https://docs.python.org/3/library/functions.html#object))——要登录的用户对象。
   - **remember**([bool](https://docs.python.org/3/library/functions.html#bool))—— session 过期后是否记住用户。默认值为 `False`.
   - **force**([bool](https://docs.python.org/3/library/functions.html#bool))——如果用户处于不活跃状态，设置这个参数为 `True` 将强制登录用户。默认值为 `False`。
   - **fresh**([bool](https://docs.python.org/3/library/functions.html#bool))——将该参数设置为`False`，将会在登录用户时标记 session 为”不新鲜“。默认值为 `True`。

- **`flask_login`.logout_user()** [[source\]](https://flask-login-cn.readthedocs.io/zh/latest/_modules/flask_login/utils.html#logout_user)

  注销用户。（不需要传入实际的用户对象。）若存在记住我 cookie，该cookie将会被清除。

- **`flask_login`.confirm_login()** [[source]](https://flask-login-cn.readthedocs.io/zh/latest/_modules/flask_login/utils.html#confirm_login)

  将当前 session 设置为”新鲜“状态。当从 cookie 重新恢复时， session 会变得不新鲜。

### 视图保护

- **`flask_login`.login_required**(*func*) [[source]](https://flask-login-cn.readthedocs.io/zh/latest/_modules/flask_login/utils.html#login_required)

  如果你用这个函数装饰一个视图，它将确保当前用户在调用实际的视图之前已经通过认证并登录。（如果他们没有，它将会调用 [LoginManager.unauthorized](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.LoginManager.unauthorized) 回调函数）。例如：

  ```python
  @app.route('/post')
  @login_required
  def post():
      pass
  ```

  如果只在特定场景你需要要求用户已经登录，你可以这样做：

  ```
  if not current_user.is_authenticated:
      return current_app.login_manager.unauthorized()
  ```

  ...这基本上也是这个函数装饰视图时会额外执行的代码。
  我们可以很方便在进行单元测试时全局地关闭认证功能。如果应用程序的配置变量 **LOGIN_DISABLED** 被设置为 [True](https://docs.python.org/3/library/constants.html#True)，这个装饰器将会被忽略。

>*注意：*
>根据 [W3 guidelines for CORS preflight requests](http://www.w3.org/TR/cors/#cross-origin-request-with-preflight-0) ， “OPTIONS” 类型的 **HTTP** 请求不会进行登录检查。

​	**参数：** **func**(*function*)——要装饰的视图函数。

- **`flask_login`.fresh_login_require**(*func*) [[source\]](https://flask-login-cn.readthedocs.io/zh/latest/_modules/flask_login/utils.html#fresh_login_required)

  如果你用这个函数装饰视图，它将确保当前用户的登录是”新鲜“的 - 即他们的 session 不是从“记住我” cookie 中恢复的。像改变密码或者邮箱这样的敏感操作应该用这个来保护，以提防 cookie 窃贼的攻击。
  如果用户没有通过认证，[LoginManager.unauthorized()](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.LoginManager.unauthorized) 像平常一样会被调用。如果他们已经通过认证，但 session 是”不新鲜“的，它将调用 [LoginManager.needs_refresh()](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.LoginManager.needs_refresh) 。（在这种情况下，你将需要提供一个 [LoginManager.refresh_view](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.LoginManager.refresh_view)）
  关于配置变量，该装饰器和 [login_required()](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.login_required) 装饰器有同样的行为。

>*注意：*
>根据 [W3 guidelines for CORS preflight requests](http://www.w3.org/TR/cors/#cross-origin-request-with-preflight-0) ， “OPTIONS” 类型的 **HTTP**请求不会进行登录检查。

​	**参数：** **func**(*function*)——要装饰的视图函数。

### 用户对象辅助

class `flask_login`.**UserMixin** [[source\]](https://flask-login-cn.readthedocs.io/zh/latest/_modules/flask_login/mixins.html#UserMixin)

提供 Flask-Login 期望用户对象所拥有方法的默认实现。

class `flask_login`.**AnonymousUserMixin** [[source]](https://flask-login-cn.readthedocs.io/zh/latest/_modules/flask_login/mixins.html#AnonymousUserMixin)

用来代表匿名用户的默认对象。

### 实用工具

- `flask_login`.**login_url**(*login_view*, *next_url=None*, *next_field='next'*) [[source]](https://flask-login-cn.readthedocs.io/zh/latest/_modules/flask_login/utils.html#login_url)

  创建用于重定向到登录页面的 URL。如果只提供了 **login_view** 参数，函数将仅返回该视图的 URL。如果提供了 **next_url** 参数，则会添加一个 `next=URL` 的参数到查询字符串，以便登录视图可以重定向到提供的这个 URL。Flask-Login 默认的未认证处理器（unauthorized handler）在重定向到登录 url 时使用这个函数。 将 **FORCE_HOST_FOR_REDIRECTS** 配置设置为一个主机地址， 即可强制在 URL 中使用主机名。这可以防止在请求中有 Host 或 X-Forwarded-For 首部字段时重定向到外部站点。
  
  **参数：** 

   - **login_view**([str](https://docs.python.org/3/library/stdtypes.html#str))——登录视图的名称（也可以是登录视图的实际 URL）
   - **next_url**([str](https://docs.python.org/3/library/stdtypes.html#str))——提供给登录视图来重定向的URL。
   - **next_field**([str](https://docs.python.org/3/library/stdtypes.html#str))——存储下一个 URL 的字段名称。（默认为`next`）

### 信号

查看 [Flask document on signals](http://flask.pocoo.org/docs/signals/) 了解如何在你的代码中使用信号。

- `flask_login`.**user_logged_in**

  在用户登录后发送。除了程序实例以外（作为 sender 参数，信号的发送者），还会传入 **user** 参数，即被登录的用户。

- `flask_login`.**user_logged_out**

  在用户注销后发送。除了程序实例以外（作为 sender 参数，信号的发送者），还会传入 **user** 参数，即被注销的用户。

- `flask_login`.**user_login_confirmed**

  在用户的登录被确认后发送，会将登录标记为新鲜。（普通的登录不会调用这个函数）不接收除了程序实例以外的参数。

- `flask_login`.**user_unauthorized**

  当 [LoginManager](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.LoginManager)  的 `unauthorized` 方法被调用时发送。不接收除了程序实例以外的参数。

- `flask_login`.**user_needs_refresh**

  当 [LoginManager](https://flask-login-cn.readthedocs.io/zh/latest/#flask_login.LoginManager)  的 `needs_refresh` 方法被调用时发送。不接收除了程序实例以外的参数。

- `flask_login`.**session_protected**

  当 session 保护发挥作用时调用，这时一个 session 会被标记为”不新鲜“或被删除。不接收除了程序实例以外的参数。

