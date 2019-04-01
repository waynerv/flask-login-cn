# -*- coding: utf-8 -*-
'''
    flask_login.utils
    -----------------
    General utilities.
'''


import hmac
from hashlib import sha512
from functools import wraps
from werkzeug.local import LocalProxy
from werkzeug.security import safe_str_cmp
from werkzeug.urls import url_decode, url_encode

from flask import (_request_ctx_stack, current_app, request, session, url_for,
                   has_request_context)

from ._compat import text_type, urlparse, urlunparse
from .config import COOKIE_NAME, EXEMPT_METHODS
from .signals import user_logged_in, user_logged_out, user_login_confirmed


#: 当前用户的代理对象。如果当前用户未登录，这将是一个匿名用户
current_user = LocalProxy(lambda: _get_user())


def encode_cookie(payload, key=None):
    '''
    This will encode a ``unicode`` value into a cookie, and sign that cookie
    with the app's secret key.

    :param payload: The value to encode, as `unicode`.
    :type payload: unicode

    :param key: The key to use when creating the cookie digest. If not
                specified, the SECRET_KEY value from app config will be used.
    :type key: str
    '''
    return u'{0}|{1}'.format(payload, _cookie_digest(payload, key=key))


def decode_cookie(cookie, key=None):
    '''
    This decodes a cookie given by `encode_cookie`. If verification of the
    cookie fails, ``None`` will be implicitly returned.

    :param cookie: An encoded cookie.
    :type cookie: str

    :param key: The key to use when creating the cookie digest. If not
                specified, the SECRET_KEY value from app config will be used.
    :type key: str
    '''
    try:
        payload, digest = cookie.rsplit(u'|', 1)
        if hasattr(digest, 'decode'):
            digest = digest.decode('ascii')  # pragma: no cover
    except ValueError:
        return

    if safe_str_cmp(_cookie_digest(payload, key=key), digest):
        return payload


def make_next_param(login_url, current_url):
    '''
    Reduces the scheme and host from a given URL so it can be passed to
    the given `login` URL more efficiently.

    :param login_url: The login URL being redirected to.
    :type login_url: str
    :param current_url: The URL to reduce.
    :type current_url: str
    '''
    l = urlparse(login_url)
    c = urlparse(current_url)

    if (not l.scheme or l.scheme == c.scheme) and \
            (not l.netloc or l.netloc == c.netloc):
        return urlunparse(('', '', c.path, c.params, c.query, ''))
    return current_url


def expand_login_view(login_view):
    '''
    Returns the url for the login view, expanding the view name to a url if
    needed.

    :param login_view: The name of the login view or a URL for the login view.
    :type login_view: str
    '''
    if login_view.startswith(('https://', 'http://', '/')):
        return login_view
    else:
        return url_for(login_view)


def login_url(login_view, next_url=None, next_field='next'):
    '''
    创建用于重定向到登录页面的 URL。如果只提供了 `login_view` 参数，
    函数将仅返回该视图的 URL。如果提供了 `next_url` 参数，则会添加一个
    ``next=URL`` 的参数到查询字符串，以便登录视图可以重定向到提供的这个 URL。
    Flask-Login 默认的未认证处理器(unauthorized handler) 在重定向到登录 url 时使用这个函数。
    将 `FORCE_HOST_FOR_REDIRECTS` 配置设置为一个主机地址， 即可强制在 URL 中使用主机名。
    这可以防止在请求中有 Host 或 X-Forwarded-For 首部字段时重定向到外部站点。

    :param login_view: 登录视图的名称（也可以是登录视图的实际 URL）
    :type login_view: str
    :param next_url: 提供给登录视图来重定向的URL。
    :type next_url: str
    :param next_field: 存储下一个 URL 的字段名称。（默认为 ``next``）
    :type next_field: str
    '''
    base = expand_login_view(login_view)

    if next_url is None:
        return base

    parsed_result = urlparse(base)
    md = url_decode(parsed_result.query)
    md[next_field] = make_next_param(base, next_url)
    netloc = current_app.config.get('FORCE_HOST_FOR_REDIRECTS') or \
        parsed_result.netloc
    parsed_result = parsed_result._replace(netloc=netloc,
                                           query=url_encode(md, sort=True))
    return urlunparse(parsed_result)


def login_fresh():
    '''
    如果当前登录是“新鲜”的，返回 ``True``。
    '''
    return session.get('_fresh', False)


def login_user(user, remember=False, duration=None, force=False, fresh=True):
    '''
    登录用户。你应该在这个方法中传入实际的用户对象。
    如果用户的 `is_active` 属性为 ``False``，他们将不会被登录，除非 `force` 参数为 ``True``。

    如果登录成功将返回  ``True`` ，如果登录失败则返回 ``False`` (即用户的账号为不活跃状态)。

    :param user: 要登录的用户对象。
    :type user: object
    :param remember: session 过期后是否记住用户。默认值为 ``False``。
    :type remember: bool
    :param duration: 记住我 cookie 的过期时长。如果值为 ``None`` 将使用配置中设置的值. 默认值为 ``None``。
    :type duration: :class:`datetime.timedelta`
    :param force: 如果用户处于不活跃状态，设置这个参数为 ``True`` 将强制登录用户。默认值为 ``False``。
    :type force: bool
    :param fresh: 将该参数设置为 ``False``，将会在登录用户时标记 session 为”不新鲜“。默认值为 ``True``。
    :type fresh: bool
    '''
    if not force and not user.is_active:
        return False

    user_id = getattr(user, current_app.login_manager.id_attribute)()
    session['user_id'] = user_id
    session['_fresh'] = fresh
    session['_id'] = current_app.login_manager._session_identifier_generator()

    if remember:
        session['remember'] = 'set'
        if duration is not None:
            try:
                # equal to timedelta.total_seconds() but works with Python 2.6
                session['remember_seconds'] = (duration.microseconds +
                                               (duration.seconds +
                                                duration.days * 24 * 3600) *
                                               10**6) / 10.0**6
            except AttributeError:
                raise Exception('duration must be a datetime.timedelta, '
                                'instead got: {0}'.format(duration))

    current_app.login_manager._update_request_context_with_user(user)
    user_logged_in.send(current_app._get_current_object(), user=_get_user())
    return True


def logout_user():
    '''
    注销用户。（不需要传入实际的用户对象。）若存在记住我 cookie，该 cookie 将会被清除。
    '''

    user = _get_user()

    if 'user_id' in session:
        session.pop('user_id')

    if '_fresh' in session:
        session.pop('_fresh')

    if '_id' in session:
        session.pop('_id')

    cookie_name = current_app.config.get('REMEMBER_COOKIE_NAME', COOKIE_NAME)
    if cookie_name in request.cookies:
        session['remember'] = 'clear'
        if 'remember_seconds' in session:
            session.pop('remember_seconds')

    user_logged_out.send(current_app._get_current_object(), user=user)

    current_app.login_manager._update_request_context_with_user()
    return True


def confirm_login():
    '''
    将当前 session 设置为”新鲜“状态。当从 cookie 重新恢复时， session 会变得不新鲜。
    '''
    session['_fresh'] = True
    session['_id'] = current_app.login_manager._session_identifier_generator()
    user_login_confirmed.send(current_app._get_current_object())


def login_required(func):
    '''
    如果你用这个函数装饰一个视图，它将确保当前用户在调用实际的视图之前已经通过认证并登录。
    （如果他们没有，它将会调用 :attr:`LoginManager.unauthorized` 回调函数）。例如::

        @app.route('/post')
        @login_required
        def post():
            pass

    如果只在特定场景你需要要求用户已经登录，你可以这样做::

        if not current_user.is_authenticated:
            return current_app.login_manager.unauthorized()

    ...这基本上也是这个函数装饰视图时会额外执行的代码。

    我们可以很方便在进行单元测试时全局地关闭认证功能。
    如果应用程序的配置变量 `LOGIN_DISABLED`
    被设置为 `True`，这个装饰器将会被忽略。

    .. Note ::

        根据 `W3 guidelines for CORS preflight requests
        <http://www.w3.org/TR/cors/#cross-origin-request-with-preflight-0>`_,
        ``OPTIONS`` 类型的 HTTP 请求不会进行登录检查。

    :param func: 要装饰的视图函数。
    :type func: function
    '''
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if request.method in EXEMPT_METHODS:
            return func(*args, **kwargs)
        elif current_app.config.get('LOGIN_DISABLED'):
            return func(*args, **kwargs)
        elif not current_user.is_authenticated:
            return current_app.login_manager.unauthorized()
        return func(*args, **kwargs)
    return decorated_view


def fresh_login_required(func):
    '''
    如果你用这个函数装饰视图，它将确保当前用户的登录是”新鲜“的 - 即他们
    的 session 不是从“记住我” cookie 中恢复的。
    像改变密码或者邮箱这样的敏感操作应该用这个来保护，以提防 cookie 窃贼的攻击。

    如果用户没有通过认证，:meth:`LoginManager.unauthorized` 像平常一样会被调用。
    如果他们已经通过认证，但 session 是”不新鲜“的，
    它将调用 :meth:`LoginManager.needs_refresh`。（在这种情况下，你将需要提供
    一个 :attr:`LoginManager.refresh_view`。)

    关于配置变量，该装饰器和 :func:`login_required` 装饰器有同样的行为。

    .. Note ::

        根据 `W3 guidelines for CORS preflight requests
        <http://www.w3.org/TR/cors/#cross-origin-request-with-preflight-0>`_，
        ``OPTIONS`` 类型的 HTTP 请求不会进行登录检查。

    :param func: 要装饰的视图函数。
    :type func: function
    '''
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if request.method in EXEMPT_METHODS:
            return func(*args, **kwargs)
        elif current_app.config.get('LOGIN_DISABLED'):
            return func(*args, **kwargs)
        elif not current_user.is_authenticated:
            return current_app.login_manager.unauthorized()
        elif not login_fresh():
            return current_app.login_manager.needs_refresh()
        return func(*args, **kwargs)
    return decorated_view


def set_login_view(login_view, blueprint=None):
    '''
    Sets the login view for the app or blueprint. If a blueprint is passed,
    the login view is set for this blueprint on ``blueprint_login_views``.

    :param login_view: The user object to log in.
    :type login_view: str
    :param blueprint: The blueprint which this login view should be set on.
        Defaults to ``None``.
    :type blueprint: object
    '''

    num_login_views = len(current_app.login_manager.blueprint_login_views)
    if blueprint is not None or num_login_views != 0:

        (current_app.login_manager
            .blueprint_login_views[blueprint.name]) = login_view

        if (current_app.login_manager.login_view is not None and
                None not in current_app.login_manager.blueprint_login_views):

            (current_app.login_manager
                .blueprint_login_views[None]) = (current_app.login_manager
                                                 .login_view)

        current_app.login_manager.login_view = None
    else:
        current_app.login_manager.login_view = login_view


def _get_user():
    if has_request_context() and not hasattr(_request_ctx_stack.top, 'user'):
        current_app.login_manager._load_user()

    return getattr(_request_ctx_stack.top, 'user', None)


def _cookie_digest(payload, key=None):
    key = _secret_key(key)

    return hmac.new(key, payload.encode('utf-8'), sha512).hexdigest()


def _get_remote_addr():
    address = request.headers.get('X-Forwarded-For', request.remote_addr)
    if address is not None:
        # An 'X-Forwarded-For' header includes a comma separated list of the
        # addresses, the first address being the actual remote address.
        address = address.encode('utf-8').split(b',')[0].strip()
    return address


def _create_identifier():
    user_agent = request.headers.get('User-Agent')
    if user_agent is not None:
        user_agent = user_agent.encode('utf-8')
    base = '{0}|{1}'.format(_get_remote_addr(), user_agent)
    if str is bytes:
        base = text_type(base, 'utf-8', errors='replace')  # pragma: no cover
    h = sha512()
    h.update(base.encode('utf8'))
    return h.hexdigest()


def _user_context_processor():
    return dict(current_user=_get_user())


def _secret_key(key=None):
    if key is None:
        key = current_app.config['SECRET_KEY']

    if isinstance(key, text_type):  # pragma: no cover
        key = key.encode('latin1')  # ensure bytes

    return key
