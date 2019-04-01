# -*- coding: utf-8 -*-
'''
    flask_login.login_manager
    -------------------------
    The LoginManager class.
'''


import warnings
from datetime import datetime, timedelta

from flask import (_request_ctx_stack, abort, current_app, flash, redirect,
                   has_app_context, request, session)

from ._compat import text_type
from .config import (COOKIE_NAME, COOKIE_DURATION, COOKIE_SECURE,
                     COOKIE_HTTPONLY, LOGIN_MESSAGE, LOGIN_MESSAGE_CATEGORY,
                     REFRESH_MESSAGE, REFRESH_MESSAGE_CATEGORY, ID_ATTRIBUTE,
                     AUTH_HEADER_NAME, SESSION_KEYS, USE_SESSION_FOR_NEXT)
from .mixins import AnonymousUserMixin
from .signals import (user_loaded_from_cookie, user_loaded_from_header,
                      user_loaded_from_request, user_unauthorized,
                      user_needs_refresh, user_accessed, session_protected)
from .utils import (login_url as make_login_url, _create_identifier,
                    _user_context_processor, encode_cookie, decode_cookie,
                    make_next_param, expand_login_view)


class LoginManager(object):
    '''这个对象用来保存登录需要的设置。:class:`LoginManager` 的
    实例*不会*绑定到特定程序实例，所以你可以在代码的主体部分创建它，
    然后在工厂函数中绑定到程序实例。
    '''
    def __init__(self, app=None, add_context_processor=True):
        #: 一个创建匿名用户的类或者工厂函数，在未登录时使用。
        self.anonymous_user = AnonymousUserMixin

        #: 当用户需要登录时要重定向到的视图的名称。
        #: （可以是一个绝对 URL，如果你的认证设施在应用程序的外部。）
        self.login_view = None

        #: Names of views to redirect to when the user needs to log in,
        #: per blueprint. If the key value is set to None the value of
        #: :attr:`login_view` will be used instead.
        self.blueprint_login_views = {}

        #: 当用户被重定向到登录页面时闪现的信息。
        self.login_message = LOGIN_MESSAGE

        #: The message category to flash when a user is redirected to the login
        #: page.
        self.login_message_category = LOGIN_MESSAGE_CATEGORY

        #: 当用户需要重新认证时要重定向到的视图的名称。
        self.refresh_view = None

        #: 当用户被重定向到重新认证页面时闪现的信息。
        self.needs_refresh_message = REFRESH_MESSAGE

        #: The message category to flash when a user is redirected to the
        #: 'needs refresh' page.
        self.needs_refresh_message_category = REFRESH_MESSAGE_CATEGORY

        #: The mode to use session protection in. This can be either
        #: ``'basic'`` (the default) or ``'strong'``, or ``None`` to disable
        #: it.
        self.session_protection = 'basic'

        #: If present, used to translate flash messages ``self.login_message``
        #: and ``self.needs_refresh_message``
        self.localize_callback = None

        self.unauthorized_callback = None

        self.needs_refresh_callback = None

        self.id_attribute = ID_ATTRIBUTE

        self._user_callback = None

        self._header_callback = None

        self._request_callback = None

        self._session_identifier_generator = _create_identifier

        if app is not None:
            self.init_app(app, add_context_processor)

    def setup_app(self, app, add_context_processor=True):  # pragma: no cover
        '''
        这个方法已经被弃用。请使用
        :meth:`LoginManager.init_app` 作为代替。
        '''
        warnings.warn('Warning setup_app is deprecated. Please use init_app.',
                      DeprecationWarning)
        self.init_app(app, add_context_processor)

    def init_app(self, app, add_context_processor=True):
        '''
        Configures an application. This registers an `after_request` call, and
        attaches this `LoginManager` to it as `app.login_manager`.

        :param app: The :class:`flask.Flask` object to configure.
        :type app: :class:`flask.Flask`
        :param add_context_processor: Whether to add a context processor to
            the app that adds a `current_user` variable to the template.
            Defaults to ``True``.
        :type add_context_processor: bool
        '''
        app.login_manager = self
        app.after_request(self._update_remember_cookie)

        if add_context_processor:
            app.context_processor(_user_context_processor)

    def unauthorized(self):
        '''
        这个方法会在用户被要求登录的时候调用。如果你使用
        :meth:`LoginManager.unauthorized_handler` 注册了回调函数，
        被调用的会是这个回调函数（译注：首先调用 unauthorized() ，
        然后跳过后续代码直接返回并调用该回调函数）。否则，它将执行下列行为:

            - 向用户闪现消息 :attr:`LoginManager.login_message` 。

            - 如果应用使用了蓝图将通过 `blueprint_login_views` 找到当前蓝图的登录视图。
              如果应用没有使用蓝图或者没有指定当前的蓝图的登录视图，
              将使用 `login_view` 的值。

            - 重定向用户到登录视图。（用户试图访问的页面地址将会被传递到查询字符串的 ``next`` 变量中，
              所以如果验证通过你会重定向到该页面而不是返回首页。
              作为另一选择，如果设置了 USE_SESSION_FOR_NEXT 配置，
              该页面地址将会被添加到 session 的 ``next`` 键中。）

        如果 :attr:`LoginManager.login_view` 未定义，该方法将直接唤起 HTTP 401（Unauthorized）错误。

        该方法应该返回自一个视图或者 before/after_request 函数，
        否则重定向不会生效。（译注：这样才会有有效的 ``next`` 值。）
        '''
        user_unauthorized.send(current_app._get_current_object())

        if self.unauthorized_callback:
            return self.unauthorized_callback()

        if request.blueprint in self.blueprint_login_views:
            login_view = self.blueprint_login_views[request.blueprint]
        else:
            login_view = self.login_view

        if not login_view:
            abort(401)

        if self.login_message:
            if self.localize_callback is not None:
                flash(self.localize_callback(self.login_message),
                      category=self.login_message_category)
            else:
                flash(self.login_message, category=self.login_message_category)

        config = current_app.config
        if config.get('USE_SESSION_FOR_NEXT', USE_SESSION_FOR_NEXT):
            login_url = expand_login_view(login_view)
            session['_id'] = self._session_identifier_generator()
            session['next'] = make_next_param(login_url, request.url)
            redirect_url = make_login_url(login_view)
        else:
            redirect_url = make_login_url(login_view, next_url=request.url)

        return redirect(redirect_url)

    def user_loader(self, callback):
        '''
        用来设置从 session 中重载用户的回调函数。
	被设置的函数应该接收一个用户 ID（``unicode``）并返回一个用户对象，
	如果用户不存在的话返回 ``None``。

        :param callback: 用来取回用户对象的回调函数。
        :type callback: callable
        '''
        self._user_callback = callback
        return callback

    def header_loader(self, callback):
        '''
        该函数已被废弃，请使用
        :meth:`LoginManager.request_loader` 作为代替。

        用来设置通过请求头的值加载用户的回调函数。
	被设置的函数应该接收一个认证令牌并返回一个用户对象，
        如果用户不存在的话返回 ``None``。

        :param callback: 用来取回用户对象的回调函数。
        :type callback: callable
        '''
        print('LoginManager.header_loader is deprecated. Use ' +
              'LoginManager.request_loader instead.')
        self._header_callback = callback
        return callback

    def request_loader(self, callback):
        '''
        This sets the callback for loading a user from a Flask request.
        The function you set should take Flask request object and
        return a user object, or `None` if the user does not exist.

        :param callback: The callback for retrieving a user object.
        :type callback: callable
        '''
        self._request_callback = callback
        return callback

    def unauthorized_handler(self, callback):
        '''
        为 `unauthorized` 方法设置一个回调函数，
        这个回调函数另外还会被 `login_required` 所使用。
        它不接收参数，并且应该返回一个会被发送给用户的响应而不是普通的视图。

        :param callback: 用于未认证用户的回调函数。
        :type callback: callable
        '''
        self.unauthorized_callback = callback
        return callback

    def needs_refresh_handler(self, callback):
        '''
        为 `needs_refresh` 方法设置一个回调函数，
        这个回调函数另外还会被 `fresh_login_required` 所使用。
        它不接收参数，并且应该返回一个会被发送给用户的响应而不是普通的视图。

        :param callback: 用于未认证用户的回调函数。
        :type callback: callable
        '''
        self.needs_refresh_callback = callback
        return callback

    def needs_refresh(self):
        '''
        当用户已经登录但因为登录 session ”不新鲜“而需要重新认证时，该方法将被调用。
        如果你使用 `needs_refresh_handler` 注册了回调函数，
        该回调函数将被调用（译注：过程同上）。否则它将执行下列行为：

            - 向用户闪现消息 :attr:`LoginManager.needs_refresh_message`。

            - 重定向用户到 :attr:`LoginManager.refresh_view`。（用户试图
              访问的页面地址将会被传递到查询字符串的 ``next`` 变量中，
	      所以如果验证通过你会重定向到该页面而不是返回首页。）

        如果 :attr:`LoginManager.refresh_view` 未定义，
	该方法将直接唤起 HTTP 401（Unauthorized）错误。

        该方法应该返回自一个视图或者 before/after_request 函数，否则重定向不会生效。
        '''
        user_needs_refresh.send(current_app._get_current_object())

        if self.needs_refresh_callback:
            return self.needs_refresh_callback()

        if not self.refresh_view:
            abort(401)

        if self.localize_callback is not None:
            flash(self.localize_callback(self.needs_refresh_message),
                  category=self.needs_refresh_message_category)
        else:
            flash(self.needs_refresh_message,
                  category=self.needs_refresh_message_category)

        config = current_app.config
        if config.get('USE_SESSION_FOR_NEXT', USE_SESSION_FOR_NEXT):
            login_url = expand_login_view(self.refresh_view)
            session['_id'] = self._session_identifier_generator()
            session['next'] = make_next_param(login_url, request.url)
            redirect_url = make_login_url(self.refresh_view)
        else:
            login_url = self.refresh_view
            redirect_url = make_login_url(login_url, next_url=request.url)

        return redirect(redirect_url)

    def _update_request_context_with_user(self, user=None):
        '''Store the given user as ctx.user.'''

        ctx = _request_ctx_stack.top
        ctx.user = self.anonymous_user() if user is None else user

    def _load_user(self):
        '''Loads user from session or remember_me cookie as applicable'''

        if self._user_callback is None and self._request_callback is None:
            raise Exception(
                "Missing user_loader or request_loader. Refer to "
                "http://flask-login.readthedocs.io/#how-it-works "
                "for more info.")

        user_accessed.send(current_app._get_current_object())

        # Check SESSION_PROTECTION
        if self._session_protection_failed():
            return self._update_request_context_with_user()

        user = None

        # Load user from Flask Session
        user_id = session.get('user_id')
        if user_id is not None and self._user_callback is not None:
            user = self._user_callback(user_id)

        # Load user from Remember Me Cookie or Request Loader
        if user is None:
            config = current_app.config
            cookie_name = config.get('REMEMBER_COOKIE_NAME', COOKIE_NAME)
            header_name = config.get('AUTH_HEADER_NAME', AUTH_HEADER_NAME)
            has_cookie = (cookie_name in request.cookies and
                          session.get('remember') != 'clear')
            if has_cookie:
                cookie = request.cookies[cookie_name]
                user = self._load_user_from_remember_cookie(cookie)
            elif self._request_callback:
                user = self._load_user_from_request(request)
            elif header_name in request.headers:
                header = request.headers[header_name]
                user = self._load_user_from_header(header)

        return self._update_request_context_with_user(user)

    def _session_protection_failed(self):
        sess = session._get_current_object()
        ident = self._session_identifier_generator()

        app = current_app._get_current_object()
        mode = app.config.get('SESSION_PROTECTION', self.session_protection)

        if not mode or mode not in ['basic', 'strong']:
            return False

        # if the sess is empty, it's an anonymous user or just logged out
        # so we can skip this
        if sess and ident != sess.get('_id', None):
            if mode == 'basic' or sess.permanent:
                sess['_fresh'] = False
                session_protected.send(app)
                return False
            elif mode == 'strong':
                for k in SESSION_KEYS:
                    sess.pop(k, None)

                sess['remember'] = 'clear'
                session_protected.send(app)
                return True

        return False

    def _load_user_from_remember_cookie(self, cookie):
        user_id = decode_cookie(cookie)
        if user_id is not None:
            session['user_id'] = user_id
            session['_fresh'] = False
            user = None
            if self._user_callback:
                user = self._user_callback(user_id)
            if user is not None:
                app = current_app._get_current_object()
                user_loaded_from_cookie.send(app, user=user)
                return user
        return None

    def _load_user_from_header(self, header):
        if self._header_callback:
            user = self._header_callback(header)
            if user is not None:
                app = current_app._get_current_object()
                user_loaded_from_header.send(app, user=user)
                return user
        return None

    def _load_user_from_request(self, request):
        if self._request_callback:
            user = self._request_callback(request)
            if user is not None:
                app = current_app._get_current_object()
                user_loaded_from_request.send(app, user=user)
                return user
        return None

    def _update_remember_cookie(self, response):
        # Don't modify the session unless there's something to do.
        if 'remember' not in session and \
                current_app.config.get('REMEMBER_COOKIE_REFRESH_EACH_REQUEST'):
            session['remember'] = 'set'

        if 'remember' in session:
            operation = session.pop('remember', None)

            if operation == 'set' and 'user_id' in session:
                self._set_cookie(response)
            elif operation == 'clear':
                self._clear_cookie(response)

        return response

    def _set_cookie(self, response):
        # cookie settings
        config = current_app.config
        cookie_name = config.get('REMEMBER_COOKIE_NAME', COOKIE_NAME)
        domain = config.get('REMEMBER_COOKIE_DOMAIN')
        path = config.get('REMEMBER_COOKIE_PATH', '/')

        secure = config.get('REMEMBER_COOKIE_SECURE', COOKIE_SECURE)
        httponly = config.get('REMEMBER_COOKIE_HTTPONLY', COOKIE_HTTPONLY)

        if 'remember_seconds' in session:
            duration = timedelta(seconds=session['remember_seconds'])
        else:
            duration = config.get('REMEMBER_COOKIE_DURATION', COOKIE_DURATION)

        # prepare data
        data = encode_cookie(text_type(session['user_id']))

        if isinstance(duration, int):
            duration = timedelta(seconds=duration)

        try:
            expires = datetime.utcnow() + duration
        except TypeError:
            raise Exception('REMEMBER_COOKIE_DURATION must be a ' +
                            'datetime.timedelta, instead got: {0}'.format(
                                duration))

        # actually set it
        response.set_cookie(cookie_name,
                            value=data,
                            expires=expires,
                            domain=domain,
                            path=path,
                            secure=secure,
                            httponly=httponly)

    def _clear_cookie(self, response):
        config = current_app.config
        cookie_name = config.get('REMEMBER_COOKIE_NAME', COOKIE_NAME)
        domain = config.get('REMEMBER_COOKIE_DOMAIN')
        path = config.get('REMEMBER_COOKIE_PATH', '/')
        response.delete_cookie(cookie_name, domain=domain, path=path)

    @property
    def _login_disabled(self):
        """Legacy property, use app.config['LOGIN_DISABLED'] instead."""
        if has_app_context():
            return current_app.config.get('LOGIN_DISABLED', False)
        return False

    @_login_disabled.setter
    def _login_disabled(self, newvalue):
        """Legacy property setter, use app.config['LOGIN_DISABLED'] instead."""
        current_app.config['LOGIN_DISABLED'] = newvalue
