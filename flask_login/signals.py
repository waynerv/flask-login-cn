# -*- coding: utf-8 -*-
'''
    flask_login.signals
    -------------------
    This module provides signals to get notified when Flask-Login performs
    certain actions.
'''


from flask.signals import Namespace


_signals = Namespace()


#: 在用户登录后发送。除了程序实例以外（作为 sender 参数，信号的发送者），
#: 还会传入 `user` 参数，即被登录的用户。
user_logged_in = _signals.signal('logged-in')

#: 在用户注销后发送。除了程序实例以外（作为 sender 参数，信号的发送者），
#: 还会传入 `user` 参数，即被注销的用户。
user_logged_out = _signals.signal('logged-out')

#: Sent when the user is loaded from the cookie. In addition to the app (which
#: is the sender), it is passed `user`, which is the user being reloaded.
user_loaded_from_cookie = _signals.signal('loaded-from-cookie')

#: Sent when the user is loaded from the header. In addition to the app (which
#: is the #: sender), it is passed `user`, which is the user being reloaded.
user_loaded_from_header = _signals.signal('loaded-from-header')

#: Sent when the user is loaded from the request. In addition to the app (which
#: is the #: sender), it is passed `user`, which is the user being reloaded.
user_loaded_from_request = _signals.signal('loaded-from-request')

#: 在用户的登录被确认后发送，会将登录标记为“新鲜”。
#: （普通的登录不会调用这个函数）不接收除了程序实例以外的参数。
user_login_confirmed = _signals.signal('login-confirmed')

#: 当 `LoginManager` 的 `unauthorized` 的方法被调用时发送。
#: 不接收除了程序实例以外的参数。
user_unauthorized = _signals.signal('unauthorized')

#: 当 `LoginManager` 的 `needs_refresh` 方法被调用时发送。
#: 不接收除了程序实例以外的参数。
user_needs_refresh = _signals.signal('needs-refresh')

#: Sent whenever the user is accessed/loaded
#: receives no additional arguments besides the app.
user_accessed = _signals.signal('accessed')

#: 当 session 保护发挥作用时调用，这时一个 session 会被标记为”不新鲜“或被删除。
#: 不接收除了程序实例以外的参数。
session_protected = _signals.signal('session-protected')
