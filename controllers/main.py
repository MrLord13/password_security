# Copyright 2015 LasLabs Inc.
# License LGPL-3.0 or later (http://www.gnu.org/licenses/lgpl.html).

import logging

from werkzeug.exceptions import BadRequest

from odoo import http
from odoo.http import request

from odoo.addons.auth_signup.controllers.main import AuthSignupHome
from odoo.addons.auth_totp.controllers.home import Home as TotpHome
from odoo.addons.web.controllers.home import ensure_db

_logger = logging.getLogger(__name__)


# =========================
# SIGNUP / LOGIN SECURITY
# =========================
class PasswordSecurityHome(AuthSignupHome):
    def do_signup(self, qcontext):
        password = qcontext.get("password")
        user = request.env.user
        if password:
            user._check_password(password)

        return super().do_signup(qcontext)

    @http.route()
    def web_login(self, *args, **kw):
        ensure_db()
        response = super().web_login(*args, **kw)
        user = request.env.user
        if not request.params.get("login_success"):
            return response

        if not user:
            return response

        if user._password_has_expired():
            user.action_expire_password()
            return request.redirect("/web/reset_password")
        return response

    @http.route()
    def web_auth_signup(self, *args, **kw):

        try:
            qcontext = self.get_auth_signup_qcontext()
        except Exception as e:
            _logger.exception("Signup context error")
            raise BadRequest("Invalid signup request") from e

        try:
            return super().web_auth_signup(*args, **kw)

        except Exception as e:
            qcontext["error"] = str(e)

            response = request.render("auth_signup.signup", qcontext)
            response.headers["X-Frame-Options"] = "SAMEORIGIN"
            response.headers["Content-Security-Policy"] = "frame-ancestors 'self'"

            return response


class PasswordSecurity2FAHome(TotpHome):

    @http.route()
    def web_totp(self, redirect=None, **kwargs):

        ensure_db()

        already_logged_in = bool(request.session.uid)

        result = super().web_totp(redirect, **kwargs)

        user = request.env.user

        if not request.session.uid or not user:
            return result
        if already_logged_in:
            return result
        if not user._password_has_expired():
            return result
        user.action_expire_password()

        return result