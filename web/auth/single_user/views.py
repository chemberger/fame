from urlparse import urlparse
from flask_login import login_user, make_secure_token
from fame.core.user import User
import os

from flask import Blueprint, request, redirect, session

from web.views.helpers import prevent_csrf



auth = Blueprint('auth', __name__, template_folder='templates')

def create_admin():
    create_user( "admin", "admin@fame", ['admin', '*'], ['admin'], ['*'])

    return True

def create_user(name, email, groups, sharing, permissions):
    from fame.core.store import store

    user = User.get(email=email)
    if not store.users.count():
        user = User({
            'name': name,
            'email': email,
            'groups': groups,
            'default_sharing' : sharing,
            'permissions': premissions,
            'enabled': True
        })
        user.save()
        user.generate_avatar()

    return user['api_key']



@auth.route('/login', methods=['GET', 'POST'])
@prevent_csrf
def login():
    redir = request.args.get('next', '/')

    if "/login" in redir:
        redir = '/'
    login_user(User.get(email="admin@fame"))


    return redirect(redir)


@auth.route('/logout')
def logout():
    redir = '/'
    return redirect(redir)
