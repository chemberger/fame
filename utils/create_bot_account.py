#!/usr/bin/env python


def create_user_for_worker():
    from fame.core.user import User
    from web.auth.single_user.views import create_user

    worker_user = User.get(email="worker@fame")

    if worker_user:
        print "[+] User for worker already created."
    else:
        print "[+] Creating user for worker ..."
        worker_user = create_user("FAME Worker", "worker@fame", ["*"], ["*"], ["worker"])

    return worker_user['api_key']

if __name__ == '__name__':
    print(create_user_for_worker())
