#!/usr/bin/env python

import os
import sys
from time import time

sys.path.append(os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")))

from fame.core import fame_init
from fame.core.config import Config
from fame.core.internals import Internals
from fame.common.config import fame_config

def add_community_repository():
    from fame.core.repository import Repository

    repo = Repository.get(name="community")

    if repo:
        print "[+] Community repository already installed."
    else:
        print "[+] Installing community repository ..."
        repo = Repository({
            'name': 'community',
            'address': 'https://github.com/certsocietegenerale/fame_modules.git',
            'private': False,
            'status': 'cloning'
        })
        repo.save()
        repo.do_clone()


def create_single_user_account():
    if fame_config.auth == "single_user":
        from web.auth.single_user.views import create_user
        create_user()


def create_types():
    types = Config.get(name='types')
    if types is None:
        types = Config({
            'name': 'types',
            'description': 'Mappings for file type determination.',
            'config': [
                {
                    'name': 'mappings',
                    'type': 'text',
                    'value': open(os.path.join(os.path.dirname(os.path.abspath(__file__)),"initial_type_entry.txt" )).read(),
                    'description': "In order to determine the file type, FAME will use the `python-magic` library. It will then try to find a match in 'mappings' for either the extension, the detailed type or the mime type (in this order of priority). If no matching type was found, the mime type will be used."
                }
            ]
        })

        types.save()


def create_internals():
    updates = Internals.get(name='updates')
    if updates is None:
        updates = Internals({
            'name': 'updates',
            'last_update': time()
        })

        updates.save()


def create_virustotal_configuration():
    vt = Config.get(name='virustotal')
    if vt is None:
        vt = Config({
            'name': 'virustotal',
            'description': 'VirusTotal API configuration, in order to be able to submit hashes.',
            'config': [
                {
                    'name': 'api_key',
                    'description': 'VirusTotal Intelligence API key.',
                    'type': 'str',
                    'value': None
                }
            ]})

        vt.save()


def create_initial_data():
    create_single_user_account()
    create_types()
    create_virustotal_configuration()
    create_internals()


if __name__ == '__main__':
    fame_init()
    create_initial_data()
    add_community_repository()
    print "[+] Created initial data."
