#!/usr/bin/env python
#
# Excellent Regards, the Alveare Solutions #!/Society -x
#
# Building...

import sys
import os
import pkgutil
#import pysnooper

from setuptools import setup, find_packages

SCRIPT_NAME = 'foolscipher'
VERSION = '1.0'
conf_path = 'conf/fools_cipher.conf.json'
root_dir = os.path.abspath(os.path.dirname(__file__))

#@pysnooper.snoop()
def find_file_recursively(directory, target_filename):
    for root, _, files in os.walk(directory):
        if target_filename in files:
            return os.path.join(root, target_filename)
    return None

# MISCELLANEOUS

#@pysnooper.snoop()
def add_package_dir_to_path() -> None:
    '''
    [ NOTE ]: Add the package directory to the Python path
    '''
    package_dir = os.path.join(root_dir, SCRIPT_NAME)
    sys.path.insert(0, package_dir)
    for loader, name, is_pkg in pkgutil.walk_packages([package_dir]):
        full_name = SCRIPT_NAME + '.' + name
        if is_pkg:
            path = loader.path
        else:
            path = os.path.dirname(loader.path)
        sys.path.insert(0, path)

if __name__ == '__main__':
    with open('README.md', 'r', encoding='utf-8') as fl:
        readme_content = fl.read()
    setup_info = {
        'name': SCRIPT_NAME,
        'version': VERSION,
        'author': '#!/Society -x',
        'author_email': 'alveare.solutions@gmail.com',
        'url': 'https://github.com/Del-Tango/',
        'download_url': '',
        'project_urls': {
            'Documentation': 'https://github.com/Del-Tango/FoolsCipher/blob/master/dox',
            'Source': 'https://github.com/Del-Tango/FoolsCipher',
            'Tracker': 'https://github.com/Del-Tango/FoolsCipher/issues',
        },
        'description': 'Cipher automation',
        'long_description': readme_content,
        'long_description_content_type': 'text/markdown',
        'license': 'BSD',
        'classifiers': [
            'Development Status :: 1 - Development/Unstable',
            'Environment :: Linux :: Windows',
            'Intended Audience :: End Users',
            'License :: ',
            'Operating System :: POSIX :: Linux :: Windows',
            'Programming Language :: Python :: 3',
            'Programming Language :: Python :: 3.8',
            'Programming Language :: Python :: 3.9',
            'Programming Language :: Python :: 3.10',
            'Programming Language :: Python :: 3.11',
            'Topic Encryption :: Decryption :: Security :: Utils :: Scripts',
        ],
        'packages': find_packages(),
        'package_data': {SCRIPT_NAME: [conf_path]},
        'options': {'build': {'build_base': '_build'}},
        'zip_safe': True,
        'install_requires': [],
        'entry_points': {
            'console_scripts': [
                '%s=foolscipher.fools_cipher:init' % SCRIPT_NAME,
            ]
        }
    }
    add_package_dir_to_path()
    setup(**setup_info)

