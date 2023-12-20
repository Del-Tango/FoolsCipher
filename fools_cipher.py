#!/usr/bin/python3
#
# Excellent Regards, the Alveare Solutions #!/Society -x
#
# Fools Cipher Enryptor/Decryptor

# [ DESCRIPTION ]: Just Another Substitution Cipher, YAWN... Not quite!
#   Ehh, you'll figure it out, maybe. Probably not.

import optparse
import os
import json
import string
#import pysnooper

SCRIPT_NAME = 'FoolsCipher'
VERSION = '1.0'
VERSION_NAME = 'Arcana'
CURRENT_DIR = os.getcwd()
CONFIG = {
    'config_file': '',
    'current_dir': CURRENT_DIR,
    'cleartext_file': '%s/fc_clear.txt' % CURRENT_DIR,
    'ciphertext_file': '%s/fc_cipher.txt' % CURRENT_DIR,
    'report_file': '%s/fc_report.dump' % CURRENT_DIR,
    'running_mode': 'decrypt',                                                  # <decrypt|encrypt>
    'data_source': 'file',                                                      # <file|terminal>
    'keycode': '01234',                                                         # Order of suits
    'cleanup': [],                                                              # CONFIG keys containing file paths
    'full_cleanup': [
        'cleartext_file', 'ciphertext_file', 'report_file'
    ],
    'report': True,
    'silent': False,
}
ciphertext_cache = {}                                                           # {'0': 'a', ...}
cleartext_cache = {}                                                            # {'a': '0', ...}
character_cache = {
    'lower': list(string.ascii_lowercase),
    'upper': list(string.ascii_uppercase),
    'digits': list(string.digits),
    'symbols': list(
        p for p in string.punctuation
        if p not in ('"', "'", '.', '/', ',', ';', '_', '\\', '^', '`', '~')
    ),
}
suit_cache = {
    '0': [x for x in range(22)],
    '1': [x for x in range(22, 36)],
    '2': [x for x in range(36, 50)],
    '3': [x for x in range(50, 64)],
    '4': [x for x in range(64, 78)],
}
action_result = {'input': [], 'output': [], 'msg': '', 'exit': 0}

# FETCHERS

def fetch_running_mode_from_user(prompt='Action'):
    global CONFIG
    stdout_msg('Specify action or (.back)...', info=True)
    if CONFIG.get('running_mode'):
        prompt = prompt + '[' + CONFIG['running_mode'] + ']> '
        print(
            '[ INFO ]: Leave blank to keep current '\
            '(%s)' % CONFIG['running_mode']
        )
    stdout_msg('1) Encrypt cleartext\n2) Decrypt ciphertext\n3) Disk Cleanup')
    selection_map = {'1': 'encrypt', '2': 'decrypt', '3': 'cleanup'}
    while True:
        selection = input(prompt)
        if not selection:
            if not CONFIG.get('running_mode'):
                continue
            selection = [k for k, v in selection_map.items() \
                if v == CONFIG.get('running_mode')][0]
        if selection == '.back':
            return
        if selection not in ('1', '2', '3'):
            print('[ ERROR ]: Invalid selection (%s)' % selection)
        CONFIG['running_mode'] = selection_map[selection]
        break
    print()
    return selection_map[selection]

def fetch_data_from_user(prompt='Data'):
    stdout_msg(
        'Specify input data for action '\
        '(%s) or (.back)...' % CONFIG.get('running_mode', ''), info=True
    )
    if CONFIG.get('running_mode') in ('encrypt', 'decrypt', 'cleanup'):
        prompt = prompt + '[' + CONFIG['running_mode'] + ']'
    while True:
        data = input(prompt + '> ')
        if not data:
            continue
        if data == '.back':
            return
        break
    print()
    return data

def fetch_replay_confirmation_from_user(prompt='Replay'):
    stdout_msg(
        '[ Q/A ]: Do you want to go again?', silence=CONFIG.get('silent')
    )
    while True:
        answer = input(prompt + '[Y/N]> ')
        if not answer:
            continue
        if answer.lower() not in ('y', 'n', 'yes', 'no', 'yeah', 'nah'):
            print(); stdout_msg(
                'Invalid answer (%s)\n' % answer, err=True,
                silence=CONFIG.get('silent')
            )
            continue
        break
    print()
    return True if answer in ('y', 'yes', 'yeah') else False

def fetch_keycode_from_user(prompt='KeyCode'):
    global CONFIG
    stdout_msg(
        'Specify text keycode sequence or (.back)...', info=True,
        silence=CONFIG.get('silent')
    )
    if CONFIG.get('keycode'):
        prompt = prompt + '[' + CONFIG['keycode'] + ']> '
        stdout_msg(
            'Leave blank to keep current '\
            '(%s)' % CONFIG['keycode'], info=True, silence=CONFIG.get('silent')
        )
    while True:
        code = input(prompt)
        if not code:
            if not CONFIG.get('keycode'):
                continue
            code = CONFIG.get('keycode')
        if code == '.back':
            return
        CONFIG.update({'keycode': code})
        break
    print()
    return code

# CHECKERS

#@pysnooper.snoop()
def check_preconditions(**conf):
    errors = []
    file_paths = ['cleartext_file', 'ciphertext_file']
    requirements = ['running_mode', 'data_source', 'keycode']
    for fl in file_paths + requirements:
        if not conf.get(fl):
            errors.append('Attribute (%s) not set' % fl)
    if conf.get('running_mode', '').lower() == 'encrypt' \
            and conf.get('data_source') != 'terminal':
        if not os.path.exists(conf.get('cleartext_file')):
            errors.append(
                'Cleartext file (%s) not found' % conf.get('ciphertext_file')
            )
    elif conf.get('running_mode', '').lower() == 'decrypt' \
            and conf.get('data_source') != 'terminal':
        if not os.path.exists(conf.get('ciphertext_file')):
            errors.append(
                'Ciphertext file (%s) not found' % conf.get('ciphertext_file')
            )
    if conf.get('running_mode', '').lower() not in ('encrypt', 'decrypt', 'cleanup'):
        errors.append(
            'Invalid running mode specified (%s)' % conf.get('running_mode')
        )
    if conf.get('data_source') not in ('file', 'terminal'):
        errors.append(
            'Invalid data source specified (%s)' % conf.get('data_source')
        )
    action_result.update({'exit': len(errors) + 10, 'msg': '\n'.join(errors)})
    return False if errors else True

# GENERAL

#@pysnooper.snoop()
def load_config(file_path):
    global CONFIG
    if not file_path or not os.path.exists(file_path):
        return
    with open(file_path, 'r') as fl:
        CONFIG.update(json.load(fl))
    return CONFIG

#@pysnooper.snoop()
def file2list(file_path):
    if not file_path or not os.path.exists(file_path):
        return {}
    with open(file_path, 'r') as fl:
        converted = fl.readlines()
    return converted

#@pysnooper.snoop()
def write2file(*args, file_path=str(), mode='w', **kwargs):
    with open(file_path, mode, encoding='utf-8', errors='ignore') \
            as active_file:
        content = ''
        for line in args:
            content = content + (
                str(line) if '\n' in line else str(line) + '\n'
            )
        for line_key in kwargs:
            content = content + \
                str(line_key) + '=' + str(kwargs[line_key]) + '\n'
        try:
            active_file.write(content)
        except UnicodeError as e:
            return False
    return True

def clear_screen():
    return os.system('cls' if os.name == 'nt' else 'clear')

def stdout_msg(message, silence=False, red=False, info=False, warn=False,
            err=False, done=False, bold=False, green=False, ok=False, nok=False):
    if red:
        display_line = '\033[91m' + str(message) + '\033[0m'
    elif green:
        display_line = '\033[1;32m' + str(message) + '\033[0m'
    elif ok:
        display_line = '[ ' + '\033[1;32m' + 'OK' + '\033[0m' + ' ]: ' \
            + '\033[92m' + str(message) + '\033[0m'
    elif nok:
        display_line = '[ ' + '\033[91m' + 'NOK' + '\033[0m' + ' ]: ' \
            + '\033[91m' + str(message) + '\033[0m'
    elif info:
        display_line = '[ INFO ]: ' + str(message)
    elif warn:
        display_line = '[ ' + '\033[91m' + 'WARNING' + '\033[0m' + ' ]: ' \
            + '\033[91m' + str(message) + '\x1b[0m'
    elif err:
        display_line = '[ ' + '\033[91m' + 'ERROR' + '\033[0m' + ' ]: ' \
            + '\033[91m' + str(message) + '\033[0m'
    elif done:
        display_line = '[ ' + '\x1b[1;34m' + 'DONE' + '\033[0m' + ' ]: ' \
            + str(message)
    elif bold:
        display_line = '\x1b[1;37m' + str(message) + '\x1b[0m'
    else:
        display_line = message
    if silence:
        return False
    print(display_line)
    return True

#@pysnooper.snoop()
def build_cache(**context):
    global action_result
    global cleartext_cache                                                      # {'0': 'a', ...}
    global ciphertext_cache                                                     # {'a': '0', ...}
    builder, code = {}, [item for item in list(context.get('keycode', '')) if item]
    if not code:
        return False
    for suit_id in code:
        builder.update({k: str() for k in suit_cache[suit_id]})
    if len(builder) != 78:
        action_result.update({
            'msg': 'Malformed cache! Details: %s' % str(builder),
            'exit': 69,
        })
        return False
    extended_builder = {
        x: y for x, y in zip(
            builder.keys(), character_cache['lower'] + character_cache['upper']
            + character_cache['digits'] + character_cache['symbols']
        )
    }
    for i in range(len(builder), len(builder) * 2):
        extended_builder.update({i: extended_builder[i - len(builder)] + '_'})
    if len(extended_builder) != int(len(builder) * 2):
        action_result.update({
            'msg': 'Malformed cache! Details: %s' % str(builder),
            'exit': 420,
        })
        return False
    cleartext_cache = {str(key): str(val) for key, val in extended_builder.items()}
    ciphertext_cache = {val: key for key, val in cleartext_cache.items()}
    return True

# ACTIONS

#@pysnooper.snoop()
def encrypt_cleartext(*data, **context) -> list:
    '''
    [ INPUT  ]: data = ['74;12;100;2;0;', '13;0;21;', ...]
    [ RETURN ]: ['Asa_q12!?_', '#!|;', ...]
    '''
    global action_result
    ciphertext, failures = [], 0
    for line in data:
        encrypted_cipher = []
        line_lst = [item for item in line.split(';') if item]
        for item in line_lst:
            if item not in cleartext_cache:
                encrypted_cipher.append(item)
                failures += 1
                continue
            encrypted_cipher.append(cleartext_cache[item])
        ciphertext.append(''.join(encrypted_cipher))
    action_result = {
        'input': data,
        'output': ciphertext,
        'msg': 'OK: Encryption successful' if ciphertext and not failures \
            else 'NOK: Encryption failures detected (%s)' % failures,
        'exit': 0 if ciphertext and not failures else 9,
    }
    return ciphertext

#@pysnooper.snoop()
def decrypt_ciphertext(*data, **context) -> list:
    '''
    [ INPUT  ]: data = ['Aa_12!@#;', ...]
    [ RETURN ]: ['23;78;43;21;43;71;77', ...]
    '''
    global action_result
    cleartext, failures = [], 0
    for cipher in data:
        decrypted_cipher = []
        character_set = [item for item in list(cipher.rstrip('\n').rstrip(';')) if item]
        character_fmt, previous = [], None
        for i in range(len(character_set)):
            if i == 0 or character_set[i] != '_':
                previous = character_set[i]
                character_fmt.append(character_set[i])
                continue
            character_fmt[-1] = character_fmt[-1] + '_'
            previous = character_set[i]
        for item in character_fmt:
            if item not in ciphertext_cache:
                decrypted_cipher.append(item)
                failures += 1
                continue
            decrypted_cipher.append(ciphertext_cache[item])
        cleartext.append(';'.join(decrypted_cipher))
    action_result = {
        'input': data,
        'output': cleartext,
        'msg': 'OK: Decryption successful' if cleartext and not failures \
            else 'NOK: Decryption failures detected (%s)' % failures,
        'exit': 0 if cleartext and not failures else 9,
    }
    return cleartext

# FORMATTERS

def format_header():
    header = '''
_______________________________________________________________________________

  *              *             *  %s''' % SCRIPT_NAME + '''  *              *             *
________________________________________________________v%s%s_____________''' % (VERSION, VERSION_NAME) + '''
             Excellent Regards, the Alveare Solutions #!/Society -x
    '''
    return header

# DISPLAY

#@pysnooper.snoop()
def display2terminal(*lines, result=False, **context):
    if (not lines and not result) or context.get('silent'):
        return True
    if result:
        stdout_msg(
            '[ %s ]: %s Action Result' % (
                CONFIG.get('running_mode', '').upper(), SCRIPT_NAME
            ), silence=context.get('silent')
        )
        stdout_msg(
            json.dumps(action_result, indent=4), silence=context.get('silent')
        )
    else:
        stdout_msg('\n'.join(lines) + '\n', silence=context.get('silent'))
    print()
    return True

#@pysnooper.snoop()
def display_header(**context):
    if context.get('silent'):
        return False
    stdout_msg(format_header())
    return True

# CREATORS

#@pysnooper.snoop()
def create_command_line_parser():
    parser = optparse.OptionParser(
        format_header() + '\n[ DESCRIPTION ]: FoolsCipher Encryption/Decryption -\n\n'
        '    [ Ex ]: Terminal based running mode\n'
        '       ~$ %prog \n\n'
        '    [ Ex ]: File based running mode decryption\n'
        '       ~$ %prog \\ \n'
        '           --action decrypt \\ \n'
        '           --key-code 01234 \\ \n'
        '           --ciphertext-file fc_cipher.txt\n\n'
        '    [ Ex ]: File based running mode encryption with no STDOUT\n'
        '       ~$ %prog \\ \n'
        '           --action encrypt \\ \n'
        '           --key-code 01234 \\ \n'
        '           --cleartext-file fc_clear.txt \\ \n'
        '           --silent\n\n'
        '   [ Ex ]: Run with context data from JSON config file\n'
        '       ~$ %prog \\ \n'
        '           --konfig-file conf/fools_cipher.conf.json\n\n'
        '   [ Ex ]: Cleanup all generated files from disk\n'
        '       ~$ %prog \\ \n'
        '           --action cleanup'
    )
    return parser

# PARSERS

#@pysnooper.snoop()
def process_command_line_options(parser, **context):
    global CONFIG
    (options, args) = parser.parse_args()
    if options.config_file:
        return load_config(options.config_file)
    to_update = {key: val for key, val in options.__dict__.items() if val}
    CONFIG.update(to_update)
    return to_update

#@pysnooper.snoop()
def add_command_line_parser_options(parser):
    parser.add_option(
        '-a', '--action', dest='running_mode', type='string',
        help='Specify the desired action. Options: <encrypt|decrypt|cleanup>',
    )
    parser.add_option(
        '-k', '--key-code', dest='keycode', type='string',
        help='Specify password.',
    )
    parser.add_option(
        '-c', '--cleartext-file', dest='cleartext_file', type='string',
        help='Path to the output or input (depends on action) cleartext file. '
            'Default: ./fc_clear.txt'
    )
    parser.add_option(
        '-C', '--ciphertext-file', dest='ciphertext_file', type='string',
        help='Path to the output or input (depends on action) ciphertext file. '
            'Default: ./fc_cipher.txt'
    )
    parser.add_option(
        '-s', '--data-src', dest='data_source', type='string',
        help='Specify if the input data source. Options: <file|terminal>, '
            'Default: file'
    )
    parser.add_option(
        '-K', '--konfig-file', dest='config_file', type=str,
        help='Path to the %s configuration file.' % SCRIPT_NAME
    )
    parser.add_option(
        '-S', '--silent', dest='silent', action='store_true',
        help='Run with no STDOUT output. Implies a file data source.'
    )
    return parser

#@pysnooper.snoop()
def parse_cli_args(**context):
    parser = create_command_line_parser()
    add_command_line_parser_options(parser)
    return process_command_line_options(parser, **context)

# REPORTERS

def report_action_result(result, **context):
    return write2file(
        json.dumps(action_result, indent=4),
        file_path=context.get('report_file')
    )

# CLEANERS

#@pysnooper.snoop()
def cleanup(full=False, **context):
    global CONFIG
    global action_result
    to_remove = [
        context.get(label, '')
        for label in context['cleanup' if not full else 'full_cleanup']
    ]
    try:
        for file_path in to_remove:
            if not os.path.exists(file_path):
                continue
            os.remove(file_path)
        if full:
            CONFIG.update({'report': False})
    except OSError as e:
        action_result.update({
            'msg': 'Cleanup error! Details: %s' % str(e),
            'exit': 8,
        })
        return False
    return True

# SETUP

#@pysnooper.snoop()
def setup(**context):
    global action_result
    file_paths = ['cleartext_file', 'ciphertext_file']
    errors = []
    for fl_path in file_paths:
        if fl_path not in context or os.path.exists(context[fl_path]):
            continue
        try:
            create = write2file('', mode='a', file_path=context[fl_path])
        except Exception as e:
            errors.append(str(e))
    if errors:
        action_result.update({
            'msg': '%s Setup failed ' % SCRIPT_NAME +
                'with (%d) errors! Details: ' % len(errors) + ','.join(errors),
            'exit': 11,
        })
    return True if not errors else False

# INIT

#@pysnooper.snoop()
def init_terminal_running_mode(**conf):
    global action_result
    while True:
        action = fetch_running_mode_from_user()
        if not action:
            action_result.update({
                'exit': 0,
                'msg': 'Action aborted at running mode prompt'
            })
            break
        if action == 'cleanup':
            clean = cleanup(full=True, **conf)
            clear = clear_screen()
            display_header(**conf)
            continue
        keycode = fetch_keycode_from_user()
        if not keycode:
            action_result.update({
                'exit': 0,
                'msg': 'Action aborted at keycode prompt'
            })
            break
        data = fetch_data_from_user()
        if not data:
            action_result.update({
                'exit': 0,
                'msg': 'Action aborted at data input prompt'
            })
            break
        handlers = {
            'encrypt': encrypt_cleartext,
            'decrypt': decrypt_ciphertext,
        }
        if conf.get('running_mode') not in handlers:
            action_result.update({
                'exit': 4,
                'msg': 'Invalid running mode %s' % conf.get('running_mode')
            })
            return action_result['exit']
        action = handlers[CONFIG['running_mode']](data, **conf)
        if not action:
            action_result.update({
                'exit': 5,
                'msg': 'Action %s failed' % conf.get('running_mode')
            })
        display = display2terminal(result=True, **conf)
        if not display:
            action_result.update({
                'exit': 7,
                'msg': 'Could not display action result'
            })
        replay = fetch_replay_confirmation_from_user()
        if not replay:
            break
        clear = clear_screen()
        display_header(**conf)
    return action_result['exit']

#@pysnooper.snoop()
def init_file_running_mode(**conf):
    global action_result
    if not conf.get('keycode'):
        keycode = fetch_keycode_from_user()
    src_file = conf.get('ciphertext_file') \
        if conf.get('running_mode') == 'decrypt' else conf.get('cleartext_file')
    data = [
        item.rstrip('\n') if item != '\n' else item for item in file2list(src_file)
    ]
    if not data:
        action_result.update({
            'exit': 2,
            'msg': 'Could not fetch source data from file %s' % src_file
        })
        return action_result['exit']
    handlers = {
        'encrypt': encrypt_cleartext,
        'decrypt': decrypt_ciphertext,
    }
    if conf.get('running_mode') not in handlers:
        action_result.update({
            'exit': 4,
            'msg': 'Invalid running mode %s' % conf.get('running_mode')
        })
        return action_result['exit']
    action = handlers[CONFIG['running_mode']](*data, **conf)
    if not action:
        action_result.update({
            'exit': 5,
            'msg': 'Action %s failed' % conf.get('running_mode')
        })
    else:
        action_result.update({'output': action})
    out_file = conf.get('cleartext_file') if conf.get('running_mode') \
        == 'decrypt' else conf.get('ciphertext_file')
    write = write2file(*action, file_path=out_file)
    if not write:
        action_result.update({
            'exit': 6,
            'msg': 'Could not write to out file %s' % out_file
        })
    display = display2terminal(result=True, **conf)
    if not display:
        action_result.update({
            'exit': 7,
            'msg': 'Could not display action result'
        })
    return action_result['exit']

#@pysnooper.snoop()
def init():
    global CONFIG
    global action_result
    cli_parse = parse_cli_args(**CONFIG)
    CONFIG['data_source'] = 'terminal' if not cli_parse \
        and not CONFIG['data_source'] else 'file'
    display_header(**CONFIG)
    stdout_msg(
        "[ INIT ]: Playing The Fool requires both Wisdom and Cunning...\n",
        silence=CONFIG.get('silent')
    )
    try:
        if CONFIG.get('running_mode', '').lower() == 'cleanup':
            stdout_msg(
                '[ ACTION ]: Cleaning up files from disk...',
                silence=CONFIG.get('silent')
            )
            clean = cleanup(full=True, **CONFIG)
            stdout_msg(
                'Terminating with exit code (%s)' % str(action_result['exit']),
                silence=CONFIG.get('silent'), done=True
            )
            exit(action_result['exit'])
        lock_n_load = setup(**CONFIG)
        check = check_preconditions(**CONFIG)
        if not check:
            details = action_result.get('msg', '')
            action_result.update({
                'msg': 'Action preconditions check failed for running mode '\
                    '%s. Details: %s' % (CONFIG.get('running_mode'), details),
                'exit': 1,
            })
            exit(action_result['exit'])
        build = build_cache(**CONFIG)
        if not build:
            action_result.update({
                'exit': 3,
                'msg': 'Could not build key cache'
            })
        if not cli_parse or CONFIG.get('data_source').lower() == 'terminal':
            run = init_terminal_running_mode(**CONFIG)
        else:
            run = init_file_running_mode(**CONFIG)
    except Exception as e:
        action_result.update({'msg': str(e), 'exit': 10})
    finally:
        if CONFIG.get('cleanup'):
            clean = cleanup(**CONFIG)
        if CONFIG.get('report'):
            report = report_action_result(action_result, **CONFIG)
            if not report:
                action_result.update({
                    'msg': 'Failed to generate report %s'
                        % CONFIG.get('report_file'),
                    'exit': 20,
                })
    print(); stdout_msg(
        'Terminating with exit code (%s)' % str(action_result['exit']),
        silence=CONFIG.get('silent'), done=True
    )
    exit(action_result['exit'])


if __name__ == '__main__':
    init()


# CODE DUMP

