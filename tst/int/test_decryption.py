#
# Excellent Regards, the Alveare Solutions #!/Society -x
#
# Decryption Integration Tests

import pytest
import json
import os
import pysnooper

from tst.conftest import shell_cmd, sanitize_line, CONFIG
from fools_cipher import write2file, file2list


@pysnooper.snoop()
def test_file_base_decryption_from_cli(fc_setup_teardown, fc_decryption_cmd,
                                       decryption_data, encryption_data, conf_json):
    conf_json.update({'running_mode': 'decrypt', 'report': False})
    write2file(
        json.dumps(conf_json, indent=4), file_path=CONFIG['config_file'], mode='w'
    )
    cmd = fc_decryption_cmd + [
        '--key-code', CONFIG['keycode'],
        '--ciphertext-file', CONFIG['ciphertext_file'],
        '--cleartext-file', CONFIG['cleartext_file'],
    ]
    write2file(
        *decryption_data, file_path=CONFIG['ciphertext_file'], mode='w'
    )
    out, err, exit = shell_cmd(' '.join(cmd))
    assert exit == 0
    cleartext_content = file2list(CONFIG['cleartext_file'])
    assert cleartext_content
    for i in range(len(cleartext_content)):
        assert sanitize_line(cleartext_content[i]) == sanitize_line(encryption_data[i])

@pysnooper.snoop()
def test_file_base_decryption_from_cli_silently(fc_setup_teardown, fc_decryption_cmd,
                                                decryption_data, encryption_data, conf_json):
    conf_json.update({'running_mode': 'decrypt', 'report': False})
    write2file(
        json.dumps(conf_json, indent=4), file_path=CONFIG['config_file'], mode='w'
    )
    cmd = fc_decryption_cmd + [
        '--key-code', CONFIG['keycode'],
        '--ciphertext-file', CONFIG['ciphertext_file'],
        '--cleartext-file', CONFIG['cleartext_file'],
        '--silent'
    ]
    write2file(
        *decryption_data, file_path=CONFIG['ciphertext_file'], mode='w'
    )
    out, err, exit = shell_cmd(' '.join(cmd))
    assert exit == 0
    cleartext_content = file2list(CONFIG['cleartext_file'])
    assert cleartext_content
    for i in range(len(cleartext_content)):
        assert sanitize_line(cleartext_content[i]) == sanitize_line(encryption_data[i])

@pysnooper.snoop()
def test_file_base_decryption_from_cli_reported(fc_setup_teardown, fc_decryption_cmd,
                                                decryption_data, encryption_data, conf_json):
    conf_json.update({'running_mode': 'decrypt', 'report': True})
    write2file(
        json.dumps(conf_json, indent=4), file_path=CONFIG['config_file'], mode='w'
    )
    cmd = fc_decryption_cmd + [
        '--key-code', CONFIG['keycode'],
        '--ciphertext-file', CONFIG['ciphertext_file'],
        '--cleartext-file', CONFIG['cleartext_file'],
        '--silent'
    ]
    write2file(
        *decryption_data, file_path=CONFIG['ciphertext_file'], mode='w'
    )
    out, err, exit = shell_cmd(' '.join(cmd))
    assert exit == 0
    assert os.path.exists(CONFIG['report_file'])
    cleartext_content = file2list(CONFIG['cleartext_file'])
    assert cleartext_content
    for i in range(len(cleartext_content)):
        assert sanitize_line(cleartext_content[i]) == sanitize_line(encryption_data[i])
    report_content = {}
    with open(CONFIG['report_file'], 'r') as fl:
        report_content = json.load(fl)
    assert report_content['input']
    assert isinstance(report_content['input'], list)
    assert report_content['output']
    assert isinstance(report_content['output'], list)
    assert isinstance(report_content['msg'], str)
    assert isinstance(report_content['exit'], int)
    assert report_content['exit'] == 0

@pysnooper.snoop()
def test_file_base_decryption_from_config(fc_setup_teardown, fc_konfig_cmd,
                                          decryption_data, encryption_data, conf_json):
    conf_json.update({'running_mode': 'decrypt'})
    write2file(
        json.dumps(conf_json, indent=4), file_path=CONFIG['config_file'], mode='w'
    )
    write2file(
        *decryption_data, file_path=CONFIG['ciphertext_file'], mode='w'
    )
    out, err, exit = shell_cmd(' '.join(fc_konfig_cmd))
    assert exit == 0
    cleartext_content = file2list(CONFIG['cleartext_file'])
    assert cleartext_content
    for i in range(len(cleartext_content)):
        assert sanitize_line(cleartext_content[i]) == sanitize_line(encryption_data[i])

