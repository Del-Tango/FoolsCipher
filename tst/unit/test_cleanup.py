#
# Excellent Regards, the Alveare Solutions #!/Society -x
#
# Cleanup Unit Tests

import pytest
import os
import pysnooper

from tst.conftest import shell_cmd
from fools_cipher import *


@pysnooper.snoop()
def test_cleanup(fc_setup_teardown, fc_encryption_cmd, encryption_data, conf_json):
    create_cleartext = write2file(
        *encryption_data, file_path=conf_json['cleartext_file'], mode='w'
    )
    assert create_cleartext
    out, err, exit = shell_cmd(' '.join(fc_encryption_cmd))
    assert exit == 0
    conf_json['report'] = True
    result = cleanup(**conf_json)
    assert result
    for label in conf_json['cleanup']:
        assert not os.path.exists(conf_json[label])

@pysnooper.snoop()
def test_full_cleanup(fc_setup_teardown, fc_encryption_cmd, encryption_data, conf_json):
    create_cleartext = write2file(
        *encryption_data, file_path=conf_json['cleartext_file'], mode='w'
    )
    assert create_cleartext
    out, err, exit = shell_cmd(' '.join(fc_encryption_cmd))
    assert exit == 0
    conf_json['report'] = True
    result = cleanup(full=True, **conf_json)
    assert result
    for label in conf_json['full_cleanup']:
        assert not os.path.exists(conf_json[label])
