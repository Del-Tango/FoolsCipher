#
# Excellent Regards, the Alveare Solutions #!/Society -x
#
# Decryption Unit Tests

import pytest
import os
import pysnooper

from tst.conftest import sanitize_line
from fools_cipher import *


#@pysnooper.snoop()
def test_decryption(fc_setup_teardown, decryption_data, encryption_data, conf_json):
    lock_n_load = setup(**conf_json)
    assert lock_n_load
    check = check_preconditions(**conf_json)
    assert check
    build = build_cache(**conf_json)
    assert build
    result = decrypt_ciphertext(*decryption_data, **conf_json)
    assert result
    assert len(result) == len(decryption_data)
    for i in range(len(result)):
        assert sanitize_line(result[i]) == sanitize_line(encryption_data[i])

