#
# Excellent Regards, the Alveare Solutions #!/Society -x
#
# Build Tests

import pytest
import os
import pysnooper

from tst.conftest import shell_cmd


@pysnooper.snoop()
def test_build(bw_setup_teardown, bw_build_cmd):
    out, err, exit = shell_cmd(' '.join(bw_build_cmd))
    assert exit == 0

