#
# Excellent Regards, the Alveare Solutions #!/Society -x
#
# Cleanup Tests

import pytest
import pysnooper

from tst.conftest import shell_cmd


@pysnooper.snoop()
def test_cleanup(bw_setup_cmd, bw_build_cmd, bw_install_cmd, bw_cleanup_cmd, fc_cleanup_cmd):
    out, err, exit = shell_cmd(' '.join(bw_setup_cmd))
    assert exit == 0
    out, err, exit = shell_cmd(' '.join(bw_build_cmd))
    assert exit == 0
    out, err, exit = shell_cmd(' '.join(bw_install_cmd))
    assert exit == 0
    out, err, exit = shell_cmd(' '.join(bw_cleanup_cmd))
    assert exit == 0
    out, err, exit = shell_cmd(' '.join(fc_cleanup_cmd))
    assert exit == 0
