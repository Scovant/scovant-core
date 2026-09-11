import re

import scovant_core


def test_version_is_semver():
    assert re.fullmatch(r"\d+\.\d+\.\d+", scovant_core.__version__)


def test_compat_exposes_soft_time_limit_exception():
    from scovant_core.compat import SoftTimeLimitExceeded
    assert issubclass(SoftTimeLimitExceeded, Exception)
