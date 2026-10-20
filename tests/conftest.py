import pytest

from safefile.kdf import ScryptParams


@pytest.fixture
def fast_params():
    # scrypt with the real parameters takes ~0.3 s per call; in tests we use
    # the minimum allowed so the suite runs fast.
    return ScryptParams(log_n=10, r=8, p=1)
