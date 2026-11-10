import pytest
from sonic_py_common import device_info
from swsscommon import swsscommon
from unittest import mock
from tests.common.mock_configdb import MockDefaultValueProvider

@pytest.fixture(autouse=True, scope='session')
def mock_get_device_runtime_metadata():
    device_info.get_device_runtime_metadata = mock.MagicMock(return_value={})

@pytest.fixture(autouse=True)
def mock_default_value_provider():
    with mock.patch.object(swsscommon, 'DefaultValueProvider', MockDefaultValueProvider, create=True):
        yield
