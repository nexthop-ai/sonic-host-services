import copy
import importlib.machinery
import importlib.util
import filecmp
import shutil
import os
import sys
from swsscommon import swsscommon

from parameterized import parameterized
from unittest import TestCase, mock
from sonic_py_common.general import getstatusoutput_noshell
from tests.hostcfgd.test_tacacs_vectors import HOSTCFGD_TEST_TACACS_VECTOR
from tests.common.mock_configdb import MockConfigDb, MockDBConnector, MockDefaultValueProvider

test_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
modules_path = os.path.dirname(test_path)
scripts_path = os.path.join(modules_path, "scripts")
templates_path = os.path.join(modules_path, "data/templates")
output_path = os.path.join(test_path, "hostcfgd/output")
sample_output_path = os.path.join(test_path, "hostcfgd/sample_output")
sys.path.insert(0, modules_path)

# Load the file under test
hostcfgd_path = os.path.join(scripts_path, 'hostcfgd')
loader = importlib.machinery.SourceFileLoader('hostcfgd', hostcfgd_path)
spec = importlib.util.spec_from_loader(loader.name, loader)
hostcfgd = importlib.util.module_from_spec(spec)
loader.exec_module(hostcfgd)
sys.modules['hostcfgd'] = hostcfgd

# Mock swsscommon classes
hostcfgd.ConfigDBConnector = MockConfigDb
hostcfgd.DBConnector = MockDBConnector
hostcfgd.Table = mock.Mock()

class TestHostcfgdTACACS(TestCase):
    """
        Test hostcfd daemon - TACACS
    """
    def run_diff(self, file1, file2):
        _, output = getstatusoutput_noshell(['diff', '-ur', file1, file2])
        return output

    """
        Mock hostcfgd
    """
    def mock_hostcfgd(self, test_data, config_name, op_path, sop_path):
        t_path = templates_path
        hostcfgd.PAM_AUTH_CONF_TEMPLATE = t_path + "/common-auth-sonic.j2"
        hostcfgd.NSS_TACPLUS_CONF_TEMPLATE = t_path + "/tacplus_nss.conf.j2"
        hostcfgd.NSS_RADIUS_CONF_TEMPLATE = t_path + "/radius_nss.conf.j2"
        hostcfgd.PAM_RADIUS_AUTH_CONF_TEMPLATE = t_path + "/pam_radius_auth.conf.j2"
        hostcfgd.PAM_AUTH_CONF = op_path + "/common-auth-sonic"
        hostcfgd.PAM_COMMON_SESS = op_path + "/common-session"
        hostcfgd.NSS_TACPLUS_CONF = op_path + "/tacplus_nss.conf"
        hostcfgd.NSS_RADIUS_CONF = op_path + "/radius_nss.conf"
        hostcfgd.NSS_CONF = op_path + "/nsswitch.conf"
        hostcfgd.ETC_PAMD_SSHD = op_path + "/sshd"
        hostcfgd.ETC_PAMD_LOGIN = op_path + "/login"
        hostcfgd.RADIUS_PAM_AUTH_CONF_DIR = op_path + "/"
        hostcfgd.LDAP_CONF_TEMPLATE = t_path + "/ldap.conf.j2"
        hostcfgd.LDAP_CONF = op_path + "/ldap.conf"

        shutil.rmtree( op_path, ignore_errors=True)
        os.mkdir( op_path)

        shutil.copyfile( sop_path + "/sshd.old", op_path + "/sshd")
        shutil.copyfile( sop_path + "/login.old", op_path + "/login")

        MockConfigDb.set_config_db(test_data[config_name])
        return hostcfgd.HostConfigDaemon()

    """
        Render different config
    """
    def render_config_file(self, host_config_daemon):
        aaa = host_config_daemon.config_db.get_table('AAA')

        try:
            tacacs_global = host_config_daemon.config_db.get_table('TACPLUS')
        except:
            tacacs_global = []
        try:
            tacacs_server = \
                host_config_daemon.config_db.get_table('TACPLUS_SERVER')
        except:
            tacacs_server = []

        host_config_daemon.aaacfg.load(aaa,tacacs_global,tacacs_server,[],[], {}, {})

    """
        Check different config
    """
    def check_config(self, test_name, test_data, config_name):
        op_path = output_path + "/" + test_name + "_" + config_name
        sop_path = sample_output_path + "/" +  test_name + "_" + config_name
        host_config_daemon = self.mock_hostcfgd(test_data, config_name, op_path, sop_path)

        self.render_config_file(host_config_daemon)

        dcmp = filecmp.dircmp(sop_path, op_path)
        diff_output = ""
        for name in dcmp.diff_files:
            diff_output += \
                "Diff: file: {} expected: {} output: {}\n".format(\
                    name, dcmp.left, dcmp.right)
            diff_output += self.run_diff( dcmp.left + "/" + name,\
                dcmp.right + "/" + name)
        self.assertTrue(len(diff_output) == 0, diff_output)


    @parameterized.expand(HOSTCFGD_TEST_TACACS_VECTOR)
    def test_hostcfgd_tacacs(self, test_name, test_data):
        """
            Test TACACS hostcfd daemon initialization

            Args:
                test_name(str): test name
                test_data(dict): test data which contains initial Config Db tables, and expected results

            Returns:
                None
        """
        # test local config
        self.check_config(test_name, test_data, "config_db_local")
        # test remote config
        self.check_config(test_name, test_data, "config_db_tacacs")
        # test local + tacacs config
        self.check_config(test_name, test_data, "config_db_local_and_tacacs")
        # test disable accounting
        self.check_config(test_name, test_data, "config_db_disable_accounting")

    @parameterized.expand(HOSTCFGD_TEST_TACACS_VECTOR)
    def test_hostcfgd_traceid_disabled_with_tacacs(self, test_name, test_data):
        test_data = copy.deepcopy(test_data)
        config_name = "config_db_tacacs"
        test_data[config_name]["TACPLUS"]["global"]["traceid_authorization"] = "false"
        op_path = output_path + "/" + test_name + "_traceid_disabled"
        sop_path = sample_output_path + "/" + test_name + "_" + config_name
        host_config_daemon = self.mock_hostcfgd(test_data, config_name, op_path, sop_path)

        self.render_config_file(host_config_daemon)

        with open(hostcfgd.NSS_TACPLUS_CONF) as conf_file:
            directives = conf_file.read().splitlines()
        self.assertIn("tacacs_authorization", directives)
        self.assertNotIn("traceid_authorization", directives)

    @parameterized.expand(HOSTCFGD_TEST_TACACS_VECTOR)
    def test_hostcfgd_sshd_not_empty(self, test_name, test_data):
        """
            Test hostcfd sshd config file not empty check

            Args:
                test_name(str): test name
                test_data(dict): test data which contains initial Config Db tables, and expected results

            Returns:
                None
        """
        config_name = "config_db_local"
        op_path = output_path + "/" + test_name + "_" + config_name
        sop_path = sample_output_path + "/" +  test_name + "_" + config_name
        host_config_daemon = self.mock_hostcfgd(test_data, config_name, op_path, sop_path)

        # test sshd empty case
        hostcfgd.ETC_PAMD_SSHD = op_path + "/sshd_empty"
        shutil.copyfile( sop_path + "/sshd_empty.old", op_path + "/sshd_empty")

        # render with empty sshd config file and check error log
        original_syslog = hostcfgd.syslog
        with mock.patch('hostcfgd.syslog.syslog') as mocked_syslog:
            mocked_syslog.LOG_ERR = original_syslog.LOG_ERR
            self.render_config_file(host_config_daemon)

            # check sys log
            expected = [
                mock.call(mocked_syslog.LOG_ERR, "file size check failed: {} is empty, file corrupted".format(hostcfgd.ETC_PAMD_SSHD))
            ]
            mocked_syslog.assert_has_calls(expected)

        # test sshd missing case
        hostcfgd.ETC_PAMD_SSHD = op_path + "/sshd_missing"

        with mock.patch('hostcfgd.syslog.syslog') as mocked_syslog:
            mocked_syslog.LOG_ERR = original_syslog.LOG_ERR

            # missing file can't test by render config file,
            # because missing file case difficult to reproduce: code always generate a empty file.
            host_config_daemon.aaacfg.check_file_not_empty(hostcfgd.ETC_PAMD_SSHD)

            # check sys log
            expected = [
                mock.call(mocked_syslog.LOG_ERR, "file size check failed: {} is missing".format(hostcfgd.ETC_PAMD_SSHD))
            ]
            mocked_syslog.assert_has_calls(expected)

        # test sshd exist and not empty case
        hostcfgd.ETC_PAMD_SSHD = op_path + "/sshd_not_empty"
        shutil.copyfile( sop_path + "/sshd_not_empty.old", op_path + "/sshd_not_empty")

        # render with empty sshd config file and check error log
        original_syslog = hostcfgd.syslog
        with mock.patch('hostcfgd.syslog.syslog') as mocked_syslog:
            mocked_syslog.LOG_INFO = original_syslog.LOG_INFO
            self.render_config_file(host_config_daemon)

            # check sys log
            expected = [
                mock.call(mocked_syslog.LOG_INFO, "file size check pass: {} size is ({}) bytes".format(hostcfgd.ETC_PAMD_SSHD, 21))
            ]
            mocked_syslog.assert_has_calls(expected)

    @parameterized.expand(HOSTCFGD_TEST_TACACS_VECTOR)
    def test_hostcfgd_delete_config_table(self, test_name, test_data):
        """
            Test hostcfd delete config table check

            Args:
                test_name(str): test name
                test_data(dict): test data which contains initial Config Db tables, and expected results

            Returns:
                None
        """
        config_name = "config_db_local"
        op_path = output_path + "/" + test_name + "_" + config_name
        sop_path = sample_output_path + "/" +  test_name + "_" + config_name
        host_config_daemon = self.mock_hostcfgd(test_data, config_name, op_path, sop_path)
        host_config_daemon.register_callbacks()

        # render with delete config table
        original_syslog = hostcfgd.syslog
        with mock.patch('hostcfgd.syslog.syslog') as mocked_syslog:
            mocked_syslog.LOG_INFO = original_syslog.LOG_INFO
            mocked_syslog.LOG_ERR = original_syslog.LOG_ERR

            # simulate subscribe callback
            try:
                host_config_daemon.__dict__['config_db'].publish('AAA', 'authorization', 'DEL', None)
            except TypeError as e:
                assert False

            # check sys log
            expected = [
                mock.call(mocked_syslog.LOG_INFO, "file size check pass: {} size is (2139) bytes".format(hostcfgd.ETC_PAMD_SSHD)),
                mock.call(mocked_syslog.LOG_INFO, "file size check pass: {} size is (4951) bytes".format(hostcfgd.ETC_PAMD_LOGIN)),
                mock.call(mocked_syslog.LOG_INFO, "Found audisp-tacplus PID: "),
                mock.call(mocked_syslog.LOG_INFO, "cmd - ['service', 'aaastatsd', 'stop']"),
                mock.call(mocked_syslog.LOG_ERR, "['service', 'aaastatsd', 'stop'] - failed: return code - 1, output:\nNone"),
                mock.call(mocked_syslog.LOG_INFO, "AAA Update: key: DEL, op: DEL, data: {}")
            ]
            for expected_call in expected:
                assert expected_call in mocked_syslog.mock_calls, f"Expected call {expected_call} not found"
<<<<<<< HEAD
=======

    @parameterized.expand(HOSTCFGD_TEST_TACACS_VECTOR)
    def test_hostcfgd_aaa_debug_cleared_on_delete(self, test_name, test_data):
        """
            Removing the debug field or deleting AAA|authentication turns debug off
            in the rendered TACACS+ config
        """
        config_name = "config_db_local"
        op_path = output_path + "/" + test_name + "_" + config_name
        sop_path = sample_output_path + "/" +  test_name + "_" + config_name
        host_config_daemon = self.mock_hostcfgd(test_data, config_name, op_path, sop_path)
        host_config_daemon.register_callbacks()
        aaa_callback = host_config_daemon.config_db.handlers['AAA']

        def nss_debug_on():
            with open(hostcfgd.NSS_TACPLUS_CONF) as f:
                return "debug=on" in f.read().splitlines()

        aaa_callback('AAA', 'authentication', {'login': 'tacacs+,local', 'debug': 'true'})
        self.assertTrue(nss_debug_on())

        aaa_callback('AAA', 'authentication', {'login': 'tacacs+,local'})
        self.assertFalse(nss_debug_on())

        aaa_callback('AAA', 'authentication', {'login': 'tacacs+,local', 'debug': 'true'})
        self.assertTrue(nss_debug_on())

        aaa_callback('AAA', 'authentication', None)
        self.assertFalse(nss_debug_on())

    @parameterized.expand(HOSTCFGD_TEST_TACACS_VECTOR)
    def test_hostcfgd_tacacs_server_yang_defaults(self, test_name, test_data):
        """
            A server row without tcp_port or priority, as a client that writes
            only the fields it sets leaves it, renders with their YANG defaults,
            and a global timeout still wins over the server's own default
        """
        config_name = "config_db_local"
        op_path = output_path + "/" + test_name + "_" + config_name
        sop_path = sample_output_path + "/" +  test_name + "_" + config_name
        host_config_daemon = self.mock_hostcfgd(test_data, config_name, op_path, sop_path)
        host_config_daemon.register_callbacks()
        aaa_callback = host_config_daemon.config_db.handlers['AAA']
        global_callback = host_config_daemon.config_db.handlers['TACPLUS']
        server_callback = host_config_daemon.config_db.handlers['TACPLUS_SERVER']

        aaa_callback('AAA', 'authentication', {'login': 'tacacs+,local'})
        global_callback('TACPLUS', 'global', {'passkey': 'dellsonic', 'timeout': '3'})
        server_callback('TACPLUS_SERVER', '10.10.49.39', {'vrf': 'default'})

        with open(hostcfgd.NSS_TACPLUS_CONF) as f:
            self.assertIn("server=10.10.49.39:49,secret=dellsonic,timeout=3,vrf=default", f.read().splitlines())
        with open(hostcfgd.PAM_AUTH_CONF) as f:
            self.assertIn("server=10.10.49.39:49 secret=dellsonic login=pap timeout=3 ", f.read())

    @parameterized.expand(HOSTCFGD_TEST_TACACS_VECTOR)
    def test_hostcfgd_tacacs_server_without_fields(self, test_name, test_data):
        """
            A server row with no fields, at startup or added later, renders on its
            YANG defaults, and only deleting the row removes it
        """
        config_name = "config_db_local"
        op_path = output_path + "/" + test_name + "_" + config_name
        sop_path = sample_output_path + "/" +  test_name + "_" + config_name
        host_config_daemon = self.mock_hostcfgd(test_data, config_name, op_path, sop_path)
        aaa = {'authentication': {'login': 'tacacs+,local'}}
        tacacs_global = {'global': {'passkey': 'dellsonic'}}
        host_config_daemon.aaacfg.load(aaa, tacacs_global, {'10.10.49.40': {}}, {}, {}, {}, {})
        host_config_daemon.register_callbacks()
        server_callback = host_config_daemon.config_db.handlers['TACPLUS_SERVER']

        def nss_servers():
            with open(hostcfgd.NSS_TACPLUS_CONF) as f:
                return [line for line in f.read().splitlines() if line.startswith("server=")]

        self.assertEqual(nss_servers(), ["server=10.10.49.40:49,secret=dellsonic,timeout=5"])

        server_callback('TACPLUS_SERVER', '10.10.49.41', {})
        self.assertEqual(sorted(nss_servers()), ["server=10.10.49.40:49,secret=dellsonic,timeout=5",
                                                 "server=10.10.49.41:49,secret=dellsonic,timeout=5"])

        server_callback('TACPLUS_SERVER', '10.10.49.40', None)
        self.assertEqual(nss_servers(), ["server=10.10.49.41:49,secret=dellsonic,timeout=5"])

    @parameterized.expand(HOSTCFGD_TEST_TACACS_VECTOR)
    def test_hostcfgd_tacacs_server_yang_default_under_global(self, test_name, test_data):
        """
            A server's own YANG default applies until the global row sets that
            field, whatever the global table's YANG default is
        """
        class Provider(MockDefaultValueProvider):
            DEFAULTS = dict(MockDefaultValueProvider.DEFAULTS,
                            TACPLUS_SERVER=dict(MockDefaultValueProvider.DEFAULTS['TACPLUS_SERVER'], timeout='7'))

        config_name = "config_db_local"
        op_path = output_path + "/" + test_name + "_" + config_name
        sop_path = sample_output_path + "/" +  test_name + "_" + config_name
        with mock.patch.object(swsscommon, 'DefaultValueProvider', Provider):
            host_config_daemon = self.mock_hostcfgd(test_data, config_name, op_path, sop_path)
        host_config_daemon.register_callbacks()
        aaa_callback = host_config_daemon.config_db.handlers['AAA']
        global_callback = host_config_daemon.config_db.handlers['TACPLUS']
        server_callback = host_config_daemon.config_db.handlers['TACPLUS_SERVER']

        def nss_servers():
            with open(hostcfgd.NSS_TACPLUS_CONF) as f:
                return [line for line in f.read().splitlines() if line.startswith("server=")]

        aaa_callback('AAA', 'authentication', {'login': 'tacacs+,local'})
        global_callback('TACPLUS', 'global', {'passkey': 'dellsonic'})
        server_callback('TACPLUS_SERVER', '10.10.49.44', {})
        self.assertEqual(nss_servers(), ["server=10.10.49.44:49,secret=dellsonic,timeout=7"])

        global_callback('TACPLUS', 'global', {'passkey': 'dellsonic', 'timeout': '3'})
        self.assertEqual(nss_servers(), ["server=10.10.49.44:49,secret=dellsonic,timeout=3"])

    @parameterized.expand(HOSTCFGD_TEST_TACACS_VECTOR)
    def test_hostcfgd_tacacs_yang_defaults_unavailable(self, test_name, test_data):
        """
            When the YANG defaults cannot be read, or swsscommon has no
            DefaultValueProvider, the error is logged once, the read is not
            retried, and each server renders on the built-in defaults
        """
        config_name = "config_db_local"
        op_path = output_path + "/" + test_name + "_" + config_name
        sop_path = sample_output_path + "/" +  test_name + "_" + config_name
        providers = {
            'raises': mock.Mock(getDefaultValues=mock.Mock(
                side_effect=RuntimeError("Open Yang model path /usr/local/yang-models failed"))),
            'raises_other': mock.Mock(getDefaultValues=mock.Mock(side_effect=SystemError("Unknown exception"))),
            'empty': mock.Mock(getDefaultValues=mock.Mock(return_value={})),
            'missing': None,
        }
        for name, provider in providers.items():
            with self.subTest(provider=name):
                original_syslog = hostcfgd.syslog
                with mock.patch('hostcfgd.syslog.syslog') as mocked_syslog, \
                     mock.patch.object(swsscommon, 'DefaultValueProvider') as provider_class:
                    mocked_syslog.LOG_INFO = original_syslog.LOG_INFO
                    mocked_syslog.LOG_ERR = original_syslog.LOG_ERR
                    if provider is None:
                        del swsscommon.DefaultValueProvider
                    else:
                        provider_class.return_value = provider
                    host_config_daemon = self.mock_hostcfgd(test_data, config_name, op_path, sop_path)
                    host_config_daemon.register_callbacks()
                    aaa_callback = host_config_daemon.config_db.handlers['AAA']
                    global_callback = host_config_daemon.config_db.handlers['TACPLUS']
                    server_callback = host_config_daemon.config_db.handlers['TACPLUS_SERVER']

                    aaa_callback('AAA', 'authentication', {'login': 'tacacs+,local'})
                    global_callback('TACPLUS', 'global', {'passkey': 'dellsonic'})
                    server_callback('TACPLUS_SERVER', '10.10.49.42', {'vrf': 'default'})
                    server_callback('TACPLUS_SERVER', '10.10.49.43',
                                    {'priority': '2', 'tcp_port': '49', 'timeout': '5', 'vrf': 'default'})

                    errors = [c for c in mocked_syslog.mock_calls
                              if c.args and c.args[0] == original_syslog.LOG_ERR and "TACACS+" in c.args[1]]
                    self.assertEqual(len(errors), 1)
                if provider is not None:
                    provider.getDefaultValues.assert_called_once()

                with open(hostcfgd.NSS_TACPLUS_CONF) as f:
                    nss_servers = [line for line in f.read().splitlines() if line.startswith("server=")]
                self.assertEqual(nss_servers, ["server=10.10.49.43:49,secret=dellsonic,timeout=5,vrf=default",
                                               "server=10.10.49.42:49,secret=dellsonic,timeout=5,vrf=default"])
                with open(hostcfgd.PAM_AUTH_CONF) as f:
                    pam_servers = [line.split("pam_tacplus.so ")[1] for line in f.read().splitlines()
                                   if "pam_tacplus.so " in line]
                self.assertEqual(pam_servers,
                                 ["server=10.10.49.43:49 secret=dellsonic login=pap timeout=5  vrf=default   try_first_pass",
                                  "server=10.10.49.42:49 secret=dellsonic login=pap timeout=5  vrf=default   try_first_pass"])
>>>>>>> d09d571 (NOS-20736: [hostcfgd] Take a TACACS+ server's defaults from its YANG model (#282))
