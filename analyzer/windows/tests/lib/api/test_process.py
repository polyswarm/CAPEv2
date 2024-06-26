import os
import threading
import unittest
from unittest.mock import MagicMock, patch

from lib.api.process import Process


class ProcessTests(unittest.TestCase):
    @patch("lib.api.process.PSAPI", MagicMock(), create=True)
    def test_unknown_image_name(self):
        process = Process()
        assert f"{process}" == "<Process 0 ???>"

    def test_known_image_name(self):
        mock_image_name = MagicMock()
        mock_image_name.return_value = self.id()
        with patch("lib.api.process.Process.get_image_name", mock_image_name):
            process = Process()
            assert f"{process}" == f"<Process 0 {self.id()}>"

    def test_process_self(self):
        _ = Process(pid=os.getpid(), thread_id=threading.get_ident())

    def test_process_fill_system_info(self):
        p = Process()
        p.fill_system_info()
        # arbitrary sysinfo field assertion here
        self.assertNotEqual(0, p.system_info.dwPageSize)
