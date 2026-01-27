import sys
import unittest


sys.modules['fm_core'] = unittest.mock.Mock()
