import unittest

from regex_test import removeIP

class TestSum(unittest.TestCase):
    def test_filter_init(self):
        stringo = "yoink 17.172.224.47 yoink yoink yoink"
        result = removeIP(stringo)
        print(result)
        self.assertIn("XX.XX.XX.XX", result)
        

if __name__ == '__main__':
    unittest.main()