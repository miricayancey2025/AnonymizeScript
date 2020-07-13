import unittest
import re


from regex_test import cleanCondor, cleanGlidein, findCondorUserIDs, findEmail, findGlideinUserIDs
IP_REGEX = ["(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)", "(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|^::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$|^[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$|^[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){0,2}[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,3}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){0,3}[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,2}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:)?[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}::[0-9a-fA-F]{1,4}$|(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}::"]

class TestFilter(unittest.TestCase):
    # def test_filter_init(self):

    def test_glidein(self): #Glidein Logs
        file1 = "regular_logs/overall_test_in.txt"
        user_ids2 = findGlideinUserIDs(file1)
        cleanGlidein(file1)
        file = open(file1, "r", encoding="utf8")
        line = file.read()
        file.close()
        
        self.assertNotRegex(line, IP_REGEX[0])
        self.assertNotRegex(line, IP_REGEX[1])
        self.assertNotRegex(line, rf"{user_ids2[0]}[\w \W]{user_ids2[1]}")
        for x in range(0, len(user_ids2)):
            self.assertFalse(line.find(user_ids2[x]) != -1)
 
        

    def test_condor(self):
        file2 = "condor_logs/ip.txt"
        user_ids2 = findCondorUserIDs(file2)
        email = findEmail(file2)
        cleanCondor(file2)
        file = open(file2)
        line = file.read()
        file.close()
        
        self.assertFalse(line.find(email) != -1)
        self.assertNotRegex(line, IP_REGEX[0])
        self.assertNotRegex(line, IP_REGEX[1])
        for x in range(0, len(user_ids2)):
            self.assertFalse(line.find(user_ids2[x]) != -1)
 

if __name__ == '__main__':
    unittest.main()