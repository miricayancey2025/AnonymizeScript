import unittest
import re


from regex_test import findCondorUserIDs, findEmail, cleanCondor, cleanGlidein
IP_REGEX = ["(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)", "(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|^::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$|^[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$|^[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){0,2}[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,3}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){0,3}[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,2}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:)?[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}::[0-9a-fA-F]{1,4}$|(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}::"]

class TestFilter(unittest.TestCase):
    #def test_filter_init(self):

    def test_glidein(self): #Glidein Logs
        file1 = "regular_logs/overall_test_in.txt"
        cleanGlidein(file1)
        line = (open(file1)).read()
        self.assertNotRegex(line, IP_REGEX[0])
        self.assertNotRegex(line, IP_REGEX[1])
        
        #need to check that the glidein user ids are gone


    """ def test_condor(self):
        file2 = "condor_logs/job.1.StartdLog.txt"
        
        user_ids2 = findCondorUserIDs(file2)
        email = findEmail(file2)
        cleanCondor(file2)
        
        f_in = (open(file2)).read()
        
        self.assertFalse(f_in.find(email) != -1) """
        
    """  for x in range(0, len(user_ids2)):
            self.assertFalse(f_in.find(user_ids2[x])) """

   

if __name__ == '__main__':
    unittest.main()