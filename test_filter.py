import unittest
import re


from regex_test import cleanCondor, cleanCondorUser, cleanGlidein, findCondorUserIDs, findEmail, findGlideinUserIDs, replaceIP
IP_REGEX = ["(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)", "(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|^::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$|^[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$|^[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){0,2}[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,3}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){0,3}[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,2}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:)?[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}::[0-9a-fA-F]{1,4}$|(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}::"]

class TestFilter(unittest.TestCase):
    # def test_filter_init(self):

    # def test_glidein(self): #Glidein Logs
    #     file1 = "regular_logs/overall_test_in.txt"
    #     user_ids2 = findGlideinUserIDs(file1)
    #     cleanGlidein(file1)
    #     file = open(file1, "r", encoding="utf8")
    #     line = file.read()
    #     file.close()
        
    #     self.assertNotRegex(line, IP_REGEX[0])
    #     self.assertNotRegex(line, IP_REGEX[1])
    #     self.assertNotRegex(line, rf"{user_ids2[0]}[\w \W]{user_ids2[1]}")
    #     for x in range(0, len(user_ids2)):
    #         self.assertFalse(line.find(user_ids2[x]) != -1)
 
        

    def test_condor(self):
        master = "condor_logs/job.1.MasterLog.txt"
        history = "condor_logs/job.1.StartdHistoryLog.txt"
        # starter = "condor_logs/job.1.StarterLog.txt"
        # startd = "condor_logs/job.1.StartdLog.txt"
        eu = "condor_logs/testingEU.txt"
        m_ids = findCondorUserIDs(master)
        h_ids = findCondorUserIDs(history)
        # sr_ids = findCondorUserIDs(starter)
        # s_ids = findCondorUserIDs(startd)
        eu_ids = findCondorUserIDs(eu)
        m_email = findEmail(master)
        h_email = findEmail(history)
        # sr_email = findEmail(starter)
        # s_email = findEmail(startd)
        eu_email = findEmail(eu)
        m_ip = replaceIP(master)
        h_ip = replaceIP(history)
        # sr_ip = replaceIP(starter)
        # s_ip = replaceIP(startd)
        eu_ip = replaceIP(eu)
        m_data= cleanCondorUser(master, m_email, m_ids)
        h_data= cleanCondorUser(history, h_email, h_ids)
        # sr_data= cleanCondorUser(starter, sr_email, sr_ids)
        # s_data = cleanCondorUser(startd, s_email, s_ids)
        #print(m_ip)
        print(h_email, h_ids)
        print()
        print(m_email, m_ids)
        print()
        print(eu_email, eu_ids)
        # print(h_data)
        # user_ids2 = findCondorUserIDs(file2)
        # email = findEmail(file2)
        #print(h_data)
        cleanCondor(history)
        cleanCondor(master)
        cleanCondor(eu)
        file = open(history)
        line = file.read()
        file.close()
        
        m_file = open(master)
        m_line= m_file.read()
        m_file.close()
        
        eu_file = open(eu)
        eu_line= eu_file.read()
        eu_file.close()
        #print(sr_data)
        
        self.assertFalse(line.find(h_email) != -1)
        self.assertNotRegex(line, IP_REGEX[0])
        self.assertNotRegex(line, IP_REGEX[1])
        for x in range(0, len(h_ids)):
            self.assertFalse(line.find(h_ids[x]) != -1)
            
        #self.assertFalse(m_line.find(m_email) != -1)
        self.assertNotRegex(m_line, IP_REGEX[0])
        self.assertNotRegex(m_line, IP_REGEX[1])
        # for x in range(0, len(m_ids)):
        #     self.assertFalse(m_line.find(m_ids[x]) != -1)
        
        #self.assertFalse(eu_line.find(eu_email) != -1)
        self.assertNotRegex(eu_line, IP_REGEX[0])
        self.assertNotRegex(eu_line, IP_REGEX[1])
        for x in range(0, len(eu_ids)):
            self.assertFalse(eu_line.find(eu_ids[x]) != -1)
        
 

if __name__ == '__main__':
    unittest.main()