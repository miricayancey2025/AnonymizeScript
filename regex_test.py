#Improvements - delete original file so there is no chance or reversal
#Weakness - ex. 444.76.9.23 - leaves off beginning 4 as it's not accepted and decides that the Ip is 44.76.9.23 meaning it can mistake othe number sequences for IP
#Weakness - Does not account for if an IP of type 4 is on the same line as an IP of type 6
#Testing Succesfull against short glidein outfile

"""Regex Breakdown of Ipv4 + Ipv6 + CN User
    
    Regex Breakdown for Ipv4
    (?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)
    
    #Checks if numbers are between 0 and 225 (25[0-5]) or any other 200 val (2[0-4][0-9]) or any over 100 val or less ([01]?[0-9][0-9])
    Checks for three words following a period and then once without

    (?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}
    Source: https://riptutorial.com/regex/example/14146/match-an-ip-address
    
    
    Regex Breakdown for Ipv6
    (?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|^::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$|^[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$|^[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){0,2}[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,3}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){0,3}[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,2}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:)?[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}::[0-9a-fA-F]{1,4}$|(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}::
   
    #Check for seven words (w/ four places each with a variety of nums + letters) following a colon (?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|^::(?:[0-9a-fA-F]{1,4}:
    #Zeros are replaced with ::
    #Checks many different forms of Ipv6
    Source: https://riptutorial.com/regex/example/14146/match-an-ip-address
    
    Regex Breakdown for CN User Info
    CN.*(")
    
    #Check if line contains CN
    #After that, anything can come after CN but it must end with a "
    
"""
"""To Do
1. Try Catch Loop with file to see if it exists
2. Fix Weaknesses 
3. Delete Original File
4. Add MAC to our IP_Address lists + function
"""

import re
import mmap
import argparse
import os

#Replace Terms
IPV4 = "XX.XX.XX.XX"
IPV6 ="XXXX:XXXX:XXXX:XXXX::"
USER = "USER"
IP_REGEX = ["(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)", "(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|^::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$|^[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$|^[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){0,2}[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,3}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){0,3}[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,2}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:)?[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}::[0-9a-fA-F]{1,4}$|(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}::"]

    
def findEmail(filename): #CONDOR SPECIFIC finds and returns user email (before @symbol)
    lis = ''
    with open(filename, 'rb', 0) as file, \
        mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as s:
        if s.find(b'x509UserProxyEmail') != -1:
            x = s.find(b'x509UserProxyEmail')
            end = s.find(b'@',x)
            lis = (((s[x: end].split(b'='))[1].decode("utf-8")).replace('"', '')).replace(' ', '')   
    return lis
            
def findCondorUserIDs(filename): #finds and returns the CN user identifiers
    lis = []
    with open(filename, 'rb', 0) as file, \
        mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as s:
        if s.find(b'CN=') != -1: #Starts at CN= and goes until a " then that byte is decoded, any commas, equal signs etc are replaced
            x = s.find(b'CN=')
            end = s.find(b'"',x)
            lis = ((s[x: end]).decode("utf-8").replace(',', '')).split('=')
            lis = ('/'.join(lis)).split('/')
            lis_new = []
            for i in range(0, len(lis)):
                if lis[i] == "CN":
                    lis_new.append(lis[i+1])       
            lis = lis_new
    return lis

#regex version of condor remove data
#Negatives: reads line by line. Bad if the process is stopped halfway through
def findGlideinUserIDs(filename): #Greedy CN Replacer
    cns = []
    f_in = open(filename, "r")
    outlines = f_in.readlines()
    f_in.close()
    cn_regex = 'CN.*(")'
    for line in outlines: #using search instead of find all means there cannot be more than one instance in a line
      if re.search(cn_regex, line, flags=re.MULTILINE):
        idx = re.search('CN', line).start()
        end = line.find('"',idx)
        line = line[idx:end]
        cns.append(line)
        
    #might become a long process with longer files
    cns = ("".join(cns)).split("CN=")
    cns = ("".join(cns)).split("CN\\=")
    cns = (" ".join(cns)).split(" ")    
    return cns
  
def cleanCondor(filename,email,userinfo, USER): #removes email 6 user data (name, email) from a file
    f = open(filename,'r')
    filedata = f.read()
    f.close()
    newdata = filedata.replace(email, USER)
    for x in range(0, len(userinfo)):
        newdata = newdata.replace(userinfo[x], USER)
    return newdata

def cleanGlidein(filename, recog, replacement):
    f = open(filename,'r')
    filedata = f.read()
    f.close()
    newdata = filedata.replace(recog[0], USER)
    for x in range(1, len(recog)):
        newdata = newdata.replace(recog[x], USER)
        newdata = newdata.replace(recog[x], USER)
    return newdata
    

###########################################################################################################
#Problematic if interupted half way through because of the line for line read
def replaceIP(filename):
    f_in = open(filename,"r")
    f_out = open("ip_out.txt", "w")
    outlines = f_in.readlines()
    #multi line tag helps it catch ip addresses spanning multi lines
    #[scans file one line at a time, finds all instances of line match, substitutes and writes new file, otherwise no match just writes line]
    for line in outlines:
        if re.search("(\^?\\?\/DC[\\=]=?\w{0,10}){2}([\s/.\d\w\\/=/@/$]+)", line, flags=re.MULTILINE):
            #super specific list indexes for now
            if re.findall(IP_REGEX[0], line, flags=re.MULTILINE):
                new_line = re.sub(IP_REGEX[0], IPV4, line, flags=re.MULTILINE)
                f_out.write(new_line)
            elif re.findall(IP_REGEX[1], line, flags=re.MULTILINE):
                new_line = re.sub(IP_REGEX[1], IPV6, line, flags=re.MULTILINE)
                newdata = newdata + new_line
                f_out.write(new_line)  
            else:
                f_out.write(line)  
        else:
            f_out.write(line)  
    f_in.close()
##########################################################################################################


def cleanLogs():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="GlideinMonitor's Filtering")
    parser.add_argument('-i', help="Input Directory", required=True)
    parser.add_argument('-o', help="Output Directory", required=True)
    args = parser.parse_args()

    input_directory = args.i
    output_directory = args.o

#####################################################################################################################
    # In practice, use a loop until no files have been found in the input directory for better performance
    input_directory_files = [file
                            for file in os.listdir(input_directory)
                            if os.path.isfile(os.path.join(input_directory, file))]
######################################################################################################################

    # Iterate through each file in the input directory
    for file_name in input_directory_files:
        # Read in the file from the input directory
        with open(os.path.join(input_directory, file_name), 'r') as input_file_handle:
            input_file_contents = input_file_handle.read()

        # Replace the target stand in for actual code finding out if condor
        if os.path.splitext(file_name)[1] == '.out' or os.path.splitext(file_name)[1] == '.err' :
            ids = findGlideinUserIDs(input_file_handle)
            output_file_contents = cleanGlidein(input_file_handle, ids)
            output_file_contents = replaceIP(input_file_handle) #won't work for now
        else:
            ids = findCondorUserIDs(input_file_handle)
            email = findEmail(input_file_handle)
            output_file_contents = cleanCondor(input_file_handle, email, ids)

        # Write the file to the output directory
        with open(os.path.join(output_directory, file_name), 'w') as file:
            file.write(output_file_contents)

        # Delete the file from the input directory
        os.remove(os.path.join(input_directory, file_name))
    
if __name__ == "__main__":
    
    #cleanLogs()
    
    #Condor Logs
    file2 = "condor_logs/job.1.StartdLog.txt"
    user_ids2 = findCondorUserIDs(file2)
    print("Condor Log", user_ids2)
    
    
    #Glidein Logs
    file1 = "regular_logs/test_ip.txt"
    user_ids = findGlideinUserIDs(file1)
    print("Glidein Log" ,user_ids)
    data = cleanGlidein(file1, user_ids, USER)
    f_out = open("regular_logs/overall_test_out.txt", "w")
    f_out.write(data)
    f_out.close()
    replaceIP("regular_logs/overall_test_out.txt")
