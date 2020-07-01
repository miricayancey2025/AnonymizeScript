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
  
def cleanCondorInfo(filename,email,userinfo): #removes email 6 user data (name, email) from a file
    f = open(filename,'r')
    filedata = f.read()
    f.close()
    newdata = filedata.replace(email, USER)
    for x in range(0, len(userinfo)):
        newdata = newdata.replace(userinfo[x], USER)
    return newdata

def cleanGlideinUser(filename, recog):
    f = open(filename,'r')
    filedata = f.read()
    f.close()
    newdata = filedata.replace(recog[0], USER)
    for x in range(1, len(recog)):
        newdata = newdata.replace(recog[x], USER)
        newdata = newdata.replace(recog[x], USER)
        
    return newdata
    

def replaceIP(filename):
    newdata = ""
    f_in = open(filename,"r")
    outlines = f_in.readlines()
    for line in outlines: #super specific list indexes for now
        if re.search(IP_REGEX[0], line, flags=re.MULTILINE) or re.search(IP_REGEX[1], line, flags=re.MULTILINE):
            if re.findall(IP_REGEX[0], line, flags=re.MULTILINE):
                newdata = newdata + re.sub(IP_REGEX[0], IPV4, line, flags=re.MULTILINE)
            elif re.findall(IP_REGEX[1], line, flags=re.MULTILINE):
                newdata = newdata + re.sub(IP_REGEX[1], IPV6, line, flags=re.MULTILINE)
            else:
                newdata = newdata + line
        else:
            newdata = newdata + line
    f_in.close()
    return newdata

def overwrite(filename, data):
    f_out = open(filename, "w")
    f_out.seek(0)
    f_out.write(data)
    f_out.truncate()
    f_out.close()    


def cleanLogs():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="GlideinMonitor's Filtering")
    parser.add_argument('-i', help="Input Directory", required=True)
    parser.add_argument('-o', help="Output Directory", required=True)
    args = parser.parse_args()
    input_directory = args.i
    output_directory = args.o

    # In practice, use a loop until no files have been found in the input directory for better performance
    input_directory_files = [file for file in os.listdir(input_directory) if os.path.isfile(os.path.join(input_directory, file))]

    for file_name in input_directory_files:     # Iterate through each file in the input directory
        with open(os.path.join(input_directory, file_name), 'r') as input_file_handle:         # Read in the file from the input directory
            input_file_contents = input_file_handle.read()

        if os.path.splitext(file_name)[1] == '.out' or os.path.splitext(file_name)[1] == '.err' : #may need overwrite method here
            ids = findGlideinUserIDs(input_file_handle)
            output_file_contents = cleanGlideinUser(input_file_handle, ids)
            output_file_contents = replaceIP(input_file_handle)
        else: #may need overwrite method here
            ids = findCondorUserIDs(input_file_handle)
            email = findEmail(input_file_handle)
            output_file_contents = cleanCondorInfo(input_file_handle, email, ids)

        # Write the file to the output directory
        with open(os.path.join(output_directory, file_name), 'w') as file:
            file.write(output_file_contents)

        os.remove(os.path.join(input_directory, file_name))  # Delete the file from the input directory
        

def cleanGlidein(file1):
    #Glidein Logs
    user_ids = findGlideinUserIDs(file1)
    data = cleanGlideinUser(file1, user_ids)
    overwrite(file1, data)
    clean_data = replaceIP(file1)
    overwrite(file1, clean_data)
      
def cleanCondor(file2):
    user_ids2 = findCondorUserIDs(file2)
    email = findEmail(file2)
    co_data = cleanCondorInfo(file2,email,user_ids2)
    overwrite(file2, co_data)
    
if __name__ == "__main__":
    
    #cleanLogs()

    #Condor Logs
    """ file2 = "condor_logs/job.1.StartdLog.txt"
    user_ids2 = findCondorUserIDs(file2)
    email = findEmail(file2)
    co_data = cleanCondorInfo(file2,email,user_ids2)
    overwrite(file2, co_data) """
    
    #cleanGlidein("regular_logs/overall_test_in.txt")
    
