import re, mmap, argparse, os, logging

IPV4 = "XX.XX.XX.XX"
IPV6 ="XXXX:XXXX:XXXX:XXXX::"
USER = "USER"
CONDORS = ["MasterLog", "StartdLog", "StarterLog", "StartdHistory"]
IP_REGEX = ["(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)", "(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|^::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$|^[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$|^[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){0,2}[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,3}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){0,3}[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,2}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:)?[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}::[0-9a-fA-F]{1,4}$|(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}::"]



#Would like to find a way to combine findglideinuser and findcondoruser
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

def findGlideinUserIDs(filename):
    cns = []
    with open(filename,'r', encoding="utf8") as f_in:
        line = f_in.read()
        cn_regex = 'CN.*(")'
        if re.search(cn_regex, line, flags=re.MULTILINE):
            idx = re.search('CN', line).start()
            end = line.find('"',idx)
            line = line[idx:end]
            cns.append(line)
    cns = ("".join(cns)).split("CN=")
    cns = ("".join(cns)).split("CN\\=")
    cns = (" ".join(cns)).split(" ")
    return cns

def findEmail(filename): #CONDOR SPECIFIC finds and returns user email (before @symbol)
    lis = ''
    with open(filename, 'rb', 0) as file, \
        mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as s:
        if s.find(b'x509UserProxyEmail') != -1:
            x = s.find(b'x509UserProxyEmail')
            end = s.find(b'@',x)
            lis = (((s[x: end].split(b'='))[1].decode("utf-8")).replace('"', '')).replace(' ', '')   
    return lis
            
def cleanCondorUser(filename,email,userinfo): #removes email & user data (name, email) from a file
   newdata = ""
   with open(filename,'r', encoding="utf8") as f:
        filedata = f.read()
        if email and userinfo:  #both
            newdata = filedata.replace(email, USER)
            for x in range(0, len(userinfo)):
                newdata = newdata.replace(userinfo[x], USER)
    
        elif email and not userinfo: #not userids
            newdata = filedata.replace(email, USER)
            
        elif userinfo and not email: #not email
            newdata = filedata.replace(userinfo[0], USER)
            for x in range(1, len(userinfo)):
                newdata = newdata.replace(userinfo[x], USER)

        elif not email and not userinfo: #not either
            newdata = ""
            
        return newdata

def cleanGlideinUser(filename, recog): #removes all instance of user
   with open(filename,'r', encoding="utf8") as f:
        filedata = f.read()
        newdata = filedata.replace(recog[0], USER)
        for x in range(1, len(recog)):
            newdata = newdata.replace(recog[x], USER)
            newdata = newdata.replace(recog[x], USER)
        newdata = re.sub(rf"{recog[0]}[\w \W]{recog[1]}", USER ,newdata, flags=re.I + re.M)
        return newdata

def replaceIP(filename):
    newdata = ""
    with open(filename,"r", encoding="utf8") as f_in:
        outlines = f_in.read()
        newdata = re.sub(IP_REGEX[0], IPV4, outlines)
        newdata = re.sub(IP_REGEX[1], IPV6, newdata)
        return newdata

def overwrite(filename, data):
    with open(filename,'w', encoding="utf8") as f_out:
        f_out.seek(0)
        f_out.write(data)
        f_out.truncate()

def cleanGlidein(file1):
    user_ids = findGlideinUserIDs(file1)
    data = cleanGlideinUser(file1, user_ids)
    overwrite(file1, data)
    clean_data = replaceIP(file1)
    overwrite(file1, clean_data)
      
def cleanCondor(file2):
    user_ids2 = findCondorUserIDs(file2)
    email = findEmail(file2)
    co_data = cleanCondorUser(file2,email,user_ids2)
    if co_data != "":
        overwrite(file2, co_data)
    clean_data = replaceIP(file2)
    overwrite(file2, clean_data)

def condorFile(file_name):
    for i in range(0, len(CONDORS)):
        if CONDORS[i] in file_name:
            return True
    return False
        
def cleanLogs():
    # parser = argparse.ArgumentParser(description="GlideinMonitor's Filtering")     # Parse command line arguments
    # parser.add_argument('-i', help="Input Directory", required=True)
    # parser.add_argument('-o', help="Output Directory", required=True)
    # args = parser.parse_args()
    # input_directory = args.i
    # output_directory = args.o

    # In practice, use a loop until no files have been found in the input directory for better performance
    # input_directory_files = [
    #     file 
    #     for file in os.listdir(input_directory) 
      
    #     if os.path.isfile(
    #         os.path.join(input_directory, file)
    #         )
    #     ]
    
    #input_directory_files = []
    input_directory = "input_dir"
    output_directory = "output_dir"
    
    # while True:
    #     for file in os.listdir(input_directory):
    #         if os.path.isfile(os.path.join(input_directory, file)):
    #             input_directory_files.append(file)
    #         else:
    #             False
    
    input_directory_files = [
        file 
        for file in os.listdir(input_directory) 
      
        if os.path.isfile(
            os.path.join(input_directory, file)
            )
        ]

    for file_name in input_directory_files:  
        #with open(os.path.join(input_directory, file_name), 'r') as input_file_handle:
            #input_file_contents = input_file_handle.read()
        path = os.path.join(input_directory, file_name)
        #print(path)
        #f_in = open(path, "r")
        if os.path.splitext(file_name)[1] == '.out' or os.path.splitext(file_name)[1] == '.err' : 
            print("Cleaning Glidein!")
            #cleanGlidein(path)
        # elif condorFile(file_name) == True: 
        else:
            print("Cleaning Condor!")
            cleanCondor(path)
            
        out_path = os.path.join(output_directory, file_name)
        
        
        
        
        f_in = open(path, "r")
        with open(out_path, 'w') as file:
            output_file_contents = f_in.read()
            f_in.close()
            file.write(output_file_contents)
            print("Wrote to outfile!")

        # os.remove(os.path.join(input_directory, file_name)) 
        # print("Removed Old File!")

if __name__ == "__main__":
    cleanLogs()
    # cleanGlidein("regular_logs/overall_test_in.txt")
    # logger = logging.getLogger(__name__)
    # # Create handlers
    # c_handler = logging.StreamHandler()
    # f_handler = logging.FileHandler('file.log')
    # c_handler.setLevel(logging.WARNING)
    # f_handler.setLevel(logging.ERROR)

    # # Create formatters and add it to handlers
    # c_format = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
    # f_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    # c_handler.setFormatter(c_format)
    # f_handler.setFormatter(f_format)

    # # Add handlers to the logger
    # logger.addHandler(c_handler)
    # logger.addHandler(f_handler)
    # logging.info(cleanGlidein("regular_logs/overall_test_in.txt"))
    
    #-h option to print option of how to work this page
    #documentation
