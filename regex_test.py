import re, mmap, argparse, os, logging
IPV4 = "XX.XX.XX.XX"
IPV6 ="XXXX:XXXX:XXXX:XXXX::"
USER = "USER"
CONDORS = ["MasterLog", "StartdLog", "StarterLog", "StartdHistory"]
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
  
def findUserIds(filename): #CONDOR SPECIFIC finds and returns user email (before @symbol)
    lis = ''
    with open(filename, 'rb', 0) as file, \
        mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as s:
        if s.find(b'x509UserProxyFQAN = "') != -1:
            x = s.find(b'x509UserProxyFQAN = "')
            end = s.find(b'Role=',x)
            lis = s[x: end].decode("utf-8")#
            lis = lis.split('CN=')
            lis.pop(0)
            lis = " ".join(lis).replace("/","").replace(",cms","").split(' ')
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
    clean_data = replaceIP(file1)
    overwrite(file1, clean_data)
      
def cleanCondor(file2):
    user_ids2 = findUserIds(file2)
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

    input_directory = "input_dir"
    output_directory = "output_dir"

    # In practice, use a loop until no files have been found in the input directory for better performance
    input_directory_files = [file for file in os.listdir(input_directory) if os.path.isfile(os.path.join(input_directory, file))]

    for file_name in input_directory_files:  
        path = os.path.join(input_directory, file_name)
        if os.path.splitext(file_name)[1] == '.out' or os.path.splitext(file_name)[1] == '.err' : 
            print("Cleaning Glidein!")
            cleanGlidein(path)
        elif condorFile(file_name) == True: 
            print("Cleaning Condor!")
            cleanCondor(path)
            
        out_path = os.path.join(output_directory, file_name)
        
        f_in = open(path, "r")
        with open(out_path, 'w') as file:
            output_file_contents = f_in.read()
            f_in.close()
            file.write(output_file_contents)
            print("Wrote to outfile!")

        os.remove(os.path.join(input_directory, file_name)) 
        print("Removed Old File!")

if __name__ == "__main__":
    cleanLogs()