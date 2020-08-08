import re, mmap, argparse, os, logging
IPV4 = "XX.XX.XX.XX"
IPV6 ="XXXX:XXXX:XXXX:XXXX::"
USER = "USER"
CONDORS = ["MasterLog", "StartdLog", "StarterLog", "StartdHistory"]
IP_REGEX = ["(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)", "(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|^::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$|^[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$|^[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){0,2}[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,3}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){0,3}[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,2}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:)?[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}::[0-9a-fA-F]{1,4}$|(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}::"]

def findEmail(filename):
    """finds the user's email in a condor file type

    Args:
        filename (str): path of the file

    Returns:
        str: user's email
    """
    lis = ''
    with open(filename, 'rb', 0) as file, \
        mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as s:
        if s.find(b'x509UserProxyEmail') != -1:
            x = s.find(b'x509UserProxyEmail')
            end = s.find(b'@',x)
            lis = (((s[x: end].split(b'='))[1].decode("utf-8")).replace('"', '')).replace(' ', '')   
    return lis
  
def findUserIds(filename):
    """finds the user's identifiers in a condor file type

    Args:
        filename (str): path of the file

    Returns:
        array: list of user identifiers
    """
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
      
def findCondorIP(filename):
    """finds the user's ip address in a condor type file

    Args:
        filename (str): path of the file

    Returns:
        str: user's ip address
    """
    lis = ''
    with open(filename, 'rb', 0) as file, \
        mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as s:
        if s.find(b'MyAddress = "') != -1:
            x = s.find(b'MyAddress = "')
            end = s.find(b'?',x)
            lis = s[x: end].decode("utf-8")
            lis = lis.split(':')
            lis.pop()
            lis = ":".join(lis)
            lis = lis.split('<')
            lis.pop(0)
    return lis  

def cleanCondor(filename,email,userinfo, ipaddress):
    """Filters information from condor file type

    Args:
        filename (str): path of file
        email (str): user's email
        userinfo (array): array of user identifiers
        ipaddress (array): array of user ip addresses
    """
    newdata = ""
    with open(filename,'r', encoding="utf8") as f:
        filedata = f.read()
        if ipaddress and email and userinfo:
            newdata = filedata.replace(email, USER)
            newdata= newdata.replace(ipaddress[0], IPV4)
            for x in range(0, len(userinfo)):
                newdata = newdata.replace(userinfo[x], USER)
            overwrite(filename, newdata)
        

def replaceAllIP(filename):
    """replaces the ip addresses in a file

    Args:
        filename (str): path of the file

    Returns:
        str: new filtered file data
    """
    newdata = ""
    with open(filename,"r", encoding="utf8") as f_in:
        outlines = f_in.read()
        newdata = re.sub(IP_REGEX[0], IPV4, outlines)
        newdata = re.sub(IP_REGEX[1], IPV6, newdata)
        return newdata

def overwrite(filename, data):
    """Overwrites file with new data

    Args:
        filename (str): path of the file
        data (str): new file data
    """
    with open(filename,'w', encoding="utf8") as f_out:
        f_out.seek(0)
        f_out.write(data)
        f_out.truncate()
    
def condorFile(filename):
    """Determines if file type is a condor file

    Args:
        filename (str): path of the file

    Returns:
        boolean: if file is condor or not
    """
    for i in range(0, len(CONDORS)):
        if CONDORS[i] in filename:
            return True
    return False
        
def cleanLogs():
    """Filters GlideinMonitor files of type Condor and Glidein and saves them to an output directory
    """
    parser = argparse.ArgumentParser(description="GlideinMonitor's Filtering")     # Parse command line arguments
    parser.add_argument('-i', help="Input Directory", required=True)
    parser.add_argument('-o', help="Output Directory", required=True)
    args = parser.parse_args()
    input_directory = args.i
    output_directory = args.o
    # input_directory = "input_dir"
    # output_directory = "output_dir"
    
    input_directory_files = [file for file in os.listdir(input_directory)
                         if os.path.isfile(os.path.join(input_directory, file))]

    for filename in input_directory_files:  
        path = os.path.join(input_directory, filename)
        if os.path.splitext(filename)[1] == '.out' or os.path.splitext(filename)[1] == '.err' : 
            print("Cleaning Glidein!")
            clean_data = replaceAllIP(filename)
            overwrite(filename, clean_data)
            
        elif condorFile(filename) == True: 
            print("Cleaning Condor!")
            cleanCondor(path)
            
        out_path = os.path.join(output_directory, filename)
        
        f_in = open(path, "r")
        with open(out_path, 'w') as file:
            output_file_contents = f_in.read()
            f_in.close()
            file.write(output_file_contents)
            print("Wrote to outfile!")

        os.remove(os.path.join(input_directory, filename)) 
        print("Removed Old File!")

if __name__ == "__main__":
    cleanLogs()