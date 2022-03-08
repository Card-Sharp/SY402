#!/usr/bin/env python3

import os
import datetime
import hashlib

logFile = open('hashLog.txt', '+a') #open file to store file info 
#Blocklist of all directories to pass up in our hashing
blocklist = ['/dev', '/sys', '/proc', '/run', '/tmp', '/var/lib', '/var/run'] 
for dirpath, dirnames, filenames in os.walk("/"): #step through all dirs
    for i in filenames: #loop through all files
        #check if file is within unhashable directory
        invalidDir = any(baddir in dirpath for baddir in blocklist)
        if invalidDir == False: #if file is in valid directory, print path
            print("File: " + dirpath + '/' + i) #print out full file paths
            logFile.write("File: " + dirpath + '/' + i + '\n') #store full file path
            now = datetime.datetime.now() #get current time
            logFile.write(now.strftime("%Y-%m-%d %H:%M:%S\n")) #store time
            fullfile = dirpath + '/' + i
            try:
                with open(fullfile, 'rb') as f:
                    bytes = f.read()
                    readable_hash = hashlib.sha256(bytes).hexdigest()
                    logFile.write(readable_hash + '\n')
                    f.close()
            except OSError:
                print("File not found")
                pass
            
            
logFile.close()
