#!/usr/bin/env python3

import os

#Blocklist of all directories to pass up in our hashing
blocklist = ['/dev', '/sys', '/proc', '/run', '/tmp', '/var/lib', '/var/run'] 
for dirpath, dirnames, filenames in os.walk("tripwire"): #step through all dirs
    for i in filenames: #loop through all files
        #check if file is within unhashable directory
        invalidDir = any(baddir in dirpath for baddir in blocklist)
        if invalidDir == False: #if file is in valid directory, print path
            print(dirpath + '/' + i) #print out full file paths

