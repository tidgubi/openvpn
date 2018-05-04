#!/usr/bin/python

# Username/Password Authentication Script for use with OpenVPN
# Copyright (c) 2018 Kenji Yoshino https://www.tidgubi.com
# This script is released under the Version 3 of the GNU General Public
# License https://www.gnu.org/licenses/gpl-3.0.txt

import sys
import os
from hashlib import pbkdf2_hmac
from time import time, sleep
from binascii import b2a_base64, a2b_base64
from getpass import getpass

# if OpenVPN is running as nobody, this file must be world readable
# The hashing will protect strong passwords, but anyone that can read this file
# can perform a brute force attack. I recommend creating an openvpn user/group
# so openvpn does not have to run as root, but access can be restricted.
SHADOW_FILE="/etc/openvpn/shadow"
LOCK_FILE="/dev/shm/openvpn-auth-lock"
HASH="sha256"
ITTERATIONS=100000
BASE_TIME=1.0 # set a minimum time in seconds for check function
SALT_SIZE=16
MAX_UN_PW_LEN=512
MAX_SHADOW_FILE=16384
INVALID=1
VALID=0
# If SHADOW_FILE is None, shadow_contents can be configured as a list of strings
# using the format <username>:<salt>:<hash> for each line. Each value is base64
# encoded. Strings can be generated using the -g option
shadow_contents=None

def usage():
   print "./openvpn-auth.py <un/pw file>"
   print "./openvpn-auth.py -[g|a|d] <username> [password]"
   print "./openvpn-auth.py -l"

def getHash(salt, password):
   return b2a_base64(pbkdf2_hmac(HASH, password, salt, ITTERATIONS)).strip()

def check(pw_file):
   while os.path.isfile(LOCK_FILE):
      sleep(0.1)
   with open(LOCK_FILE, 'a'):
      start=time()
   rtn=INVALID

   try:
      with open(pw_file, 'r') as f:
         username=b2a_base64(f.readline(MAX_UN_PW_LEN).rstrip("\r\n")).strip() + ":"
         password=f.readline(MAX_UN_PW_LEN).rstrip("\r\n")
         if len(f.readline(MAX_UN_PW_LEN)) > 0:
            return INVALID
   except Exception as e:
      print e
      return INVALID

   try:
      if SHADOW_FILE is not None:
         with open(SHADOW_FILE, 'r') as f:
            shadow_contents=f.readlines(MAX_SHADOW_FILE)
      
      for line in shadow_contents:
         if line.startswith(username):
            parts=line.split(":")
            if len(parts) != 3:
               break
            password=getHash(a2b_base64(parts[1]),password)
            if password == parts[2].strip():
               rtn=VALID
            break
   except Exception as e:
      print e
      rtn=INVALID

   # make this function run in constant time
   t=BASE_TIME-(time()-start)
   if t > 0.0:
      sleep(t)
   
   for x in range(3): #try to remove the lock file 3 times
      try:
         os.remove(LOCK_FILE)
         break
      except Exception:
         continue
   
   return rtn

def delete(username):
   if not os.path.isfile(SHADOW_FILE):
      return
   username=b2a_base64(username).strip() + ":"
   with open(SHADOW_FILE, 'r') as f:
      shadow_contents=f.readlines(MAX_SHADOW_FILE)
   
   with open(SHADOW_FILE, 'w') as f:
      for line in shadow_contents:
         if not line.startswith(username):
            f.write(line);
      f.truncate()

def generate(username, password, add):
   start=time()
   while password is None:
      password=getpass("Enter a password for %s: " % username)
      verifypass=getpass("Verify password: ")
      if password != verifypass:
         print("Passwords do not match. Try again.\n")
         password=None
   salt=os.urandom(SALT_SIZE)
   encusername=b2a_base64(username).strip()
   password=getHash(salt,password)
   salt=b2a_base64(salt).strip()
   #TODO: warn the user if SHADOW_FILE is larger than max shawow length
   if add:
      delete(username)
      with open(SHADOW_FILE, 'a') as f:
         f.write("%s:%s:%s\n" % (encusername, salt, password))
   else:
      print("%f seconds to compute hash" % (time()-start))
      print("%s:%s:%s" % (encusername, salt, password))

def list():
   try:
      if SHADOW_FILE is not None:
         with open(SHADOW_FILE, 'r') as f:
            shadow_contents=f.readlines(MAX_SHADOW_FILE)
      
      for line in shadow_contents:
         parts=line.split(":")
         if len(parts) != 3:
            continue
         print(a2b_base64(parts[0]) + "\n")
   except Exception as e:
      print e

args=len(sys.argv)
if args == 2:
   if sys.argv[1] == "-l":
      list()
   else:
      sys.exit(check(sys.argv[1]))
elif args == 3 or args == 4:
   if sys.argv[1] == "-g" or sys.argv[1] == "-a":
      if sys.argv[1] == "-a" and SHADOW_FILE is None:
         print("Error: You must configure a SHADOW_FILE to use -a.\n")
      else:
         password=None
         if args == 4:
            password=sys.argv[3]
         generate(sys.argv[2], password, sys.argv[1] == "-a")
   elif sys.argv[1] == "-d":
      delete(sys.argv[2])
   else:
      usage()
else:
   usage()

sys.exit(0)
