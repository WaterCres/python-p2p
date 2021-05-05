import json
import hashlib
from os import walk
import subprocess

f2data= {}
mypath = "content/"

def hashFile(filepath):
    filepath = mypath + filepath
    hasher = hashlib.md5()
    with open(filepath, 'rb') as afile:
        buf = afile.read()
        while len(buf) > 0:
            hasher.update(buf)
            buf = afile.read()
    return(hasher.hexdigest())

f = []
def refresh():
    f2data = {}
    for (dirpath, dirnames, filenames) in walk(mypath):
        f.extend(filenames)
    with open('resources.json', 'w') as f2:
        for file in filenames:
            f2data[hashFile(file)] = file
        json.dump(f2data, f2)

def have_file(hash):
    refresh()
    if hash in f2data:
        return(True)

refresh()
