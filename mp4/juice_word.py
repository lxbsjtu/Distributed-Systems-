#!/usr/bin/env python
# usage juice_word file_names
import sys
from collections import defaultdict


if __name__ == "__main__":
    data = defaultdict(int)
    # open files and read them and load it all into a dict
    for arg in sys.argv[1:]:
        with open(arg, 'r') as file:
            for line in file:
                key, val = line.split()
                data[key] += int(val)

    with open("/home/raghu3/tmp/result", 'a+') as target:
        # print all the values in the dict
        for entry in data:
            print entry, " ", data[entry]
            target.write(entry+" "+str(data[entry]))
            target.write("\n")