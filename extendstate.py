[root@drxrepo ~]# more /state/export/gitrepos/profiles/files/os/extendstate.py
#!/usr/bin/python

import os
import subprocess
import sys

def main():
  # Now start doing the interesting part of extending the disk
  # We have to make the system recognize that the hdd has physically changed
  d = '/sys/class/scsi_disk'
  for i in next(os.walk(d))[1]:
    fd = open(d + '/' + i + '/device/rescan', 'wb')
    fd.write('1')
    fd.close()

  # Resize the LVM Physical Volume to take up the newly found space
  returnCode = subprocess.call("/sbin/pvresize /dev/sdb &> /dev/null", shell=True)
  if (returnCode != 0):
    sys.exit("Problem running /sbin/pvresize")

  # Resize the LVM Logical Volume
  returnCode = subprocess.call("lvextend -r /dev/vg_state/lv_state /dev/sdb &> /dev/null", shell=True)
  if (returnCode != 0):
    sys.exit("Problem running /sbin/lvextend")

if __name__ == "__main__":
  main()
[root@drxrepo ~]# 
