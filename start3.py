import errno
import os
import pty
from subprocess import Popen, STDOUT

file = open('out1.txt', 'a+')
master_fd, slave_fd = pty.openpty()
proc = Popen(['python', 'cmsmap.py', 'https://stmik-amikbandung.ac.id'],
             stdin=slave_fd, stdout=slave_fd, stderr=STDOUT, close_fds=True)
os.close(slave_fd)
try:
    while 1:
        try:
            data = os.read(master_fd, 512)
        except OSError as e:
            if e.errno != errno.EIO:
                raise
            break  # EIO means EOF on some systems
        else:
            if not data:  # EOF
                break
            rdata = repr(data)
            print('got ' + rdata, file=file)
finally:
    os.close(master_fd)
    if proc.poll() is None:
        proc.kill()
    proc.wait()

print("This is reached!")
