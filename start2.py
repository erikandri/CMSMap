import threading
import subprocess
import sys


class MyClass(threading.Thread):
    def __init__(self, command):
        self.stdout = None
        self.stderr = None
        self.command = command
        threading.Thread.__init__(self)

    def run(self):
        p = subprocess.Popen(self.command,
                             shell=False,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             universal_newlines=True,
                             bufsize=1,
                             close_fds=True)

        self.stdout, self.stderr = p.communicate()
        print(self.stdout)


if __name__ == '__main__':
    # if len(sys.argv) < 2:
    #     print('example: py start2.py https://stmik-amikbandung.ac.id')
    #     exit(0)
    # url = sys.argv[1]
    command = ['python', 'cmsmap.py', 'https://stmik-amikbandung.ac.id']
    myclass = MyClass(command=command)
    myclass.start()
    myclass.join()
    print('STDOUT BELOW...')
    file = open('out1.txt', 'a+')
    print(myclass.stdout, file=file)
    file.close()
