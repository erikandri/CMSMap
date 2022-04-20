import subprocess
import sys
import time


def execute(command):
    process = subprocess.Popen(command, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               universal_newlines=True)
    while True:
        nextline = process.stdout.readline()
        if process.poll() is not None:
            break
        print('pp:', nextline, end='')
        # file.write(nextline)
        time.sleep(1)

    output = process.communicate()[0]
    print('\n\nCommunicate is:', output)
    exitCode = process.returncode

    if exitCode == 0:
        print('\n\nReturn exitCode == 0')
        return output
    else:
        raise Exception(command, exitCode, output)
    # Exception: (['py', 'cmsmap.py', 'https://girindropringgodigdo.net'], 1,
    #             b'[-] Set the ExploitDB path "edbpath" in cmsmap.conf\r\n[-] ie: edbpath = /usr/share/exploitdb/\r\n')


if __name__ == '__main__':
    # args = sys.argv
    # if len(args) < 2:
    #     print('Example: py start.py https://testportal.helium.sh')
    #     exit(0)
    # command = ['py', 'cmsmap.py', args[1], '-F', '--noedb']
    command = ['py', 'cmsmap.py', 'https://stmik-amikbandung.ac.id', '--noedb']
    execute(command=command)
