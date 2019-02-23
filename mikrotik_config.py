import paramiko
import progressbar
import re
import sys
from getpass import getpass


def backup_config(ssh, backup_file):
    _ssh_input, _ssh_output, _ssh_error = ssh.exec_command('export')
    backup = open(backup_file, 'w')
    print("Create config backup file... (this may take some time)")
    backup.write(_ssh_output.read())
    backup.close()
    return _ssh_input, _ssh_output, _ssh_error


def create_config(filename):
    # create config from backup file
    with open(filename, 'r') as file:
        lines = file.readlines()
    branch, command = '', ''
    commands = []
    for line in lines:
        if len(line) > 0:
            if line[0] == '/':
                commands = commands + [" ".join([branch, command])]
                branch = line.strip('\r\n')
            elif line[0] != ' ':
                commands = commands + [" ".join([branch, command])]
                command = line.strip('\\').strip('\r\n')
            elif line[0] == '#':
                pass
            else:
                command = (command + line.strip('\r\n')).replace('\\    ', '')
    return commands


def create_vpn_config():
    # todo create vpn config file
    pass


ip = raw_input("IP: ").rstrip('\n')
username = raw_input("Username: ").rstrip('\n')+'+hN'
# # username+hN or 'without-paging' after each command is the same as terminal length 0 on cisco devices
password = getpass("Password: ")

paramiko.util.log_to_file("paramiko.log")

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(ip, username=username, password=password, timeout=10, look_for_keys=False)
ssh_input, ssh_output, ssh_error = backup_config(ssh, ip+'-backup.txt')

config_file = 'config.txt'
# Warning
answer = raw_input('This script is experimental, DO NOT USE on \n'
                   'production routers unless you\'ve checked \n'
                   'the generated config file! ({})'
                   ' Continue? [y/N]'.format(config_file))

if answer.lower().strip() not in ['y', 'yes']:
    print("Thank you!\nBye!")
    sys.exit()

print("Configuring ...")
config = create_config(config_file)
with progressbar.ProgressBar(max_value=len(config)) as bar:
    i=0
    for line in config:
        i = i + 1; bar.update(i)
        ssh_input, ssh_output, ssh_error = ssh.exec_command(line)
        if re.search(b"bad command name", ssh_output.read()):
            print(line + "\n*** There was a syntax error on device {0} :(".format(ip, i+1))
            ssh.close()
            sys.exit("[ERROR] Bad command name ...")

print("\nDONE for device {} :)\n".format(ip))
ssh.close()
