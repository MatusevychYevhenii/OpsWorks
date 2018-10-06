#!/usr/bin/env python3
import boto3
import sys
import os.path
import getopt
import time
from botocore.exceptions import ClientError
import paramiko
import subprocess
from flask import Flask, Response, request
from functools import wraps

app = Flask(__name__)

# Global config
name_surname = 'Yevhenii/Matusevych'
pem_file = 'Yevhenii-Matusevych.pem'


def main(argv):
    if len(argv) < 1:
        print_manual()
        sys.exit(2)
    try:
        opts, args = getopt.getopt(argv, "hics")
    except getopt.GetoptError:
        print_manual()
        sys.exit(3)
    for opt, arg in opts:
        if opt == '-h':
            print_manual()
            sys.exit()
        elif opt in ("-i"):
            # Create a session client where
            # credentials is in ~/.aws/credentials
            session = boto3.Session()
            ec2client = session.client('ec2', region_name='eu-west-1')
            ec2resource = boto3.resource('ec2', region_name='eu-west-1')
            install(ec2client, ec2resource)
        elif opt in ("-c"):
            session = boto3.Session()
            # Create a session client where
            # credentials is in ~/.aws/credentials
            ec2client = session.client('ec2', region_name='eu-west-1')
            ec2resource = boto3.resource('ec2', region_name='eu-west-1')
            clear(ec2client, ec2resource)
        elif opt in ("-s"):
            http_server_run()


def print_manual():
    print('opswork.py [-i install] [-c clear]')


def get_instance_by_tag(ec2client, name, states):
    try:
        response = ec2client.describe_instances(
            Filters=[
                {
                    'Name': 'tag:Name',
                    'Values': [name]
                },
                {
                    'Name': 'instance-state-name',
                    'Values': states
                }
            ]
        )
        instancelist = []
        for reservation in (response["Reservations"]):
            for instance in reservation["Instances"]:
                instancelist.append(instance["InstanceId"])
        if instancelist:
            return instancelist
    except Exception as e:
        print(e)


def clear(ec2client, ec2resource):
    try:
        # delete key pair
        print('Deleting key pair %s ...' % name_surname)
        try:
            ec2client.describe_key_pairs(
                KeyNames=[name_surname])
            ec2client.delete_key_pair(KeyName=name_surname)
            print('Deleting key pair success')
        except Exception as e:
            print('Key pair %s does not exist or already deleted' %
                  name_surname)

        # delete instance
        print('Deleting instances %s ...' % name_surname)
        instanceIds = get_instance_by_tag(
            ec2client, name_surname, ['running', 'stopped'])
        if instanceIds is not None:
            # if we have manualy stopped instance.
            # This terminate running and stopped instances
            for instanceId in instanceIds:
                ec2client.terminate_instances(InstanceIds=[instanceId])
                instance = ec2resource.Instance(instanceId)
                while instance.state['Name'] not in ('terminated'):
                    time.sleep(5)
                    instance.load()
                    print('Instance state: %s' % instance.state['Name'])
                print('Deleting instance success')
        else:
            print('Running Instance %s does not exist or already deleted' %
                  name_surname)
        # delete security group
        print('Deleting security group %s ...' % name_surname)
        try:
            ec2client.delete_security_group(GroupName=name_surname)
            print('Deleting security group success')
        except Exception as e:
            print('The security group %s does not exist or already deleted' %
                  name_surname)
    except Exception as e:
        print(e)


def install(ec2client, ec2resource):
    # Create key #
    try:
        key_pair = ec2client.create_key_pair(KeyName=name_surname)
        f = open(pem_file, 'w+')
        f.write(key_pair['KeyMaterial'])
        f.close()
        subprocess.call(['chmod', '0400', pem_file])
        print('The key pair created: %s' % key_pair['KeyFingerprint'])
    except ClientError as e:
        key_pair = ec2client.describe_key_pairs(
            KeyNames=[name_surname])['KeyPairs'][0]
        print('The key pair already exists: %s' % key_pair['KeyFingerprint'])
        if not os.path.isfile(pem_file):
            print('*' * 80)
            print('You haven\'t ' + pem_file + ' file in this directory. ' +
                  'Clean environment and install instance, key pair, sg again')
            print('*' * 80)
            clear(ec2client, ec2resource)
            install(ec2client, ec2resource)
            return 4

    # Create a security group #
    try:
        sg = ec2client.create_security_group(
            GroupName=name_surname, Description='Open 22 and 80 ports')
        security_group_id = sg['GroupId']
        ec2client.authorize_security_group_ingress(
            GroupId=security_group_id,
            IpPermissions=[
                {'IpProtocol': 'tcp',
                 'FromPort': 22,
                 'ToPort': 22,
                 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
                {'IpProtocol': 'tcp',
                 'FromPort': 80,
                 'ToPort': 80,
                 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
            ])
        print('The security group created: %s' % sg['GroupId'])
    except ClientError as e:
        sg = ec2client.describe_security_groups(
            GroupNames=[name_surname])['SecurityGroups'][0]
        print('The security group already exists: %s' % sg['GroupId'])

    # Create an instance with volume #
    try:
        # start instance if it has stopped state
        stoppedInstance = get_instance_by_tag(
            ec2client, name_surname, ['stopped'])
        if stoppedInstance:
            ec2client.start_instances(InstanceIds=stoppedInstance)
            instance = ec2resource.Instance(stoppedInstance[0])
            while instance.state['Name'] not in ('running'):
                time.sleep(5)
                instance.load()
                print('Instance state: %s' % instance.state['Name'])

        instanceIds = get_instance_by_tag(
            ec2client, name_surname, ['running'])
        if not instanceIds:
            new_instances = ec2client.run_instances(
                BlockDeviceMappings=[
                    {
                        'DeviceName': '/dev/sdf',
                        'VirtualName': 'ephemeral0',
                        'Ebs': {
                            'VolumeSize': 1,
                            'VolumeType': 'standard',
                        },
                    },
                ],
                ImageId='ami-00035f41c82244dab',
                InstanceType='t2.micro',
                KeyName=key_pair['KeyName'],
                MinCount=1,
                MaxCount=1,
                SecurityGroupIds=[sg['GroupId']],
                TagSpecifications=[
                    {
                        'ResourceType': 'volume',
                        'Tags': [
                            {
                                'Key': 'Name',
                                'Value': name_surname
                            },
                        ]
                    },
                    {
                        'ResourceType': 'instance',
                        'Tags': [
                            {
                                'Key': 'Name',
                                'Value': name_surname
                            },
                        ]
                    }
                ]
            )
            instanceId = new_instances['Instances'][0]['InstanceId']
        else:
            instanceId = instanceIds[0]
    except Exception as e:
        print(e)
    print('Instance ID: %s' % instanceId)

    # check instance running state and use boto3 resource
    try:
        instance = ec2resource.Instance(instanceId)
        while instance.state['Name'] not in ('running', 'stopped'):
            time.sleep(5)
            instance.load()
            print('Instance state: %s' % instance.state['Name'])
    except Exception as e:
        print(e)

    # ssh connect to ec2 using paramiko
    try:
        client = paramiko.SSHClient()
        pk = paramiko.RSAKey.from_private_key_file(pem_file)
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=instance.public_dns_name,
                       username="ubuntu", pkey=pk, look_for_keys=False)
    except Exception as e:
        # if unable to connect to port 22 on out ip
        print('Instance hasn\'t run port 22 yet. ' +
              'Wait and run install again')
        time.sleep(5)
        install(ec2client, ec2resource)
        return 5

    # Execute a command(cmd) after connecting/ssh to an instance
    try:
        stdin, stdout, stderr = client.exec_command(
            'sudo mkfs -t ext4 /dev/xvdf')
        print('sudo mkfs -t ext4 /dev/xvdf:  ', stdout.read().decode("utf-8"))

        stdin, stdout, stderr = client.exec_command(
            'sudo mkdir /additionalvolume')

        stdin, stdout, stderr = client.exec_command(
            'sudo mount /dev/xvdf /additionalvolume && ' +
            'sudo rm -rf /additionalvolume/lost+found')
        print('sudo mount /dev/xvdf /additionalvolume')

        print('sudo apt-get -y update')
        time.sleep(10)
        stdin, stdout, stderr = client.exec_command(
            'sudo apt-get -y update')
        print(stdout.read().decode("utf-8"))
        print(stderr.read().decode("utf-8"))

        stdin, stdout, stderr = client.exec_command(
            'sudo apt-get -y upgrade')
        print('sudo apt-get -y upgrade')
        print(stdout.read().decode("utf-8"))
        print(stderr.read().decode("utf-8"))

        stdin, stdout, stderr = client.exec_command(
            'sudo apt-get -y install python3-pip')
        print('sudo apt-get -y install python3-pip')
        print(stdout.read().decode("utf-8"))
        print(stderr.read().decode("utf-8"))

        stdin, stdout, stderr = client.exec_command(
            'cd /additionalvolume && ' +
            'sudo git clone ' +
            'https://github.com/MatusevychYevhenii/OpsWorks.git')
        clone_output = stderr.read().decode("utf-8")

        stdin, stdout, stderr = client.exec_command(
            'cd /additionalvolume/OpsWorks && ' +
            'sudo git pull')
        pull_output = stdout.read().decode("utf-8")
        print('git pull:\n', pull_output)

        # run install requirements only once
        stdin, stdout, stderr = client.exec_command(
            'sudo fuser 80/tcp')
        stdout_fuser_check = stdout.read().decode("utf-8")
        print('Check if something run on 80 port: ', stdout_fuser_check)
        if not stdout_fuser_check:
            stdin, stdout, stderr = client.exec_command(
                'cd /additionalvolume/OpsWorks && ' +
                'pip3 install -r requirements.txt')
            print('pip3 install -r requirements.txt')
            time.sleep(20)

        print('\'Updating\' in pull_output: ', 'Updating' in pull_output)
        print('\'Cloning into\' in clone_output: ',
              'Cloning into' in clone_output)
        # Restart http service if changes are in git pull
        # or http service is down
        if 'Updating' in pull_output or 'Cloning into' in clone_output:
            stdin, stdout, stderr = client.exec_command(
                'cd /additionalvolume/OpsWorks; ' +
                'sudo chmod +x opswork.py; ' +
                'sudo fuser -k 80/tcp')
            transport = client.get_transport()
            channel = transport.open_session()
            print('sudo nohup ./opswork.py -s > /dev/null 2>&1 &')
            channel.exec_command(
                'cd /additionalvolume/OpsWorks; ' +
                'sudo nohup ./opswork.py -s > /dev/null 2>&1 &')
            print('You open in browser this public dns to view ' +
                  'the current git commit and resource usage (cpu, memory)')
            # Close the channel connection once the job is done
            channel.close()
        print('*' * 80)
        print(' ' * 5 + 'PUBLIC DNS NAME: ' + instance.public_dns_name)
        print('Login = admin and password = xd7iwkxg')
        print('Link to GitHub repository which contain script source code :')
        print('https://github.com/MatusevychYevhenii/OpsWorks.git')
        print('*' * 80)
    except Exception as e:
        print(e)
    finally:
        # Close the client connection once the job is done
        if client:
            client.close()


def check_auth(username, password):
    # check if a username/password combination is valid.
    return username == 'admin' and password == 'xd7iwkxg'


def authenticate():
    # Sends a 401 response that enables basic auth
    return Response(
        'Could not verify your access level for that URL.\n'
        'You have to login with proper credentials', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'})


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated


@app.route('/')
@requires_auth
def index():
    # parsing for sshowing in browser
    output = subprocess.Popen(['git', 'log', '--name-status', 'HEAD^..HEAD'],
                              stdout=subprocess.PIPE)
    response_git = 'Last commit: \n<b>OpsWorks# ' +\
                   'git log --name-status HEAD^..HEAD</b>\n' +\
                   output.communicate()[0].decode("utf-8") + '\n'

    output = subprocess.Popen(['uptime'],
                              stdout=subprocess.PIPE)
    response_uptime = '<b>OpsWorks# ' +\
                      'uptime</b>\n' +\
                      output.communicate()[0].decode("utf-8") + '\n'

    output = subprocess.Popen(['vmstat', '-S', 'M'],
                              stdout=subprocess.PIPE)
    response_vmstat = '<b>OpsWorks# ' +\
                      'vmstat -S M</b>\n' +\
                      output.communicate()[0].decode("utf-8") + '\n'

    output = subprocess.Popen(['free', '-m', '-h'],
                              stdout=subprocess.PIPE)
    response_free = '<b>OpsWorks# ' +\
                    'free -m -h</b>\n' + '&emsp;' * 3 +\
                    output.communicate()[0].decode("utf-8") + '\n'

    # replace new line on <br /> tag for showing in browser
    return "<br />".join(
        (response_git + response_uptime +
         response_free + response_vmstat).split("\n"))


def http_server_run():
    try:
        app.run(host='0.0.0.0', port=int("80"), debug=True)
        print('You can open in browser using public dns this instance')
    except Exception as e:
        print(e)


if __name__ == "__main__":
    main(sys.argv[1:])
