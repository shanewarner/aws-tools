#!/usr/bin/python

import sys
import urllib2
import json
import requests
import polling
import re
import time
import argparse
import boto

asgard_host = 'asgard.darkstarnet:8080'
ec2_region = 'us-east-1'
base_url = 'http://' + asgard_host + '/' + ec2_region
notify = 'shane@darkstarnet.net'
judgement_txt = "ASG will now be evaluated for up to .* minutes during the judgment period."
poll_timeout = 600  # Timeout for polling
regex = ""


def assign_eip(eip, instance_id):
    conn = boto.connect_ec2()

    try:
        conn.associate_address(instance_id, eip)
    except Exception as e:
        print "[-] Error assigning rollback EIP to instance!"
        print e
        sys.exit(2)

    print "[+] Assigned {0} back to owner {1}.".format(eip, instance_id)


def get_token(deployment_id):
    response = requests.get(base_url + '/deployment/show/' + deployment_id)
    return response.json()["token"]


def get_error(poll_url):
    return requests.get(poll_url).json()["log"]


def judgement_ready(response):
    if re.search(judgement_txt, response.json()["operation"]):
        print '[+] Deployment is now awaiting judgement.'
        return True
    return False


def qa(response):
    if len(regex) > 0:
        if re.search(regex, response.text):
            print "[+] qa(): found string \"{0}\"".format(regex)
            return True
    else:
        if response.status_code == 200:
            print "[+] qa(): got status code 200"
            return True
    return False


def rollback(deployment_id):
    token = get_token(deployment_id)
    payload = {'id': deployment_id, 'token': token}
    post_url = base_url + '/deployment/rollback'
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    requests.post(post_url, data=json.dumps(payload), headers=headers)
    return


def search_ip(ip):
    conn = boto.connect_ec2()

    try:
        instance_id = [address.instance_id for address in conn.get_all_addresses(filters={"public-ip": ip})]
    except Exception as e:
        print "[-] Error:"
        print "{0}".format(e)
        sys.exit(2)

    if len(instance_id[0]) < 9:
        print "[-] Error: IP is not currently assigned to any instance."
        sys.exit(2)

    return instance_id[0]


def proceed(deployment_id):
    token = get_token(deployment_id)
    payload = {'id': deployment_id, 'token': token}
    post_url = base_url + '/deployment/proceed'
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    requests.post(post_url, data=json.dumps(payload), headers=headers)
    return


def main():
    version = '1.2'

    parser = argparse.ArgumentParser(description="AMI Asgard Deployment Script.")
    parser.add_argument("-n", "--nofollow", action='store_true', help="Do not follow redirects for the test URL.")
    parser.add_argument("--eip", help="Elastic IP address for rollback. (EIP based deployments only).", required=False)
    parser.add_argument("-b", "--bypass", action="store_true", help="Bypass the URL test")
    parser.add_argument("-t", "--timeout", action="store_true", help="Specify polling timeout. (Default: 600 seconds)")
    parser.add_argument('asg_id')
    parser.add_argument('ami_id')
    parser.add_argument('test_url', nargs='?')
    parser.add_argument('regex', nargs='?')
    args = parser.parse_args()

    print "AMI Asgard Deployment Script {0}".format(version)

    asg_id = args.asg_id
    ami_id = args.ami_id

    if args.timeout:
        global poll_timeout
        poll_timeout = args.timeout

    if not args.bypass:
        test_url = args.test_url
        if args.regex:
            global regex
            regex = args.regex

    print "[+] Asgard Host: {0}".format(asgard_host)
    print "[+] EC2 Region: {0}".format(ec2_region)
    print "[+] ASG: {0}".format(asg_id)
    print "[+] AMI to Launch: {0}".format(ami_id)

    if args.eip:
        print "[+] Determining rollback instance_id for: {0}".format(args.eip)
        rbinstance_id = search_ip(args.eip)
        print "{0}".format(rbinstance_id)

    query = base_url + '/deployment/prepare?id=' + asg_id
    f = urllib2.urlopen(query)
    deflcjson = f.read()
    f.close()

    deflc = json.loads(deflcjson)
    deflc['lcOptions']['imageId'] = ami_id
    deflc['deploymentOptions'] = {
        "clusterName": asg_id,
        "notificationDestination": notify,
        "steps": [
            {"type": "CreateAsg"},
            {"type": "Resize", "targetAsg": "Next", "capacity": deflc['asgOptions']['minSize'],
             "startUpTimeoutMinutes": 10},
            {"type": "DisableAsg", "targetAsg": "Previous"},
            {"type": "Judgment", "durationMinutes": 30},
            {"type": "DeleteAsg", "targetAsg": "Previous"},
        ]
    }

    post_url = base_url + '/deployment/start'
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    response = requests.post(post_url, data=json.dumps(deflc), headers=headers)

    print response
    print response.text

    print "[+] Waiting for deployment to enter judgement state. Timeout is: {0}".format(poll_timeout)
    deployment_id = response.json()["deploymentId"]
    poll_url = base_url + '/task/show/' + deployment_id + '.json'

    time.sleep(30)

    try:
        polling.poll(
            lambda: requests.get(poll_url),
            check_success=judgement_ready,
            step=30,
            timeout=poll_timeout
        )
    except Exception as e:
        print "[-] Error waiting for judgement: {0} \n{1}".format(e, get_error(poll_url))
        sys.exit(2)

    if args.eip:
        if rbinstance_id == search_ip(args.eip):
            print "[-] Error: New instance did not assign itself EIP: {0}. Cannot proceed with judgment. " \
                  "Initiating rollback.".format(args.eip)
            rollback(deployment_id)
            assign_eip(args.eip, rbinstance_id)
            sys.exit(2)

    if not args.bypass:
        if args.nofollow:
            test_func = requests.get(test_url, allow_redirects=False)
        else:
            test_func = requests.get(test_url, allow_redirects=True)

        try:
            polling.poll(
                lambda: test_func,
                check_success=qa,
                step=3,
                timeout=150
            )
        except Exception as e:
            print "[-] Error running test: Test url failed to meet test criteria."
            print "{0}".format(e)
            print "[+] Initiating rollback of deployment."
            rollback(deployment_id)
            if args.eip:
                assign_eip(args.eip, rbinstance_id)
            sys.exit(2)

        print "[+] Tests passed. Proceeding deployment."
        proceed(deployment_id)
    else:
        print "[+] Test bypassed. Proceeding deployment."
        proceed(deployment_id)

if __name__ == '__main__':
    main()
