#!/usr/bin/env python
"""
Toolset for working with:
 - KMS encrypted files on s3.
 - Roles, grants and KMS keys on a per cluster context.
"""

__author__ = 'shane@darkstarnet.net'

import argparse
import base64
import binascii
import boto
import boto.kms
import boto.iam
import boto.s3
import json
import time
import os
import random
import shutil
import sys
import subprocess
import StringIO
from subprocess import call
from argparse import RawTextHelpFormatter
from boto import utils
from boto.s3.key import Key
from Crypto.Cipher import AES
from hashlib import sha256

__author__ = 'shane.warner@fox.com'


class Kms3(object):
    def __init__(self):
        try:
            # Prefix building defaults
            response = boto.utils.get_instance_identity()
            self.region = response.get("document")['region']
            self.acct_id = response.get("document")['accountId']
            self.environment = 'dev'
            # Default cluster name is dev
            self.name = 'dev'

            # Grab metadata and make API connections
            self.kms = boto.kms.connect_to_region(self.region)
            self.iam = boto.iam.connect_to_region(self.region)
            self.s3 = boto.connect_s3()

            # Internal defaults
            self.__secrets_dir__ = "/home/ec2-user/.kms3/"
            # TODO: make this more dynamic
            self.__secrets_bucket_prefix__ = "mysecrets-"

            # Key spec
            self.__key_spec__ = "AES_256"

            # Key related defaults
            self.k = 16
            self.recycle_key = 0
            self.recycle_role = 0
        except Exception as e:
            print "[-] Error:"
            print "{0}".format(e)
            return

    def _build_prefix(self):
        """
        Internal function to build the s3 prefix for a cluster and file.
        :return: Dict containing the cluster path and shared path. Not currently used, but will possibly be repurposed
        for the vhost download.
        """
        prefix = {self.name: "", "shared": ""}

        prefix[self.name] = "cluster/" + self.region + "/" + self.environment + '/' + self.name + "/"
        prefix['shared'] = "cluster/" + self.region + "/" + self.environment + "/shared/"
        return prefix

    def _get_data_key(self):
        """
        Internal function to retrieve the data key for a cluster using KMS and the secrets file on s3.
        :return:
        """
        # If the file exists on s3, download and proceed.
        if not self.exists_on_s3(self.name + ".json"):
            print "[+] Error locating secrets file on s3 for {0}".format(self.name)
            return

        secrets_file = self.download_from_s3(self.name, self.name + ".json")

        # Load the ciphertext blob from the secrets file
        try:
            json_data = open(secrets_file, "r")
        except Exception as e:
            print "[-] Error opening json file for {0}".format(self.name)
            print "{0}".format(e)
            return

        # Decode into raw form before passing to KMS
        data = json.load(json_data)
        try:
            ciphertextblob = base64.b64decode(data[self.name]["CiphertextBlob"])
        except Exception as e:
            print "[-] Error while parsing ciphertext for cluster data key."
            print "{0}".format(e)
            sys.exit(2)

        # Decrypt the data key ciphertext blob with KMS.
        try:
            response = self.kms.decrypt(ciphertext_blob=ciphertextblob)
        except Exception as e:
            print e
            return

        decrypted_key = response.get("Plaintext")
        self.secure_delete(secrets_file, passes=10)

        return decrypted_key

    def _get_vhost_data_key(self):
        """
        Modified version of the internal function to retrieve the data key for a cluster using KMS and the secrets file on s3.
        This allows us to step outside of the structure used by the rest of the secrets, until we can refactor accordingly.
        :param name:  Name of the cluster.
        :return:
        """
        # If the file exists on s3, download and proceed.
        if not self.exists_on_s3(self.name + "-vhosts.json"):
            print "[+] Error locating secrets file on s3 for {0}".format(self.name)
            return

        # Create the output directory if it doesn't exist in /dev/shm
        directory = "/dev/shm/" + "cluster/" + self.name + "/vhost"
        if not os.path.exists(directory):
            os.makedirs(directory)

        secrets_file = self.download_from_s3(self.name, self.name + "-vhosts.json")

        # Load the ciphertext blob for the databag from the secrets file
        try:
            json_data = open(secrets_file, "r")
        except:
            print "[-] Error opening json file for {0}".format(self.name)
            return

        # Decode into raw form before passing to KMS
        data = json.load(json_data)
        ciphertextblob = base64.b64decode(data[self.name]["CiphertextBlob"])

        # Decrypt the data key ciphertext blob with KMS.
        try:
            response = self.kms.decrypt(ciphertext_blob=ciphertextblob)
        except Exception as e:
            print e
            return False

        decrypted_key = response.get("Plaintext")
        self.secure_delete(secrets_file, passes=10)

        return decrypted_key

    def decrypt(self, ciphertext, key):
        """
        Decrypts the ciphertext contents with the supplied key
        :param ciphertext: Data to be decrypted
        :param key: Key to be used for decryption
        """
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv, segment_size=64)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return self.pkcs7_unpad(plaintext)

    def decrypt_file(self, file_name, key):
        """
        Decrypts the supplied file name with the supplied key.
        :param file_name: Name of the local file to decrypt
        :param key: AES 256 key.
        :return: Returns the full path to the decrypted file.
        """
        with open(file_name, 'rb') as fo:
            try:
                ciphertext = fo.read()
            except Exception as e:
                print "[-] Error opening file {0} for reading.".format(file_name)
                print "{0}".format(e)
                return
        try:
            dec = self.decrypt(ciphertext, key)
        except Exception as e:
            print "[-] Decryption failed."
            print "{0}".format(e)
            return

        with open(file_name[:-4], 'wb') as fo:
            try:
                fo.write(dec)
            except Exception as e:
                print "[-] Error writing out file {0}".format(file_name[:-4])
                print "{0}".format(e)
                return

        os.chmod(file_name[:-4], 0600)
        return file_name[:-4]

    def download_from_s3(self, name, file_name):
        """
        Downloads the specified file name from the cluster's s3 bucket/prefix.
        :param name: Name of the cluster the file belongs to.
        :param file_name: File name on s3.
        :return: Returns the path to the file
        """
        # Connect to the bucket
        try:
            bucket = self.s3.get_bucket(self.__secrets_bucket_prefix__ + self.environment)
        except Exception as e:
            print "[-] Error"
            print "{0}".format(e)
            return

        # Set the relative bucket key path
        # TODO: add proper vhosts patch
        if ("-vhosts.json" in file_name) or ("vhosts.conf" in file_name):
            key = bucket.get_key("vhost/" + self.environment + '/' + self.name + "/" + file_name)
        else:
            key = bucket.get_key(self._build_prefix()[self.name] + file_name)

        # Create the output directory if it doesn't exist in /dev/shm
        directory = "/dev/shm/" + "cluster/" + name
        if not os.path.exists(directory):
            os.makedirs(directory)
        out_file_path = directory + "/" + file_name

        # Download the file from s3
        try:
            key.get_contents_to_filename(out_file_path)
        except Exception as e:
            print "[-] Error"
            print e
            return

        os.chmod(out_file_path, 0600)

        return out_file_path

    def download_data_key(self):
        """
        Downloads a cluster's data key to a temp file on /dev/shm

        :return:
        """
        temp_data_key = self._get_data_key()
        # File wasn't found on s3 so we return.
        if not temp_data_key:
            return False

        output_file = "/dev/shm/" + self.name + ".tmp.key"

        try:
            the_file = open(output_file, "w")
        except Exception as e:
            print "[-] Error opening /dev/shm for writing."
            print "{0}".format(e)
            return False

        the_file.write(temp_data_key)
        os.chmod(output_file, 0600)

        print "[+] {0} data key saved to {1}".format(self.name, output_file)

    def edit(self, name, the_file):
        """
        Edits a cluster specific file on s3.
        :param name: Name of the cluster the file belongs to.
        :param the_file: Name of the file to edit.
        :return:
        """
        # Check that the file exists on s3 before proceeding
        if not self.exists_on_s3(the_file):
            print "[-] File does not exist on s3 or role permissions are incorrect."
            return

        # Grab the data key from IAM
        decrypted_key = self._get_data_key()

        # store the key in a temporary file in /dev/shm for working with the encrypted file.
        key_file = "/dev/shm/" + name + ".tmp.key"
        try:
            key_file_out = open(key_file, "w")
        except Exception as e:
            print "[-] Error creating temp data key file {0}".format(key_file)
            print "{0}".format(e)
            return

        key_file_out.write(decrypted_key)
        os.chmod(key_file, 0600)
        key_file_out.close()

        # Download the file from s3 to /dev/shm
        file_name = self.download_from_s3(name, the_file)
        os.chmod(file_name, 0600)

        # Decrypt the file before editing
        decrypted_file_name = self.decrypt_file(file_name, decrypted_key)

        # Call $EDITOR to edit the file.
        editor = os.environ.get('EDITOR', 'vim')
        call([editor, decrypted_file_name])

        # Encrypt and upload the file back to s3
        self.upload(decrypted_file_name)

        # Clean up any other files laying around
        self.secure_delete(file_name, passes=10)
        self.secure_delete(decrypted_file_name, passes=10)
        self.secure_delete(key_file, passes=10)

        return

    def encrypt(self, message, key):
        """
        Encrypts the message contents with the supplied key
        :param message: Data to be encrypted
        :param key: Key to be used for encryption
        """
        message = self.pkcs7_pad(message)
        iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(AES.block_size))
        cipher = AES.new(key, AES.MODE_CBC, iv, segment_size=64)
        return iv + cipher.encrypt(message)

    def encrypt_file(self, file_name, key):
        with open(file_name, 'rb') as fo:
            try:
                plaintext = fo.read()
            except Exception as e:
                print "[-] Error opening file {0} for reading.".format(file_name)
                print "{0}".format(e)
                return

        enc = self.encrypt(plaintext, key)
        with open("/dev/shm/" + os.path.basename(file_name) + ".enc", 'wb') as fo:
            try:
                fo.write(enc)
            except Exception as e:
                print "[-] Error writing tmp file {0}".format("/dev/shm/" + os.path.basename(file_name) + ".enc")
                print "{0}".format(e)
        os.chmod("/dev/shm/" + os.path.basename(file_name) + ".enc", 0600)

        return

    def exists_on_s3(self, file_name):
        """
        Checks for the existence of a file on s3.
        :param file_name: Name of the file on s3.
        :return:
        """
        # TODO: add proper vhosts patch
        if ("-vhosts.json" in file_name) or ("vhosts.conf" in file_name):
            path = "vhost/" + self.environment + '/' + self.name + "/" + os.path.basename(file_name)
        else:
            path = self._build_prefix()[self.name] + file_name

        bucket = self.s3.get_bucket(self.__secrets_bucket_prefix__ + self.environment)

        try:
            response = bucket.get_key(path)
        except Exception as e:
            print "[-] Error"
            print "{0}".format(e)
            return

        if response:
            return True

        return False

    def get_vhosts(self):
        """
        Downloads the vhost configuraion for the specified cluster.
        :param name: Name of the cluster the file belongs to.
        :return: True or False
        """

        file = "vhosts.conf.enc"
        dest_file = "/etc/httpd/conf/vhosts.conf"

        # Check that the file exists on s3 before proceeding
        if not self.exists_on_s3(file):
            print "[-] File does not exist on s3 or role permissions are incorrect."
            return False

        # Grab the data key from IAM
        decrypted_key = self._get_vhost_data_key()

        # store the key in a temporary file in /dev/shm for working with the encrypted file.
        key_file = "/dev/shm/" + self.name + "-vhost" + ".tmp.key"
        try:
            key_file_out = open(key_file, "w")
        except:
            print "[-] Error creating temp data key file {0}".format(key_file)
            return False

        key_file_out.write(decrypted_key)
        os.chmod(key_file, 0600)
        key_file_out.close()

        # Download the file from s3 to /dev/shm
        file_name = self.download_from_s3(self.name, file)
        os.chmod(file_name, 0600)

        # Decrypt the file and move it to the final destination
        decrypted_file_name = self.decrypt_file(file_name, decrypted_key)
        shutil.move(decrypted_file_name, dest_file)

        # Return the sha256sum of the original file for use in Chef's s3_file resource
        ckf = open(dest_file, "r")
        file_data = ckf.read()
        file_sha256_checksum = sha256(file_data)
        ckf.close()

        print "[+] Updated {0}:{1}".format(dest_file, file_sha256_checksum.hexdigest())

        # Clean up any other files laying around
        self.secure_delete(file_name, passes=10)
        self.secure_delete(key_file, passes=10)

        return True

    def ls(self):
        """
        :return:
        """
        bucket = self.s3.get_bucket(self.__secrets_bucket_prefix__ + self.environment)
        prefix = self._build_prefix()[self.name]

        print "Contents of {0}/{1}:".format(bucket.name, prefix)
        print "----------------------------------------"
        for key in bucket.list(prefix):
            print key.name.replace(prefix, '')

    def secure_delete(self, path, passes=1):
        """
        :param path: Path to object to securely wipe
        :param passes: Number of passes
        :return:
        """

        retcode = 0

        # If the file doesn't exist we'll just silently exit
        if not open(path, "r"):
            return

        try:
            retcode = subprocess.call("shred -u -n " + str(passes) + " " + path, shell=True)
        except OSError as e:
            print "[-] Error shredding temp data key file {0}: {1}".format(path, retcode)
            print e
            return

        return

    def setup(self):
        """
        Generates a data key for a cluster and places the ciphertext in s3.
        :return: True or False
        """

        # Check for the existence of a secrets file for this cluster before proceeding.
        # This is a good indication that the setup process has already been completed.
        if self.exists_on_s3(self.name + ".json"):
            print "[-] This cluster has already been setup."
            sys.exit(2)

        # Build alias
        key_id = ""
        name = 'alias/cluster/' + self.name + '-' + self.environment

        # Find the cluster's master key and grab the key id
        response = self.kms.list_aliases()
        print "[+] Connected to region: {0}".format(self.region)
        for alias in response.get("Aliases"):
            if name == alias[u'AliasName']:
                self.recycle_key = 1
                key_id = alias[u'TargetKeyId']
                print "[+] Using master key {0}".format(key_id)
                time.sleep(2)

        if not key_id:
            print "[-] No master key found for the cluster. Please set this up in Terraform and try again."
            sys.exit(2)

        # Next we'll need to generate a data key to use for encrypting files. We'll also want to store the
        # cipherBlob returned from the API in our secrets master file.
        try:
            response = self.kms.generate_data_key(key_id, key_spec=self.__key_spec__)
        except Exception as e:
            print "[-] Error:"
            print "{0}".format(e)
            return

        ciphertextblob = response[u'CiphertextBlob']

        # Store the cluster name, and CiphertextBlob in the master secrets file. in json format with base64 key
        base64_ciphertextblob = base64.b64encode(ciphertextblob)
        json_data = {self.name: {'CiphertextBlob': base64_ciphertextblob}}

        try:
            if not os.path.exists(self.__secrets_dir__):
                os.makedirs(self.__secrets_dir__)
            with open(self.__secrets_dir__ + self.name + ".json", 'w') as outfile:
                json.dump(json_data, outfile)
        except Exception as e:
            print "[-] Error writing to secrets file {0}".format(self.__secrets_dir__ + self.name + ".json")
            print "{0}".format(e)
            return

        print "[+] Wrote secrets to master cluster file {0}".format(self.__secrets_dir__ + self.name + ".json")

        # Upload the secrets file to the s3 bucket
        self.upload_to_s3(self.__secrets_dir__ + self.name + ".json")


    def setup_vhosts(self):
        """
        Generates a data key for a cluster vhosts file and places the ciphertext in s3.
        :return: True or False
        """

        # Check for the existence of a vhosts secrets file for this cluster before proceeding.
        # This is a good indication that the setup process has already been completed.
        if self.exists_on_s3(self.name + "-vhosts.json"):
            print "[-] The cluster vhosts have already been setup."
            sys.exit(2)

        # Build alias
        key_id = ""
        name = 'alias/cluster/' + self.name + '-' + self.environment + '/vhost-key'

        # Find the cluster's master key and grab the key id
        response = self.kms.list_aliases()
        print "[+] Connected to region: {0}".format(self.region)
        for alias in response.get("Aliases"):
            if name == alias[u'AliasName']:
                self.recycle_key = 1
                key_id = alias[u'TargetKeyId']
                print "[+] Using master key {0}".format(key_id)
                time.sleep(2)

        if not key_id:
            print "[-] No master vhost key found for the cluster. Please set this up in Terraform and try again."
            sys.exit(2)

        # Next we'll need to generate a data key to use for encrypting files. We'll also want to store the
        # cipherBlob returned from the API in our secrets master file.
        try:
            response = self.kms.generate_data_key(key_id, key_spec=self.__key_spec__)
        except Exception as e:
            print "[-] Error:"
            print "{0}".format(e)
            return

        ciphertextblob = response[u'CiphertextBlob']

        # Store the cluster name, and CiphertextBlob in the master secrets file. in json format with base64 key
        base64_ciphertextblob = base64.b64encode(ciphertextblob)
        json_data = {self.name: {'CiphertextBlob': base64_ciphertextblob}}

        try:
            if not os.path.exists(self.__secrets_dir__):
                os.makedirs(self.__secrets_dir__)
            with open(self.__secrets_dir__ + self.name + "-vhosts.json", 'w') as outfile:
                json.dump(json_data, outfile)
        except Exception as e:
            print "[-] Error writing to secrets file {0}".format(self.__secrets_dir__ + self.name + "-vhosts.json")
            print "{0}".format(e)
            return

        print "[+] Wrote secrets to master cluster file {0}".format(self.__secrets_dir__ + self.name + "-vhosts.json")

        # Upload the secrets file to the s3 bucket
        self.upload_to_s3(self.__secrets_dir__ + self.name + "-vhosts.json")


    def upload(self, file_name):
        """
        Encrypts and uploads a file to a cluster's bucket/prefix on s3.
        :param file_name: Name of the file to upload.
        :return:
        """
        # Get the cluster's data key from KMS
        temp_data_key = self._get_data_key()

        if temp_data_key:
            # AES-256 encrypt the file
            self.encrypt_file(file_name, temp_data_key)

            # Upload the file to s3
            self.upload_to_s3("/dev/shm/" + os.path.basename(file_name) + ".enc")

            # Remove the file from /dev/shm securely
            self.secure_delete("/dev/shm/" + os.path.basename(file_name) + ".enc", 10)

            # Return the sha256sum of the original file for use in Chef's s3_file resource
            the_file = open(file_name, "r")
            file_data = the_file.read()
            file_sha256_checksum = sha256(file_data)
            the_file.close()

            print "[+] sha256sum for {0} is {1}".format(file_name, file_sha256_checksum.hexdigest())
        else:
            print "[-] Error uploading the file, data key doesn't exist."

        return


    def upload_vhosts(self, file_name):
        """
        Encrypts and uploads a file to a cluster's bucket/prefix on s3.
        :param file_name: Name of the file to upload.
        :return:
        """
        # Get the cluster's vhost data key from KMS
        temp_data_key = self._get_vhost_data_key()

        # Return the sha256sum of the original file for use in Chef's s3_file resource
        the_file = open(file_name, "r")
        file_data = the_file.read()
        file_sha256_checksum = sha256(file_data)
        the_file.close()

        if temp_data_key:
            # AES-256 encrypt the file
            self.encrypt_file(file_name, temp_data_key)

            # Upload the file to s3
            # This will eventually be updated when upload_to_s3 is reworked to allow for more dynamic prefixing
            file_name = "/dev/shm/" + os.path.basename(file_name) + ".enc"
            f = open(file_name, "r")
            path = "vhost/" + self.environment + '/' + self.name + "/" + os.path.basename(file_name)
            bucket = self.s3.get_bucket(self.__secrets_bucket_prefix__ + self.environment)
            k = Key(bucket)
            k.name = path

            try:
                k.set_contents_from_file(f)
            except Exception as e:
                print "[-] Error uploading file to s3"
                print e

            print "[+] Uploaded {0}".format("s3://" + self.__secrets_bucket_prefix__ + self.environment + "/" + path)

            print "[+] sha256sum for {0} is {1}".format(file_name, file_sha256_checksum.hexdigest())

            # Remove the file from /dev/shm securely
            self.secure_delete("/dev/shm/" + os.path.basename(file_name), 10)



        return True

    def pkcs7_unpad(self, text):
        """
        Remove the PKCS#7 padding from a text string
        """
        nl = len(text)
        val = int(binascii.hexlify(text[-1]), 16)
        if val > self.k:
            raise ValueError('Input is not padded or padding is corrupt')

        l = nl - val
        return text[:l]

    def pkcs7_pad(self, text):
        """
        Pad an input string according to PKCS#7
        """
        l = len(text)
        output = StringIO.StringIO()
        val = self.k - (l % self.k)
        for _ in xrange(val):
            output.write('%02x' % val)

        return text + binascii.unhexlify(output.getvalue())

    def upload_to_s3(self, file_name):
        """
        Uploads file to an s3 bucket
        :param file_name: Full path to the local file name.
        :return:
        """
        f = open(file_name, "r")

        # If this is a vhosts file we'll alter the path accordingly.
        # TODO: add proper vhosts patch
        if ("-vhosts.json" in file_name) or ("vhosts.conf" in file_name):
            path = "vhost/" + self.environment + '/' + self.name + "/" + os.path.basename(file_name)
        else:
            path = self._build_prefix()[self.name] + os.path.basename(file_name)

        bucket = self.s3.get_bucket(self.__secrets_bucket_prefix__ + self.environment)
        k = Key(bucket)
        k.name = path

        try:
            k.set_contents_from_file(f)
        except Exception as e:
            print "[-] Error uploading file to s3"
            print "{0}".format(e)

        print "[+] Uploaded {0}".format("s3://" + self.__secrets_bucket_prefix__ + self.environment + "/" + path)

        return


def main():
    parser = argparse.ArgumentParser(description='kms3.py ',
                                     formatter_class=RawTextHelpFormatter)
    subparsers = parser.add_subparsers(title='operations', help='Available operations')

    edit_parser = subparsers.add_parser('edit',
                                        help='Edit an KMS encrypted file on s3. WARNING: This is not intended for '
                                             'binaries.')
    edit_parser.set_defaults(operation='edit')
    edit_parser.add_argument('--name', help='Name of the cluster.', required=True)
    edit_parser.add_argument('--file', help='Name of the file.', required=True)
    edit_parser.add_argument('--env', help='Name of the environment.', required=True)
    edit_parser.add_argument('--region', help='AWS region. Defaults to the region the script runs from.',
                             required=False)

    get_key_parser = subparsers.add_parser('get-key',
                                           help='Downloads the data key for a cluster and stores it in /dev/shm.')
    get_key_parser.set_defaults(operation='get-key')
    get_key_parser.add_argument('--name', help='Name of the cluster.',
                                required=True)
    get_key_parser.add_argument('--env', help='Name of the environment. Defaults to "dev" for safety.', required=False)
    get_key_parser.add_argument('--region', help='AWS region. Defaults to the region the script runs from.',
                                required=False)

    get_vhost_parser = subparsers.add_parser('get-vhosts', help='Downloads the apache virtualhost config for the cluster.')
    get_vhost_parser.set_defaults(operation='get-vhosts')
    get_vhost_parser.add_argument('--name', help='Name of the cluster.',
                               required=True)
    get_vhost_parser.add_argument('--env', help='Name of the environment.', required=True)
    get_vhost_parser.add_argument('--region', help='AWS region. Defaults to the region the script runs from.',
                                required=False)

    ls_parser = subparsers.add_parser('ls', help='List secrets files for the specified cluster.')
    ls_parser.set_defaults(operation='ls')
    ls_parser.add_argument('--name', help='Name of the cluster.',
                           required=True)
    ls_parser.add_argument('--env', help='Name of the environment. Defaults to "dev" for safety.', required=False)
    ls_parser.add_argument('--region', help='AWS region. Defaults to the region the script runs from.',
                           required=False)

    setup_parser = subparsers.add_parser('setup',
                                         help='Set up a new cluster for KMS general secrets storage. Creates a data key, '
                                              'and s3 bucket prefix for the specified cluster.')
    setup_parser.set_defaults(operation='setup')
    setup_parser.add_argument('--name', help='Name of the cluster.',
                              required=True)
    setup_parser.add_argument('--env', help='Name of the environment.', required=True)
    setup_parser.add_argument('--region', help='AWS region. Defaults to the region the script runs from.',
                              required=False)
    setup_vhosts__parser = subparsers.add_parser('setup-vhosts',
                                                 help='Set up a new cluster for KMS encrypted VHOSTS storage. '
                                                      'Creates a data key, and s3 bucket prefix for the specified cluster.')
    setup_vhosts__parser.set_defaults(operation='setup-vhosts')
    setup_vhosts__parser.add_argument('--name', help='Name of the cluster.',
                                      required=True)
    setup_vhosts__parser.add_argument('--env', help='Name of the environment.', required=True)
    setup_vhosts__parser.add_argument('--region', help='AWS region. Defaults to the region the script runs from.',
                                      required=False)
    upload_parser = subparsers.add_parser('upload', help='Encrypts and uploads the specified file to the specified '
                                                         'cluster s3 bucket/prefix.')
    upload_parser.set_defaults(operation='upload')
    upload_parser.add_argument('--name', help='Name of the cluster.',
                               required=True)
    upload_parser.add_argument('--file', help='Full path of the local file to upload.', required=True)
    upload_parser.add_argument('--env', help='Name of the environment. Defaults to "dev" for safety.', required=True)
    upload_parser.add_argument('--region', help='AWS region. Defaults to the region the script runs from.',
                               required=False)

    upload_vhosts_parser = subparsers.add_parser('upload-vhosts', help='Encrypts and uploads the specified vhosts file to the specified cluster s3 bucket/prefix.')
    upload_vhosts_parser.set_defaults(operation='upload-vhosts')
    upload_vhosts_parser.add_argument('--name', help='Name of the cluster.',
                               required=True)
    upload_vhosts_parser.add_argument('--file', help='Full path of the local vhosts file to upload. WARNING: THIS WILL OVERWRITE THE vhosts.conf FILE FOR THE ENTIRE CLUSTER',
                                required=True)
    upload_vhosts_parser.add_argument('--env', help='Name of the environment. Defaults to "dev" for safety.', required=True)
    upload_vhosts_parser.add_argument('--region', help='AWS region. Defaults to the region the script runs from.',
                               required=False)

    args = vars(parser.parse_args())

    api = Kms3()

    # Set the environment, regional and cluster variables
    if args['env']:
        api.environment = args['env']
    if args['region']:
        api.region = args['region']
    if args['name']:
        api.name = args['name']

    if args['operation'] == "edit":
        api.edit(args['name'], args['file'])
    if args['operation'] == 'ls':
        api.ls()
    if args['operation'] == "get-key":
        if api.download_data_key():
            return True
        return False
    if args['operation'] == "get-vhosts":
        if api.get_vhosts():
            return True
        return False
    if args['operation'] == "setup":
        api.setup()
        return False
    if args['operation'] == "setup-vhosts":
        api.setup_vhosts()
        return False
    if args['operation'] == "upload":
        api.upload(args['file'])
    if args['operation'] == "upload-vhosts":
        api.upload_vhosts(args['file'])

if __name__ == "__main__":
    main()
