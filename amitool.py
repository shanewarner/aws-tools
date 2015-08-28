#!/usr/bin/env python
"""
amitool.py provides a toolset for common AMI operations.

Currently only connects to the region from which it is run.
"""
__author__ = 'shane@darkstarnet.net'

import sys
import re
import boto
import boto.ec2.autoscale
import argparse
from argparse import RawTextHelpFormatter


class Ami(object):
    def __init__(self):
        try:
            self.ec2 = boto.connect_ec2()
            self.asg = boto.connect_autoscale()
            self.in_use_amis = [launch_config.image_id for launch_config in self.asg.get_all_launch_configurations()]

        except Exception as e:
            print e
            sys.exit(2)

    def create(self, instance_id, name, desc):
        """
        Creates an AMI image.
        :param instance_id: Instance ID of the desired instance to image.
        """
        try:
            ami = self.ec2.create_image(instance_id, name, description=desc)
        except Exception as e:
            print e
            return -1

        print "{0} => {1}".format(instance_id, ami)
        return

    def delete(self, ami_):
        """
        Deletes the supplied ami-id.
        :param ami: Ami ID. Ex. ami-4234563
        """
        try:
            self.ec2.deregister_image(ami_, delete_snapshot=True)
            print "Deleted {0}".format(ami_)
        except Exception as e:
            print "Failed to delete {0}".format(ami_)
            print e
            return -1

        return

    def delete_snapshot(self, snap_id):
        """
        Deletes
        :param snap_id: Snapshot ID. Ex. snap-123456
        """
        try:
            self.ec2.delete_snapshot(snap_id)
            print "Deleted {0}".format(snap_id)
        except Exception as e:
            print "Failed to delete {0}".format(snap_id)
            print e
            return -1

        return

    def in_use(self, ami_id):
        """
        Checks if the specified AMI is in use by an autoscaling group launch config.
        :param ami_: AMI ID
        :return: True or False
        """
        if ami_id in self.in_use_amis:
            return True

        return False

    def search(self, pattern):
        """
        Builds a list of ami's based on the supplied regex pattern
        :param pattern: Regular expression pattern to search on. Ex. chef-autoscale-2014-0[67]-01
        """
        images = []
        count = 0
        space = 0
        snap_id = ""

        try:
            amis = self.ec2.get_all_images(owners='self')
        except Exception as e:
            print "Failed to get AMI's."
            print e
            return -1

        try:
            snapshots = self.ec2.get_all_snapshots(owner='self')
        except Exception as e:
            print "Failed to get snapshots."
            print e
            return -1

        for ami_ in amis:
            if ami_ and (re.search(pattern, str(ami_.description)) or re.search(pattern, str(ami_.name))):
                count += 1
                print "{0:s} => {1:s} {2:s}".format(ami_.id, ami_.name, ami_.description)
                for device, volume in ami_.block_device_mapping.iteritems():
                    if volume.snapshot_id:
                        snap_id = volume.snapshot_id

                images.append((ami_.id, ami_.name, ami_.description, snap_id))

        for snapshot in snapshots:
            for ami_id, ami_name, ami_description, snap_id in images:
                if snapshot.id == snap_id:
                    size = snapshot.volume_size
                    space += size

        print "-----------------------"
        print "        SUMMARY        "
        print "-----------------------"
        print "total amis found: {0} total space occupied: {1}GB".format(count, space)
        return images

    def find_orphans(self):
        """
        Finds orphaned AMI snapshots. Returns a list.
        """
        orphans = []
        space = 0
        count = 0
        for snapshot in self.ec2.get_all_snapshots(owner='self'):
            if snapshot.description:
                match = re.search(r'ami-[0-9A-Fa-f]+', snapshot.description)
                if match:
                    try:
                        ami = self.ec2.get_image(match.group())
                    except Exception as e:
                        ami = None

                    if not ami:
                        orphans.append((snapshot.id, match.group()))
                        space = space+snapshot.volume_size
                        count += 1
                        print "orphaned ami snapshot: {0:s} => {1:s} {2}GB".format(snapshot.id, match.group(),
                                                                                   snapshot.volume_size)

        print "-----------------------"
        print "        SUMMARY        "
        print "-----------------------"
        print "total orphans: {0} total space: {1}GB".format(count, space)
        return orphans


def main():

    parser = argparse.ArgumentParser(description='amitool.py provides a toolset for common AMI operations.', formatter_class=RawTextHelpFormatter)
    subparsers = parser.add_subparsers(title='operations', help='Available operations')

    create_parser = subparsers.add_parser('create', help='Create an AMI image.')
    create_parser.set_defaults(operation='create')
    create_parser.add_argument('--instance-id', help='Instance-id to create an AMI from.', required=True)
    create_parser.add_argument('--name', help='Image name.', required=True)
    create_parser.add_argument('--desc', help='Description of the image.', default="Amitool created image.")
    delete_parser = subparsers.add_parser('delete', help='Delete an AMI image and associated snapshot.')
    delete_parser.set_defaults(operation='delete')
    delete_parser.add_argument('ami_id', action='store', help='ami-id to delete.')

    search_parser = subparsers.add_parser('search', help='Search AMIs based on regex, or search for orphaned '
                                                         'AMI snapshots.'
                                                         '\nWARNING: If --delete is specified, found objects '
                                                         'will be deleted.')
    search_parser.set_defaults(operation='search')
    search_parser.add_argument('mode', choices=['ami', 'orphan'])
    search_parser.add_argument('--regex', help='Regex pattern for AMI search.', default='.*')
    search_parser.add_argument('--delete', action='store_true', help='WARNING: This flag will delete objects returned by search.')
    search_parser.add_argument('--force', action='store_true', help='WARNING: This flag will FORCE deletion of AMI images that are in use by autoscaling groups.')

    args = vars(parser.parse_args())
    api = Ami()

    if args['operation'] == 'create':
        api.create(args['instance_id'], args['name'],args['desc'])
    if args['operation'] == 'delete':
        print "Deleting {0}".format(args['ami_id'])
        api.delete(args['ami_id'])
    if args['operation'] == "search":
        if args['mode'] == 'ami':
            print "Finding images matching regex: {0}".format(args['regex'])
            images = api.search(args['regex'])
            if images and args['delete']:
                confirmation = raw_input('Confirm DELETE of found images (Y/N): ')
                if confirmation == 'Y':
                    for ami_id, ami_name, ami_description, snap_id in images:
                        if args['force']:
                            api.delete(ami_id)
                        else:
                            if api.in_use(ami_id):
                                print "ERROR: Not deleting {0} as it is in use by an active launch config. Use --force to force deletion.".format(ami_id)
                                continue
                            else:
                                api.delete(ami_id)

        if args['mode'] == 'orphan':
            print "Finding orphans"
            orphans = api.find_orphans()
            if orphans and args['delete']:
                confirmation = raw_input('Confirm DELETE of found orphans (Y/N): ')
                if confirmation == 'Y':
                    for snap_id, ami_id in orphans:
                        api.delete_snapshot(snap_id)

if __name__ == "__main__":
    main()
