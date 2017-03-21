aws-tools
======================

My personal set of tools for working with AWS.

AWS Tools Catalog
----------------------

This repo contains the following tools for working with Amazon Web Services.

- [amitool.py] - This is a tool for working with AMI images.
    - It has search and delete functionality based on standard regex patterns.
    - It also has orphan search and delete functionality to look for AMI images with orphaned snapshots.
- [asgard-deploy.py] - This is a deployment script for the Netflix Asgard project. You can use this in conjuction with a Jenkins or other
  CD (continuous deployment) pipeline to automate the deployments via asgard.
	- Supports automated judgment with supplied test parameteres.
  - Supports automated rollback upon test failure.
- [kms3.py] - Tool that provides a secrets storage solution for files using Amazon S3 and KMS. The tool supports directly uploading files,
  editing files, and setting up new data keys for envelope encryption.
    - Works in conjuction with my custom Terraform module and Chef recipe as a unified secrets storage solution.
    - Can be used as a seamless binary/ascii secrets storage solution.
- [mass-asg-rebuild.py] - Deprecated tool that pre-dates packer.
    - Automatically locates autoscaling enabled clusters in ASGARD, builds and bootstraps fresh nodes for them
      via Chef, and creates AMI images for the resulting node builds for use with ASGARD and autoscaling groups.


