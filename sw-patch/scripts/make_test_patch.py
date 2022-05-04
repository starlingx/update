#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
'''
Create a test patch for Debian

- fake restart script
- fake dettached signature (signature.v2)

Prereqs:
- Requires the ostree tool installed - apt-get install ostree
- export STX_BUILD_HOME
    e.g: export STX_BUILD_HOME=/localdisk/designer/lsampaio/stx-debian
- pip3 install pycryptodomex

Setup Steps:
  sudo chmod 644 $STX_BUILD_HOME/localdisk/deploy/ostree_repo/.lock
  sudo chmod 644 $STX_BUILD_HOME/localdisk/lat/std/deploy/ostree_repo/.lock
  python make_test_patch.py --prepare --repo ostree_repo --clone-repo ostree-clone

Patch Steps:
  <make some ostree changes>
  <build-image>
  rm -Rf $STX_BUILD_HOME/localdisk/deploy/delta_dir
  rm -Rf $STX_BUILD_HOME/localdisk/lat/std/deploy/delta_dir
  python make_test_patch.py --create --repo ostree_repo --clone-repo ostree-clone

'''

import argparse
import hashlib
import logging
import tarfile
import tempfile
import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

from xml.dom import minidom

sys.path.insert(0, "../cgcs-patch")
from cgcs_patch.patch_signing import sign_files


# ostree_repo location
DEPLOY_DIR = os.path.join(os.environ['STX_BUILD_HOME'], 'localdisk/lat/std/deploy')
OSTREE_REPO = os.path.join(DEPLOY_DIR, 'ostree_repo')
# Delta dir used by rsync, hardcoded for now
DELTA_DIR = 'delta_dir'

detached_signature_file = 'signature.v2'
PATCH_ID = 'PATCH_0001'
SOFTWARE_VERSION = '22.06'
patch_file =  PATCH_ID + '.patch'

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)

log = logging.getLogger('make_test_patch')


def prepare_env(name='ostree-clone'):
    '''
    Generates a copy of the current ostree_repo which is used
    to create the delta dir during patch creation
    :param name: name of the cloned directory
    '''
    log.info('Preparing ostree clone directory')
    os.chdir(DEPLOY_DIR)
    clone_dir = os.path.join(DEPLOY_DIR, name)
    if os.path.isdir(clone_dir):
        log.error('Clone directory exists {}'.format(name))
        exit(1)

    os.mkdir(clone_dir)
    current_sha = open(os.path.join(OSTREE_REPO, 'refs/heads/starlingx'), 'r').read()
    log.info('Current SHA: {}'.format(current_sha))
    log.info('Cloning the directory...')
    subprocess.call(['rsync', '-a', OSTREE_REPO + '/', clone_dir])

    log.info('Prepared ostree repo clone at {}'.format(clone_dir))


def create_delta_dir(delta_dir='delta_dir', clone_dir='ostree-clone'):
    '''
    Creates the ostree delta directory
    Contains the changes from the REPO (updated) and the cloned dir (pre update)
    :param delta_dir: delta directory name
    :param clone_dir: clone dir name
    '''
    log.info('Creating ostree delta')
    clone_dir = os.path.join(DEPLOY_DIR, clone_dir)

    if os.path.isdir(delta_dir):
        log.error('Delta dir exists {}, clean it up and try again'.format(delta_dir))
        exit(1)

    if not os.path.isdir(clone_dir):
        log.error('Clone dir not found')
        exit(1)

    subprocess.call(['rsync', '-rpgo', '--compare-dest', clone_dir, OSTREE_REPO + '/', delta_dir + '/'])
    log.info('Delta dir created')


def add_text_tag_to_xml(parent,
                        name,
                        text):
    '''
    Utility function for adding a text tag to an XML object
    :param parent: Parent element
    :param name: Element name
    :param text: Text value
    :return:The created element
    '''
    tag = ET.SubElement(parent, name)
    tag.text = text
    return tag


def gen_xml(ostree_content, file_name="metadata.xml"):
    '''
    Generate patch metadata XML file
    :param file_name: Path to output file
    '''
    top = ET.Element("patch")

    add_text_tag_to_xml(top, 'id', PATCH_ID)
    add_text_tag_to_xml(top, 'sw_version', SOFTWARE_VERSION)
    add_text_tag_to_xml(top, 'summary', 'Summary text')
    add_text_tag_to_xml(top, 'description', 'Description text')
    add_text_tag_to_xml(top, 'install_instructions', 'Install instructions text')
    add_text_tag_to_xml(top, 'warnings', 'Warnings text')
    add_text_tag_to_xml(top, 'status', 'DEV')
    add_text_tag_to_xml(top, 'unremovable', 'N')
    add_text_tag_to_xml(top, 'reboot_required', 'Y')
    add_text_tag_to_xml(top, 'apply_active_release_only', '')
    add_text_tag_to_xml(top, 'restart_script', 'Patch1_Restart_Script.sh')

    # Parse ostree_content
    content = ET.SubElement(top, 'contents')
    ostree = ET.SubElement(content, 'ostree')

    add_text_tag_to_xml(ostree, 'number_of_commits', str(len(ostree_content['commits'])))
    base_commit = ET.SubElement(ostree, 'base')
    add_text_tag_to_xml(base_commit, 'commit', ostree_content['base']['commit'])
    add_text_tag_to_xml(base_commit, 'checksum', ostree_content['base']['checksum'])

    for i, c in enumerate(ostree_content['commits']):
        commit = ET.SubElement(ostree, 'commit' + str(i + 1))
        add_text_tag_to_xml(commit, 'commit', c['commit'])
        add_text_tag_to_xml(commit, 'checksum', c['checksum'])

    add_text_tag_to_xml(top, 'requires', '')
    add_text_tag_to_xml(top, 'semantics', '')

    # print
    outfile = open(file_name, 'w')
    tree = ET.tostring(top)
    outfile.write(minidom.parseString(tree).toprettyxml(indent="  "))


def gen_restart_script(file_name):
    '''
    Generate restart script
    :param file_name: Path to script file
    '''
    # print
    outfile = open(file_name, 'w')
    r = 'echo test restart script'
    outfile.write(r)


def get_md5(path):
    '''
    Utility function for generating the md5sum of a file
    :param path: Path to file
    '''
    md5 = hashlib.md5()
    block_size = 8192
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(block_size), b''):
            md5.update(chunk)
    return int(md5.hexdigest(), 16)


def get_commit_checksum(commit_id, repo='ostree_repo'):
    '''
    Get commit checksum from a commit id
    :param commit_id
    :param repo
    '''
    # get all checksums
    cmd = 'ostree --repo={} log starlingx | grep -i checksum | sed \'s/.* //\''.format(repo)
    cksums = subprocess.check_output(cmd, shell=True).decode(sys.stdout.encoding).strip().split('\n')
    return(cksums[commit_id])


def get_commits_from_base(base_sha, repo='ostree_repo'):
    '''
    Get a list of commits from base sha
    :param base_sha
    :param repo
    '''
    commits_from_base = []

    cmd = 'ostree --repo={} log starlingx | grep commit | sed \'s/.* //\''.format(repo)
    commits = subprocess.check_output(cmd, shell=True).decode(sys.stdout.encoding).strip().split('\n')

    if commits[0] == base_sha:
        log.info('base and top commit are the same')
        return commits_from_base

    # find base and add the commits to the list
    for i, c in enumerate(commits):
        if c == base_sha:
            break
        log.info('saving commit {}'.format(c))
        # find commit checksum
        cksum = get_commit_checksum(i, repo)
        commits_from_base.append({
            'commit': c,
            'checksum': cksum
        })

    return commits_from_base

def create_patch(repo='ostree_repo', clone_dir='ostree-clone'):
    '''
    Creates a debian patch using ostree delta between 2 repos (rsync)
    :param repo: main ostree_repo where build-image adds new commits
    :param clone_dir: repo cloned before the changes
    '''
    os.chdir(DEPLOY_DIR)
    # read the base sha from the clone
    base_sha = open(os.path.join(clone_dir, 'refs/heads/starlingx'), 'r').read().strip()

    log.info('Generating delta dir')
    create_delta_dir(delta_dir=DELTA_DIR, clone_dir=clone_dir)

    # ostree --repo=ostree_repo show  starlingx | grep -i checksum |  sed 's/.* //'
    cmd = 'ostree --repo={} show starlingx | grep -i checksum | sed \'s/.* //\''.format(clone_dir)
    base_checksum = subprocess.check_output(cmd, shell=True).decode(sys.stdout.encoding).strip()

    commits = get_commits_from_base(base_sha, repo)

    if commits:
        ostree_content = {
            'base': {
                'commit': base_sha,
                'checksum': base_checksum
            },
        }
        ostree_content['commits'] = commits
    else:
        log.info('No changes detected')
        exit(0)

    log.info('Generating patch file...')
    # Create software.tar, metadata.tar and signatures
    # Create a temporary working directory
    tmpdir = tempfile.mkdtemp(prefix='patch_')
    # Change to the tmpdir
    os.chdir(tmpdir)
    tar = tarfile.open('software.tar', 'w')
    tar.add(os.path.join(DEPLOY_DIR, DELTA_DIR), arcname='')
    tar.close

    log.info('Generating xml with ostree content {}'.format(commits))
    gen_xml(ostree_content)
    tar = tarfile.open('metadata.tar', 'w')
    tar.add('metadata.xml')
    tar.close()

    log.info('Saving restart scripts (if any)')
    # TODO: verify how to handle the restart script
    gen_restart_script('Patch1_Restart_Script.sh')

    filelist = ['metadata.tar', 'software.tar']
    # Generate the signature file
    sig = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    for f in filelist:
        sig ^= get_md5(f)

    sigfile = open('signature', 'w')
    sigfile.write('%x' % sig)
    sigfile.close()

    # this comes from patch_functions   write_patch
    # Generate the detached signature
    #
    # Note: if cert_type requests a formal signature, but the signing key
    #    is not found, we'll instead sign with the 'dev' key and
    #    need_resign_with_formal is set to True.
    need_resign_with_formal = sign_files(
        filelist,
        detached_signature_file,
        cert_type=None)

    # Create the patch
    tar = tarfile.open(os.path.join(DEPLOY_DIR, patch_file), 'w:gz')
    for f in filelist:
        tar.add(f)
    tar.add('signature')
    tar.add(detached_signature_file)
    tar.add('Patch1_Restart_Script.sh')
    tar.close()

    os.chdir(DEPLOY_DIR)
    shutil.rmtree(tmpdir)

    log.info('Patch file created {} at {}'.format(patch_file, DEPLOY_DIR))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Debian make_test_patch helper")

    parser.add_argument('-r', '--repo', type=str,
                        help='Ostree repo name',
                        default=None, required=True)
    parser.add_argument('-p', '--prepare', action='store_true',
                        help='Prepare the ostree_repo clone directory, should be executed before making changes to the environment')
    parser.add_argument('-cr', '--clone-repo', type=str,
                        help='Clone repo directory name',
                        default=None, required=True)
    parser.add_argument('-c', '--create', action='store_true',
                        help='Create patch, should be executed after changes are done to the environment')

    args = parser.parse_args()

    log.info('STX_BUILD_HOME: {}'.format(os.environ['STX_BUILD_HOME']))
    log.info('DEPLOY DIR: {}'.format(DEPLOY_DIR))
    log.info('DELTA DIR: {}'.format(DELTA_DIR))

    if args.prepare:
        log.info('Calling prepare environment')
        prepare_env(args.clone_repo)
    elif args.create:
        log.info('Calling create patch')
        create_patch(args.repo, args.clone_repo)

