#!/bin/python3
#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Creates the Debian patching environment workspace

01 - Setup env
02 - Download binaries and sources
03 - Build all pkgs and image or rsync data from source build (build-avoidance)
04 - replace build ostree_repo by ostree_repo_source

Prereqs:
# Build pre reqs for Minikube or Kubernetes
# The script uses env variables to init the repo and build the environment
# Env variables to export prior to running the script:
    export PROJECT="stx-patch"
    export STX_BUILD_HOME="/localdisk/designer/${USER}/${PROJECT}"
    export MY_REPO="${STX_BUILD_HOME}/repo/cgcs-root"
    # Kubernetes:
    export STX_PLATFORM="kubernetes"
    export STX_K8S_NAMESPACE="${USER}-${PROJECT}"
    export KUBECONFIG="/build/.kube/config"
    # Minikube
    export STX_PLATFORM="minikube"

    # Manifest and branch
    export MANIFEST_URL="https://opendev.org/starlingx/manifest.git"
    export MANIFEST_BRANCH="master"
    export MANIFEST="default.xml"

Examples:
# Create workspace and build all packages
./make_patching_workspace.py --ostree-source /path_to_source_build/ostree_repo --build-all

# Create workspace and rsync source build data (aptly/mirrors)
# source dir can be a source build home or a directory that contains a copy of aptly and mirrors,
# these directories will be copied into the patch build environment
./make_patching_workspace.py --ostree-source=/path_to_ostree/ostree_repo/ \
    --build-avoidance --build-avoidance-dir=/path_to_source_dir

"""
import argparse
import logging
import os
import subprocess
import sys
import time

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
log = logging.getLogger('make_patching_workspace')


def run_cmd(cmd):
    '''
    Run a cmd and return
    param command: string representing the command to be executed
    '''
    log.debug("Running: %s", cmd)
    return subprocess.run(
        cmd,
        shell=True,
        executable='/bin/bash',
        check=True)


class PatchEnv(object):
    """
    Patch Environment
    """
    def __init__(self):
        try:
            self.project = os.environ.get("PROJECT")
            self.build_home = os.environ.get("STX_BUILD_HOME")
            self.repo = os.path.join(self.build_home, "repo")
            self.repo_subdir = os.path.join("localdisk/designer", os.environ.get("USER"), self.project)
            self.manifest_url = os.environ.get("MANIFEST_URL")
            self.manifest_branch = os.environ.get("MANIFEST_BRANCH")
            self.manifest = os.environ.get("MANIFEST")
        except Exception:
            log.error("Error while initializing PatchEnv")
            sys.exit(1)

    def __str__(self):
        return str(self.__dict__)

    def clean_gits(self):
        """
        Clean the repo gits if reusing the environment
        """
        log.info("Git - cleaning changes that would prevent checkout")
        cmd = "repo forall -c 'echo $REPO_PATH'"
        repos = subprocess.check_output(cmd, shell=True).decode(sys.stdout.encoding).strip().split('\n')
        for r in repos:
            log.info("cleaning %s", r)
            os.chdir(r)
            run_cmd("git rebase --abort >/dev/null 2>&1 || :")
            run_cmd("git am --abort >/dev/null 2>&1 || :")
            run_cmd("git clean -d -f")
            run_cmd("git checkout .")
            # Change back to root_dir
            os.chdir(self.repo)

    def create_build_dirs(self):
        """
        Create build env directories
        """
        os.makedirs(self.build_home)
        os.chdir(self.build_home)
        os.makedirs("aptly")
        os.makedirs("mirrors")
        os.makedirs(self.repo_subdir)
        os.symlink(self.repo_subdir, self.repo)

    def repo_init_sync(self):
        """
        Init repo and sync
        """
        os.chdir(self.repo)
        log.info("Repo init")
        cmd = f"repo init -u {self.manifest_url} -b {self.manifest_branch} -m {self.manifest}"
        run_cmd(cmd)
        log.info("Repo Sync")
        cmd = "repo sync"
        run_cmd(cmd)

    def setup_stx(self):
        """
        Setup stx.conf file
        """
        cmd = f'''
            source import-stx
            stx config --add builder.myuname $(id -un)
            stx config --add builder.uid $(id -u)

            stx config --add project.gituser {os.environ.get("USER")}
            stx config --add project.gitemail {os.environ.get("EMAIL")}

            stx config --add project.name {self.project}

            stx config --show
        '''
        if run_cmd(cmd).returncode != 0:
            raise Exception("Error while setting up stx.conf")

    def init_stx(self):
        """
        Init STX and rebuild the containers
        """
        cmd = '''
            source import-stx
            stx -d control stop
            ./stx-init-env --rebuild --cache
            stx -d control status
        '''
        if run_cmd(cmd).returncode != 0:
            raise Exception("Error while initializing the containers")

    def verify_stx_status(self):
        """
        Verify if containers are running
        5 STX containers should be running otherwise it raises an exception
        """
        cmd = '''
            source import-stx
            stx -d control status | grep -i running | wc -l
        '''
        for count in range(3):
            log.info("Checking stx status - %s", count)
            ret = subprocess.check_output(cmd, shell=True, executable='/bin/bash').decode(sys.stdout.encoding).strip()
            log.info("Total running containers %s", ret)
            if ret == '5':
                return

            log.info("Waiting...")
            time.sleep(30)
            if count == 2:
                raise Exception("Failed to start containers")

    def run_downloader(self):
        """
        Download source and binary dependencies
        """
        cmd = '''
            source import-stx
            stx -d shell --no-tty -c "downloader -b -s -B std,rt"
        '''
        ret = run_cmd(cmd)
        log.info("Downloader return code %s", ret.returncode)
        if ret.returncode != 0:
            raise Exception("Error while downloading dependencies")

    def build_all_pkgs(self):
        """
        Build all packages
        """
        # stx build world
        cmd = '''
            source import-stx
            stx -d shell --no-tty -c "build-pkgs -c -a"
        '''
        ret = run_cmd(cmd)
        log.info("Build pkgs return code %s", ret.returncode)
        if ret.returncode != 0:
            raise Exception("Failed to build packages")

    def build_image(self):
        """
        Build image
        """
        cmd = '''
            source import-stx
            stx -d shell --no-tty -c "build-image"
        '''
        ret = run_cmd(cmd)
        log.info("Build image return code %s", ret.returncode)
        if ret.returncode != 0:
            raise Exception("Failed to build image")


def init_stx_containers():
    """
    Init and verify if containers are running
    """
    try:
        os.chdir(os.path.join(patch_env.repo, "stx-tools"))
        patch_env.init_stx()
        patch_env.verify_stx_status()
    except Exception:
        log.exception("STX Containers not started")
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Debian make_patching_workspace")

    parser.add_argument('--ostree-source', type=str, default=None, required=True,
                        help='Ostree from Source Build path (local or remote)')
    parser.add_argument('--build-avoidance', action="store_true", help="Use build avoidance")
    parser.add_argument('--build-avoidance-dir', type=str, default=None,
                        help='STX_BUILD_HOME path for the build avoidance (source build)')
    parser.add_argument('--build-all', action="store_true", help="build all pkgs and image, ignored if build-avoidance")

    args = parser.parse_args()

    patch_env = PatchEnv()
    log.info("Environment: %s", patch_env)

    deploy_dir = os.path.join(patch_env.build_home, "localdisk", "lat", "std", "deploy")
    ostree_repo_build = os.path.join(deploy_dir, "ostree_repo")

    # Setup env
    if not os.path.isdir(patch_env.build_home):
        log.info("STX Build Home does not exist, creating stx env")
        patch_env.create_build_dirs()
        patch_env.repo_init_sync()
        log.info("sync done, setting up STX")
        os.chdir(os.path.join(patch_env.repo, "stx-tools"))
        # Setup the stx.conf file
        patch_env.setup_stx()
    else:
        log.info("Re-initializing environment %s", patch_env.project)
        os.chdir(patch_env.repo)
        patch_env.clean_gits()
        patch_env.repo_init_sync()
        os.chdir(os.path.join(patch_env.repo, "stx-tools"))

    if args.build_avoidance:
        log.info("Build avoidance")
        if not args.build_avoidance_dir:
            raise Exception("Build avoidance dir must be provided")

        # Copies aptly and mirrors from source BUILD or source directory that contains a copy of aptly and mirrors
        os.chdir(patch_env.build_home)
        log.info("Syncing aptly and mirrors")
        if os.path.isdir("aptly") or os.path.isdir("mirrors"):
            log.info("Aptly or Mirrors already exist, trying to clean it up with sudo, it may ask for password")
            command = """
                sudo rm -rf aptly
                sudo rm -rf mirrors
            """
            run_cmd(command)

        log.info("Syncing aptly and mirrors from build avoidance directory")
        command = f"""
            rsync -av {args.build_avoidance_dir}/aptly/ aptly
            rsync -av {args.build_avoidance_dir}/mirrors/ mirrors
        """
        run_cmd(command)
        init_stx_containers()

    else:
        init_stx_containers()
        # Downloader
        log.info("Running downloader")
        patch_env.run_downloader()

        if args.build_all:
            # Build pkgs
            log.info("Building packages")
            patch_env.build_all_pkgs()

            # Build image
            log.info("Building image")
            patch_env.build_image()

    # replace ostree_repo by ostree_repo_source
    log.info("Creating deploy dir")
    os.makedirs(deploy_dir, exist_ok=True)
    log.info("Copying ostree from Source Build into patch build env")
    if not os.path.isdir(deploy_dir):
        raise Exception("deploy dir not found, verify if build-image completed successfully.")

    os.chdir(deploy_dir)
    if os.path.isdir(ostree_repo_build):
        # This may prompt for sudo password
        log.info("Trying to move ostree_repo using sudo")
        subprocess.call(["sudo", "mv", "ostree_repo", "ostree_repo_build"])

    # Copy from Source
    log.info("Copying ostree_repo from Source Build %s to %s to", args.ostree_source, ostree_repo_build)
    if subprocess.call(["rsync", "-av", args.ostree_source + "/", ostree_repo_build]):
        raise Exception("Error while copying the source ostree.")

    log.info("Environment is ready for patching!")
