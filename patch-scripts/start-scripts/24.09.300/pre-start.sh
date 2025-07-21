#!/bin/bash
#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

operation="apply"

if [[ "$1" == --operation=* ]]; then
    operation="${1#*=}"
fi

echo "### Start of pre-start script ###"

if [[ "$operation" == "apply" ]]; then
    echo "Running script while applying patch"
    # Put commands to run during apply here

    ##### Put a pre-built commit instead of building one #####
    patch="24.09.300"
    ostree_feed_repo="/var/www/pages/feed/rel-24.09/ostree_repo/"
    ostree_extra_repo="/opt/software/rel-${patch}/extra/ostree_repo/"
    metadata_file="/opt/software/metadata/deploying/WRCP-${patch}-metadata.xml"

    # get commit id
    echo "Getting extra commit ID"
    extra_commit_id=$(ostree rev-parse starlingx --repo="$ostree_extra_repo")
    if [[ $? -ne 0 || -z "$extra_commit_id" ]]; then
        echo "Error: Failed to parse extra commit id"
        exit 1
    fi

    # Check if commit already exits in the feed
    echo "Getting extra checksum from commit ${extra_commit_id}"
    extra_checksum=$(ostree show "$extra_commit_id" --repo="$ostree_extra_repo" | grep "ContentChecksum:" | awk '{print $2}')
    if [[ $? -ne 0 || -z "$extra_checksum" ]]; then
        echo "Error: Failed to parse extra checksum"
        exit 1
    fi
    echo "Checking if commit with checksum ${extra_checksum} already exists in feed, if yes, quit"
    if ostree log starlingx --repo="$ostree_feed_repo" | grep -q "$extra_checksum"; then
        echo "Commit already present in feed, exiting"
        exit 0
    fi

    # Get commit message
    echo "Getting extra commit message"
    commit_msg=$(ostree show "$extra_commit_id" --repo="$ostree_extra_repo" | grep -vE '^(commit|Parent:|ContentChecksum:|Date:|<<)')
    if [[ $? -ne 0 || -z "$commit_msg" ]]; then
        echo "Error: Failed to get extra commit message"
        exit 1
    fi

    # pull and commit the new commit
    echo "Pulling and commiting"
    ostree --repo="$ostree_feed_repo" pull-local "$ostree_extra_repo" "$extra_commit_id"
    new_commit_id=$(ostree --repo="$ostree_feed_repo" commit -b starlingx --tree=ref="$extra_commit_id" -s "$commit_msg")
    if [[ $? -ne 0 || -z "$new_commit_id" ]]; then
        echo "Error: Failed to commit"
        exit 1
    fi
    echo "Commited patch ${patch} with id: ${new_commit_id}"

    # get parent commit id
    echo "Getting parent commit ID"
    parent_commit_id=$(ostree log starlingx --repo="$ostree_feed_repo" | grep "Parent:" | head -n 1 | awk '{print $2}')
    if [[ $? -ne 0 || -z "$parent_commit_id" ]]; then
        echo "Error: Failed to get parent commit"
        exit 1
    fi

    # Edit metadata file
    echo "Editing commit in metadata file. Commit: ${new_commit_id}, parent: ${parent_commit_id}"
    bak_file="${metadata_file}.bak"
    cp -- "$metadata_file" "$bak_file"
    if sed -i '/<\/patch>/c\
    <contents>\
        <ostree>\
            <base>\
                <commit>'"${parent_commit_id}"'</commit>\
                <checksum />\
            </base>\
            <commit1>\
                <commit>'"${new_commit_id}"'</commit>\
                <checksum />\
            </commit1>\
            <number_of_commits>1</number_of_commits>\
        </ostree>\
    </contents>\
</patch>' "$metadata_file"; then
        rm -f "$bak_file"
        echo "Edited metadata file with success"
    else
        echo "Error: Failed editing metadata"
        mv -f "$bak_file" "$metadata_file"
        exit 1
    fi
    ##### Put a pre-built commit instead of building one #####

else
    echo "Running script while removing patch"
    # Put commands to run during remove here
fi

echo "### End of pre-start script ###"
