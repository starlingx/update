# Patch Script Overrides

This directory contains override scripts that replace patch scripts at
upload time when a matching target exists on the system.

Scripts placed here are installed to `/usr/local/usm/patch-scripts-overrides/`
during package install or upgrade, and are consumed by
`software_controller._apply_upload_script_overrides()` whenever a patch
is uploaded.

## Directory Structure

```
patch-override/
  <release>/                        # e.g. 25.09.200
    <script-name>                   # Legacy override (flat file)
    <metapackage>/                  # e.g. base, infra, networking
      <script-name>                 # Metapackage override
```

### Legacy releases (pre-metapackage)

For legacy patches, place the override script directly under the release
version directory:

```
patch-override/25.09.200/01-restart-services.py
```

At upload time this replaces:
`/opt/software/software-scripts/<release-id>_01-restart-services.py`

### Metapackage releases

For metapackage-based releases, place the override inside a subdirectory
named after the metapackage component:

```
patch-override/26.03.100/base/post-install.sh
patch-override/26.03.100/networking/pre-start.sh
```

At upload time this replaces:
`/opt/software/releases/<release>/base/host-scripts/post-install.sh`

## When are overrides applied?

Overrides are applied immediately after a successful patch upload
(`software upload`). The controller checks
`/usr/local/usm/patch-scripts-overrides/<sw_release>/` for matching
scripts and copies them over the extracted originals.

## Important notes

- Scripts must be executable (chmod is applied automatically at install time).
- Only files whose target already exists on the system are overridden;
  extra files are silently skipped.
- Overrides persist across controller restarts since they live on the
  root filesystem.
- Overrides scripts are propagated to the subclouds during prestage.
