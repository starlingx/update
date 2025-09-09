# Install Scripts Management

This repository manages **pre-install** and **post-install** shell scripts used in the patch deployment process.
They run for each patch at the beginning and at the end of `software deploy host` for both inservice and reboot required patches.

## Folder Structure

```
install-scripts/
├── boilerplate/
│   ├── pre-install.sh
│   └── post-install.sh
├── 24.09.400/
│   ├── pre-install.sh
│   └── post-install.sh
├── examples/
└── ...
```

- `boilerplate/`:
  Contains the **default scripts**. These are the standard versions used for most software releases.

- `MM.mm.pp/`:
  Contains **version-specific scripts**, only when changes are required that differ from the boilerplate.

- `examples/`:
  Contains **previous scripts examples**. Scripts used in old releases.

---

## Usage

### Default Case

If the pre and post install steps remain unchanged:
- Use the scripts in the `boilerplate/` folder.
- No need to create a version-specific directory.

### When Customization Is Needed

If any version of the software requires changes to the install scripts:

1. **Create a version folder** (e.g., `24.09.400/`):
    ```bash
    mkdir install-scripts/24.09.400
    ```

2. **Copy the boilerplate scripts**:
    ```bash
    cp install-scripts/boilerplate/*.sh start-scripts/24.09.400/
    ```

3. **Edit the scripts** in `24.09.400/` as needed.

> Always start from the boilerplate to ensure consistency.

---

## Tips

- **Include comments** in versioned scripts, noting what the change is doing.
- Use previous versions as examples of what these scripts can do.

---

## License

Include the license in all scripts

```
Copyright (c) 2025 Wind River Systems, Inc.
SPDX-License-Identifier: Apache-2.0
```
