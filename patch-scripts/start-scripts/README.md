# Start Scripts Management

This repository manages **pre-install** and **post-install** shell scripts used in the patch deployment process.
They run for each patch at the beginning and at the end of `software deploy start`

## Folder Structure

```
start-scripts/
├── boilerplate/
│   ├── pre-start.sh
│   └── post-start.sh
├── 24.09.300/
│   ├── pre-start.sh
│   └── post-start.sh
└── ...
```

- `boilerplate/`:
  Contains the **default scripts**. These are the standard versions used for most software releases.

- `MM.mm.pp/`:
  Contains **version-specific scripts**, only when changes are required that differ from the boilerplate.

---

## Usage

### Default Case

If the pre and post start steps remain unchanged:
- Use the scripts in the `boilerplate/` folder.
- No need to create a version-specific directory.

### When Customization Is Needed

If any version of the software requires changes to the install scripts:

1. **Create a version folder** (e.g., `24.09.300/`):
    ```bash
    mkdir start-scripts/24.09.300
    ```

2. **Copy the boilerplate scripts**:
    ```bash
    cp start-scripts/boilerplate/*.sh start-scripts/24.09.300/
    ```

3. **Edit the scripts** in `24.09.300/` as needed.

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
