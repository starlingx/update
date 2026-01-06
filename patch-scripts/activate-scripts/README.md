# Activate Scripts Management

This repository manages **activate** scripts used in the patch deployment process.
They run for each patch during `software deploy activate`

## Folder Structure

```
activate-scripts/
├── 24.09.400/
│   └── 01-restart-services.sh
├── examples/
│   └── ...
└── ...
```

- `boilerplate/`:
  Contains the **default scripts**. These are the standard versions used for most software releases.

- `MM.mm.pp/`:
  Contains **version-specific scripts** to run in an specific release, copy the scripts from the examples folder and modify them if needed.

---

## Usage

### Default Case

If there is no specific folder for a given release:
- This patch will not have activation scripts.
- No need to create a version-specific directory.

### When a Script is Needed

If a patch requires an activation script, search in the examples folder and copy the related :

1. **Create a version folder** (e.g., `24.09.400/`):
    ```bash
    mkdir activate-scripts/24.09.400
    ```

2. **Copy the relevant scripts from examples folder**:
    ```bash
    cp activate-scripts/examples/<relevant-script> activate-scripts/24.09.400/
    ```

3. **Edit the scripts** in `24.09.400/` if needed.

4. **Create new scripts** in `24.09.400/` and `examples/` if needed.
Scripts names always follow the formmat `DD-name.extension`

> The scripts run in DD order
> Always check the examples folder to ensure consistency.

---

## Tips

- **Include comments** in versioned scripts, noting what the change is doing.
- Use scripts in the examples folder.
- The activate scripts runs in order of the first 2-digits at the script name.  

---

## License

Include the license in all scripts

```
Copyright (c) 2025 Wind River Systems, Inc.
SPDX-License-Identifier: Apache-2.0
```
