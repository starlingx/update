====================================================
Unified Software Management API v1
====================================================

Manage the deployment of hosts with the StarlingX Unified Software Management API.
This includes for release upload, show, list and deletion and for deploy this includes
abort, activate, activate-rollback, complete, delete, host, host-list, host-rollback, list,
precheck, show and start.

The typical port used for the Unified Software Management REST API is 5493. However, proper
technique would be to look up the software service endpoint, named as 'usm', in Keystone. Additionally,
HAProxy port used for this service is 5497.

------------
API versions
------------

******************************************************************************
Lists information about all StarlingX Unified Software Management API versions
******************************************************************************

.. rest_method:: GET / POST / DELETE

**Normal response codes**

200

**Error response codes**

internalServerError (500)

::

   "StarlingX Unified Software Management API, Available versions: /v1"


--------
Software
--------

********************************
Lists all releases in the system
********************************

.. rest_method:: GET /v1/release

Supported query values are ``available``, ``committed``,  ``deployed``, ``deploying`` or ``synced``.

**Normal response codes**

200

**Error response codes**

internalServerError (500)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "release (Optional)", "query", "xsd:string", "Specifies the release to be queried."
   "show (Optional)", "query", "xsd:string", "Specifies the release state to be queried."

**Example Endpoint with parameters**

::

  /v1/release?show=available&release=starlingx-0.0.0

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "release_id", "plain", "xsd:string", "The release identification name."
   "state", "plain", "xsd:string", "The current release state."
   "sw_version", "plain", "xsd:string", "The software version for which the deploy is intended."
   "component", "plain", "xsd:string", "The component present in the release."
   "status", "plain", "xsd:string", "The status of the release."
   "unremovable", "plain", "xsd:string", "The flag that indicates if release is unremovable."
   "summary", "plain", "xsd:string", "A brief summary of the release."
   "description", "plain", "xsd:string", "The description of any updates present in this release."
   "install_instructions", "plain", "xsd:string", "Instructions on how to install the release."
   "warnings", "plain", "xsd:string", "Any warnings associated with the usage of the release."
   "reboot_required", "plain", "xsd:bool", "The flag that indicates if release is reboot required."
   "prepatched_iso", "plain", "xsd:bool", "The flag that indicates if release is a prepatched iso."
   "requires", "plain", "xsd:list", "A list of patch ids required for this patch release to be installed."
   "packages", "plain", "xsd:list", "A list of packages present in the release."

::

    [
       {
          "release_id":"starlingx-0.0.0",
          "state":"deployed",
          "sw_version":"0.0.0",
          "component":null,
          "status":"REL",
          "unremovable":true,
          "summary":"STX 0.0 GA release",
          "description":"STX 0.0 major GA release",
          "install_instructions":"",
          "warnings":"",
          "reboot_required": true,
          "prepatched_iso": true,
          "requires":[
           ],
          "packages":[
           ]
       }
    ]

***************************************************
Shows detailed information about a specific release
***************************************************

.. rest_method:: GET v1/release/{release-id}

**Normal response codes**

200

**Error response codes**

internalServerError (500)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "release_id", "plain", "xsd:string", "The release identification name."
   "state", "plain", "xsd:string", "The current release state."
   "sw_version", "plain", "xsd:string", "The software version for which the deploy is intended."
   "component", "plain", "xsd:string", "The component present in the release."
   "status", "plain", "xsd:string", "The status of the release."
   "unremovable", "plain", "xsd:string", "The flag that indicates if release is unremovable."
   "summary", "plain", "xsd:string", "A brief summary of the release."
   "description", "plain", "xsd:string", "The description of any updates present in this release."
   "install_instructions", "plain", "xsd:string", "Instructions on how to install the release."
   "warnings", "plain", "xsd:string", "Any warnings associated with the usage of the release."
   "reboot_required", "plain", "xsd:bool", "The flag that indicates if release is reboot required."
   "prepatched_iso", "plain", "xsd:bool", "The flag that indicates if release is a prepatched iso."
   "requires", "plain", "xsd:list", "A list of patch ids required for this patch release to be installed."
   "packages", "plain", "xsd:list", "A list of packages present in the release."

::

   {
      "release_id":"starlingx-0.0.0",
      "state":"deployed",
      "sw_version":"0.0.0",
      "component":null,
      "status":"REL",
      "unremovable":true,
      "summary":"STX 0.0 GA release",
      "description":"STX 0.0 major GA release",
      "install_instructions":"",
      "warnings":"",
      "reboot_required": true,
      "prepatched_iso": true,
      "requires":[
       ],
      "packages":[
       ]
   }

This operation does not accept a request body.

*******************************
Uploads a release to the system
*******************************

.. rest_method:: POST /v1/upload

**Normal response codes**

200

**Error response codes**

internalServerError (500)

**Example Request Body (multipart/form-data)**

::

  Content-Type: multipart/form-data

  --boundary
  Content-Disposition: form-data; name="starlingx-0.0.0.iso"; filename="starlingx-0.0.0.iso"

  --boundary
  Content-Disposition: form-data; name="starlingx-0.0.0.sig"; filename="starlingx-0.0.0.sig"

**Example Request Body (text/plain)**

::

  data:
    [
      "/home/sysadmin/starlingx-0.0.0.iso",
      "/home/sysadmin/starlingx-0.0.0.sig"
    ]


**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "info", "plain", "xsd:string", "Any information regarding the request processing."
   "warning", "plain", "xsd:string", "Any warnings generated during the request processing."
   "error", "plain", "xsd:string", "Any errors generated during the request processing."
   "upload_info", "plain", "xsd:list", "Information regarding uploaded files."

::

   {
       "info": "",
       "warning": "",
       "error": "",
       "upload_info": [{'file.iso': {'id': 'starlingx-0.0.0', 'sw_release': '0.0.0'}, 'file.sig': {'id': None, 'sw_release': None}}],
   }

***************************************************************
Removes a release that is in the Available or Unavailable state
***************************************************************

.. rest_method:: DELETE /v1/release/{release-id}

**Normal response codes**

200

**Error response codes**

internalServerError (500)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "info (Optional)", "plain", "xsd:string", "Any information regarding the request processing."
   "warning (Optional)", "plain", "xsd:string", "Any warnings generated during the request processing."
   "error (Optional)", "plain", "xsd:string", "Any errors generated during the request processing."

::

   {
       "info": "Deleted feed directory /var/www/pages/feed/rel-0.0\nstarlingx-0.0.0 has been deleted\n",
       "warning": "",
       "error": ""
   }

*****************************************
Checks if a release is in available state
*****************************************

.. rest_method:: GET /v1/release/{release-id}/is_available

**Normal response codes**

200

**Error response codes**

internalServerError (500)

**Response parameters**

.. csv-table::
   :header: "Style", "Type", "Description"
   :widths: 20, 20, 60

   "plain", "xsd:bool", "Bool value indicating if the release is available or not."

::

   true

****************************************
Checks if a release is in deployed state
****************************************

.. rest_method:: GET /v1/release/{release-id}/is_deployed

**Normal response codes**

200

**Error response codes**

internalServerError (500)

**Response parameters**

.. csv-table::
   :header: "Style", "Type", "Description"
   :widths: 20, 20, 60

   "plain", "xsd:bool", "Bool value indicating if the release is deployed or not."

::

   true

*****************************************
Checks if a release is in committed state
*****************************************

.. rest_method:: GET /v1/release/{release-id}/is_committed

**Normal response codes**

200

**Error response codes**

internalServerError (500)

**Response parameters**

.. csv-table::
   :header: "Style", "Type", "Description"
   :widths: 20, 20, 60

   "plain", "xsd:bool", "Bool value indicating if the release is deployed or not."

::

   true

***************************************
Realize checks regarding the deployment
***************************************

.. rest_method:: POST /v1/deploy/{release-id}/precheck

**Normal response codes**

200

**Error response codes**

internalServerError (500)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "force (Optional)", "query", "xsd:string", "Allow bypassing non-critical checks."
   "region_name (Optional)", "query", "xsd:string", "Send the request to a specified region."

**Example Request Body**

::

  data:
    {
      "force": true,
      "region_name": "RegionOne"
    }

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "info", "plain", "xsd:string", "Any information regarding the request processing."
   "warning", "plain", "xsd:string", "Any warnings generated during the request processing."
   "error", "plain", "xsd:string", "Any errors generated during the request processing."

::

   {
       "info": "System Health:\nAll hosts are provisioned: [OK]\nAll hosts are unlocked/enabled: [OK]\nAll hosts have current configurations: [OK]\nCeph Storage Healthy: [OK]\nNo alarms: [OK]\nAll kubernetes nodes are ready: [OK]\nAll kubernetes control plane pods are ready: [OK]\nAll kubernetes applications are in a valid state: [OK]\nAll hosts are patch current: [Fail]\nDeployment in progress: 00.00 to 00.01\nActive kubernetes version [v1.24.4] is a valid supported version: [OK]\nActive controller is controller-0: [OK]\nInstalled license is valid: [OK]\nValid upgrade path from release 00.00 to 00.01: [OK]\nRequired patches are applied: [OK]\n",
       "warning": "",
       "error": "The following issues have been detected, which prevent deploying starlingx-00.01.1\nSystem Health:\nAll hosts are provisioned: [OK]\nAll hosts are unlocked/enabled: [OK]\nAll hosts have current configurations: [OK]\nCeph Storage Healthy: [OK]\nNo alarms: [OK]\nAll kubernetes nodes are ready: [OK]\nAll kubernetes control plane pods are ready: [OK]\nAll kubernetes applications are in a valid state: [OK]\nAll hosts are patch current: [Fail]\nDeployment in progress: 00.00 to 00.01\nActive kubernetes version [v1.24.4] is a valid supported version: [OK]\nActive controller is controller-0: [OK]\nInstalled license is valid: [OK]\nValid upgrade path from release 00.00 to 00.01: [OK]\nRequired patches are applied: [OK]\n",
       "system_healthy": false
   }

*************************
Starts release deployment
*************************

.. rest_method:: POST /v1/deploy/{release-id}/start

**Normal response codes**

200

**Error response codes**

internalServerError (500), notAcceptable (406)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "force (Optional)", "query", "xsd:string", "Allow bypassing non-critical checks."

**Example Request Body**

::

  data:
    {
      "force": true
    }

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "info", "plain", "xsd:string", "Any information regarding the request processing."
   "warning", "plain", "xsd:string", "Any warnings generated during the request processing."
   "error", "plain", "xsd:string", "Any errors generated during the request processing."

::

   {
       "info": "Deployment for starlingx-0.0.0 started",
       "warning": "",
       "error": ""
   }

*******************************************************
Shows detailed information about the current deployment
*******************************************************

.. rest_method:: GET /v1/deploy

**Normal response codes**

200

**Error response codes**

internalServerError (500)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "from_release", "plain", "xsd:string", "The current release version of host."
   "to_release", "plain", "xsd:string", "The target release version."
   "feed_repo", "plain", "xsd:string", "The ostree repo feed path."
   "commit_id", "plain", "xsd:string", "The commit-id to deploy."
   "reboot_required", "plain", "xsd:bool", "The flag that indicates if release is reboot required."
   "state", "plain", "xsd:string", "The current deployment state."

::

    [
        {
            'from_release': '0.0.0',
            'to_release': '0.0.1',
            'feed_repo': '/var/www/pages/feed/rel-0.0/ostree_repo',
            'commit_id': '7f381f18890de1a5e73376f539608cd02600b3470e02d1639db8f57a0ebaae9c',
            'reboot_required': True,
            'state': 'start-done'
        }
    ]

***************************************************
Shows information about the current host deployment
***************************************************

.. rest_method:: GET /v1/deploy_host

**Normal response codes**

200

**Error response codes**

internalServerError (500)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "hostname", "plain", "xsd:string", "The name of the host."
   "software_release", "plain", "xsd:string", "The current release version of host."
   "target_release", "plain", "xsd:string", "The target release version."
   "reboot_required", "plain", "xsd:bool", "The flag that indicates if release is reboot required."
   "host_state", "plain", "xsd:string", "The current host deployment state."

::

    [
        {
            'hostname': 'controller-0',
            'from_release': '0.0.0',
            'to_release': '0.0.1',
            'reboot_required': True,
            'host_state': 'pending'
        }
    ]

*******************************************
Starts the deployment to the given hostname
*******************************************

.. rest_method:: POST /v1/deploy_host/{hostname}

**Normal response codes**

200

**Error response codes**

internalServerError (500)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "force (Optional)", "query", "xsd:string", "Force deploy host."

**Example Endpoint with parameters**

::

  /v1/deploy_host/controller-1/force

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "info", "plain", "xsd:string", "Any information regarding the request processing."
   "warning", "plain", "xsd:string", "Any warnings generated during the request processing."
   "error", "plain", "xsd:string", "Any errors generated during the request processing."

::

   {
       "info": "Running major release deployment, major_release=0.1, force=False, async_req=False, commit_id=7f381f18890de1a5e73376f539608cd02600b3470e02d1639db8f57a0ebaae9c\nHost installation was successful on controller-0.\n",
       "warning": "",
       "error": ""
   }

********************************************************
Starts the rollback the deployment to the given hostname
********************************************************

.. rest_method:: POST v1/deploy_host/{hostname}/rollback

**Normal response codes**

200

**Error response codes**

internalServerError (500)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "force (Optional)", "query", "xsd:string", "Force deploy host rollback."

**Example Endpoint with parameters**

::

  /v1/deploy_host/controller-1/rollback/force

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "info", "plain", "xsd:string", "Any information regarding the request processing."
   "warning", "plain", "xsd:string", "Any warnings generated during the request processing."
   "error", "plain", "xsd:string", "Any errors generated during the request processing."

::

   {
       "info": "Running major release deployment, major_release=0.0, force=False, async_req=False, commit_id=2de04d476b51ac57f6b2a7061d829634753c6fec0d48cb09501a728f9e4637b7\nHost installation was successful on controller-0.\n",
       "warning": "",
       "error": ""
   }

********************************
Activates the current deployment
********************************

.. rest_method:: POST v1/deploy/activate

**Normal response codes**

200

**Error response codes**

internalServerError (500)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "info", "plain", "xsd:string", "Any information regarding the request processing."
   "warning", "plain", "xsd:string", "Any warnings generated during the request processing."
   "error", "plain", "xsd:string", "Any errors generated during the request processing."

::

   {
       "info": "Deploy activate has started",
       "warning": "",
       "error": ""
   }

*******************************************
Rollbacks the current deployment Activation
*******************************************

.. rest_method:: POST v1/deploy/activate_rollback

**Normal response codes**

200

**Error response codes**

internalServerError (500)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "info", "plain", "xsd:string", "Any information regarding the request processing."
   "warning", "plain", "xsd:string", "Any warnings generated during the request processing."
   "error", "plain", "xsd:string", "Any errors generated during the request processing."

::

   {
       "info": "Deploy activate-rollback has started",
       "warning": "",
       "error": ""
   }

********************************
Completes the current deployment
********************************

.. rest_method:: POST v1/deploy/complete

**Normal response codes**

200

**Error response codes**

internalServerError (500)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "info", "plain", "xsd:string", "Any information regarding the request processing."
   "warning", "plain", "xsd:string", "Any warnings generated during the request processing."
   "error", "plain", "xsd:string", "Any errors generated during the request processing."

::

   {
       "info": "Deployment has been completed\n",
       "warning": "",
       "error": ""
   }

****************************
Abort the current deployment
****************************

.. rest_method:: POST v1/deploy/abort

**Normal response codes**

200

**Error response codes**

internalServerError (500)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "info", "plain", "xsd:string", "Any information regarding the request processing."
   "warning", "plain", "xsd:string", "Any warnings generated during the request processing."
   "error", "plain", "xsd:string", "Any errors generated during the request processing."

::

   {
       "info": "Deployment has been aborted",
       "warning": "",
       "error": ""
   }

******************************
Removes the current deployment
******************************

.. rest_method:: DELETE v1/deploy

**Normal response codes**

200

**Error response codes**

internalServerError (500)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "info", "plain", "xsd:string", "Any information regarding the request processing."
   "warning", "plain", "xsd:string", "Any warnings generated during the request processing."
   "error", "plain", "xsd:string", "Any errors generated during the request processing."

::

   {
       "info": "Deploy deleted with success",
       "warning": "",
       "error": ""
   }

****************************
Query the current deployment
****************************

.. rest_method:: GET v1/software_upgrade

**Normal response codes**

200

**Error response codes**

internalServerError (500)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "from_release", "plain", "xsd:string", "The current release version of host."
   "to_release", "plain", "xsd:string", "The target release version."
   "state", "plain", "xsd:string", "The current deployment state."

::

   {
       "from_release": "0.0.0",
       "to_release": "0.0.1",
       "state": "start-done"
   }

********************************************************
Checks if deployment state is synced between controllers
********************************************************

.. rest_method:: GET v1/software/in_sync_controller

**Normal response codes**

200

**Error response codes**

internalServerError (500)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "plain", "xsd:bool",
   "in_sync", "plain", "xsd:bool", "Bool value indicating if the deployment state is synced between controllers or not."

::

    {
       "in_sync": true
    }