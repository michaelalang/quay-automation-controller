# Quay Automation POC

## DISCLAIMER

the following procedure and tools are not supported by Red Hat and might violate the support statement for your Red Hat Quay deployment.
Please consider raising and RFE with Red Hat if the tools and processes are useful to get a supported version in the future.

## Pre requisits

You'll need:
* OpenShift 4.12+
* Red Hat Quay Operator installed
* preferred a LDAP or OIDC infrastructure providing your userbase

Users are preferable provided by a centralized infrastructure as eventhough credentials will be encrypted when stored, the automation is not ment to replace your infrastructure and security concepts those provide. Furthermore, bare in mind that even encrypted, both sensitive items (de/encryption key, encrypted content are stored in the same location)

Further note, the `annotation` `quay-automation=v1` is used to `en-disable` configmaps in the automation-controller.

## Deploy the automation controller

The automation controller reads and writes configmaps as well as secrets in the namespace. Therefor it's mandatory to have write privileges which we'll handle with the `edit` namespace rolebinding.

* create the ServiceAccount for the automation controller

    ```
    oc -n quay create -f -
    apiVersion: v1
    kind: ServiceAccount
      metadata:
    name: automation
    namespace: quay
    ```

* create the Rolbinding for the ServiceAccount

    ```
    oc -n quay create -f -
    apiVersion: rbac.authorization.k8s.io/v1
    kind: RoleBinding
    metadata:
      name: automation-edit
      namespace: quay
    roleRef:
      apiGroup: rbac.authorization.k8s.io
      kind: ClusterRole
      name: edit
    subjects:
    - kind: ServiceAccount
      name: automation
      namespace: quay
    ```


## create the init config bundle 

The Red Hat Quay init config bundle specifies some basic configurations to ensure the Registry behaves as required.
For the automation controller there are only two mandatory items to be in that config bundle:

* SUPER_USERS
* FEATURE_SUPERUSERS_FULL_ACCESS

Those two configurations ensure that you will have a full empowered superuser at the end.

    ```
    # config.yaml
    ...
    SUPERUSERS:
    - automation
      ...
    FEATURE_SUPERUSERS_FULL_ACCESS: true
    ...
    ```

* create your init config bundle 
   
    ```
    oc -n quay create secret generic config-bundle-secret --from-file=config.yaml 
    ```

* create your Quay Registry CR
    Ensure to adjust the components to your needs. Due to limitations in the LAB we disable Clair and storage from being managed as well 
    as scaling the Quay Application to one replica only.
    ```
    oc -n quay create -f -
    apiVersion: quay.redhat.com/v1
    kind: QuayRegistry
    metadata:
      name: example-registry
      namespace: quay
    spec:
      components:
        - kind: clair
          managed: false
        - kind: postgres
          managed: true
        - kind: objectstorage
          managed: false
        - kind: redis
          managed: true
        - kind: horizontalpodautoscaler
          managed: false
        - kind: route
          managed: true
        - kind: mirror
          managed: true
          overrides:
            replicas: 1
        - kind: monitoring
          managed: false
        - kind: tls
          managed: true
        - kind: quay
          managed: true
          overrides:
            env:
              - name: DEBUGLOG
                value: 'true'
            replicas: 1
        - kind: clairpostgres
          managed: false
      configBundleSecret: config-bundle-secret
    ```

The Quay Operator will deploy a Quay Registry according to your configuration and the automation controller will `bootstrap` the initial Superuser as soon as the Quay API reports healthy. The generated Superuser token will be available as encrypted secret. (see [how to decrypt](README.md#how-to-decrypt))

    ```
    oc -n quay extract secret/superusertoken --to=-
    # superusertoken
    gAAAAABleA8xhzgMVTNHIniKSta-AHOiF4UZl8bTANEniQY_4yhjZlf8ikOqBCDIApLbs_byYu9gmQzjnWyrP1c9rWpt1ScsReY675-ijazZaZ_Pr-a7X4XAvEBGzlITIQ7G1Pa9RoyY
    ```

At this point, you can utilize any other automation tool (Ansible, ...) as well by transfering the superuser token into those systems for further actions.

## Create you first organizations, repositories and robot accounts

The automation controller creates such items based on found configmaps which provide json style data at the key `config.json`. 
As example we want to provide two organizations (organization1, organization2) and repositories (repository1...) with different access levels (public, private). Additionally we want Robots to be populated and Teams to be configure (LDAP sync).

The syntax looks as follows and the complete example is found in the git repository

    ```
    {
      "organizations": [
        {
          "name": "organization1",
          "repositories": [
            {
              "name": "repository1",
              "is_public": true
            },        
            {
              "name": "repository2",
              "is_public": false
            }
          ],
          "robots": [
            {
              "name": "robot1",
              "description": "robot1"
            }
          ],
          "teams": [
            {
              "name": "members",
              "role": "Member",
              "sync": "cn=organization1,ou=Groups"
            }
          ],
          "owners": [
            "milang"
          ] 
        },
        {
          "name": "organization2",
          ...
    ```

It's mandatory to provide valid json syntax as otherwise the automation controller will `ignore` the configuration. 
Furthermore, the configmaps can be explicitly be **ignored** by removing the annotation `quay-automation=v1`. 

[See the recording](Quay-Automation-controller.mkv) of the full demo with various configuration topics.

### Description of the json configuration items

#### organizations

the Organizations are grouping various items together. The only mandatory one is `name` all other items will not be executed if not present.

    ```
    {"name": "organizationname"}
    ```

the Syntax needs to follows Docker API v2 declaration (Quay inherited) and reads as follows:
	
    ```
    name must be at least one lowercase, alpha-numeric characters, optionally separated by periods, dashes or underscores. More strictly, it must match the regular expression [a-z0-9]+(?:[._-][a-z0-9]+)*
    ```

#### repositories

the Repositories holds the various image/tags. Right now, creating tags as an automated bootstrap process is out of scope and there for only Repositories can be created.

    ```
    {"name": "repository",
     "is_public": true|false,
     "state": "NORMAL|MIRROR|READ_ONLY"
    }
    ```

other type than `kind=IMAGE` are not supported. Automatic `quota` assignment will be added in a later release of the automation-controller.

##### proxycache

Proxycache can be configured on a per organization level only. The configuration takes the API attributes and only expiration will be autofilled with 1 day, if omitted.

    ```
    "proxycache": {
            "username": null,
            "password": null,
            "upstream_registry": "docker.io/library",
            "expiration": 3000
          },
    ```

##### mirror 

Mirror can be configured on a per repository level only. The configuration takes the API attributes and the attributes `sync_start_date` and `is_enabled` will be autofilled, if omitted.

**NOTE** `robot` is mandatory, `sync_start_date` follows the syntax `YYYY-mm-ddTHH:MM:SSZ`

    ```
    "mirror": {
      "external_reference": "docker.io/library/alpine",
      "external_registry_username": null,
      "external_registry_password": null,
      "robot": "organization5+robot1",
      "tags": [
        "latest",
        "edge"
      ],
      "sync_interval": 60,
      "sync_start_date": "2023-12-24T00:00:00Z",
      "is_enabled": true
    }
    ```

#### robot accounts

Robot accounts are used to delegate access to repositories or Quay functionality for automated processes (Build pipelines, Scanners, CI/CD,...)
The definition covers the name and if provided the description which is optional.

    ```
    {"name":"robot", 
     "description":"Robot for CI/CD"
    }
    ```

**NOTE** The generated tokens are stored in the namespace configmap `generatedrobots` with data keys alligned to the Organization of the robot and json formatted list of `name: token` (see [how to decrypt](README.md#how-to-decrypt))

#### user accounts 

User accounts are currently not implemented as the functionality for automation is very limited. Further release of the automation-controller might provide User creation. Please raise an RFE if you consider this functionality useful with an explanation and your use-case here in the github issues section.

#### teams 

Quay uses teams to grant permissions to group of entities (robots, users). Bear in mind that robots need to belong to the organization the permission is assigned on. You cannot grand cross organization permissions to robot accounts.

Teams definition covers both ways which are mutually exclusive, user lists, LDAP synchronization. 
Roles can be:
* Member 
* write 
* admin 

**NOTE** Users need to exists in Quay before they can be assigned to a team (see [create an all-users team](README.md#create_all-users_team))

    ```
    # LDAP synchronization
    {"name": "team2",
     "role": "Member",
     "sync": "cn=organization1,ou=Groups"
    }

    # User list 
    {"name": "team1",
     "role": "write",
     "members": [
        "organization+publisher",
        "engineer1",
        "engineer2"
     ]
    }
    ```

#### owners

Owner team is a special Team that is created by Quay for every repository. Right now the automation-controller can only set owners for all repositories under the Organization to the same value.

    ```
    "owners": [
      "admin1",
      "admin2"
    ] 
    ```

The Owner team does not support LDAP synchronization. Use an additional Team with the appropriate permissions instead.

## create all-users team

with the restriction in Quay to have Users know to the system prior Team or permission assignment, you should create a Team of all Quay login allowed users to automated further Team or permission  building. 

With LDAP synchronization your entities can be easily match in the automation organization team called `allusers`

    ```
    {
      "organizations": [
        {
          "name": "automation",
          "teams": [
            {
              "name": "allusers",
              "role": "Member",
              "sync": "cn=allusers,ou=Groups"
            }
        }
    }
    ```

Since the team `allusers` does not have any repository permissions and role `Member` does not grant any we just created a way of pulling in all users to Quay for further actions.

## how to decrypt

Even though robot tokens can be read through the API/UI storing them after creating seems useful. Bear in mind that there's no state synchronization between the automation-controller and Quay meaning changing the toke after creating it will not update the configmap in the namespace. The namespace configmap is used for easy documentation of the created entities.

    ```
    oc -n quay get configmap generatedrobots -o yaml 

    # select the token value of your choice 

    oc -n quay exec -ti deploy/automation -- /opt/app-root/src/dm ${encrypted-token}
    ```

Same applies for the superusertoken which is stored as secret named `superusertoken`
