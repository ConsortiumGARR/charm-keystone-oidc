# Overview

This subordinate charm provides a way to integrate an OpenID Connect based identity
provider with Keystone using the mod_auth_openidc Apache web server authentication
module.

The structure and purpose follow the ones of the
[keystone-saml-mellon](https://opendev.org/openstack/charm-keystone-saml-mellon)
charm.

The following documentation is useful to better understand the charm
implementation:

* https://github.com/zmartzone/mod_auth_openidc
* https://docs.openstack.org/keystone/latest/admin/federation/configure_federation.html
* https://docs.openstack.org/keystone/latest/admin/federation/mapping_combinations.html
* https://opendev.org/openstack/charm-keystone-saml-mellon/src/branch/master/src/README.md


# Usage

Use this charm with the Keystone charm, running with preferred-api-version=3:

    juju deploy keystone
    juju config keystone preferred-api-version=3 # other settings
    juju deploy openstack-dashboard # settings
    juju deploy cs:~csd-garr/keystone-oidc
    juju add-relation keystone keystone-oidc
    juju add-relation keystone openstack-dashboard


In a bundle:

```
    applications:
    # ...
      keystone-oidc:
        charm: cs:~csd-garr/keystone-oidc
        num_units: 0
        options:
          idp-name: google
          protocol-name: openid
          user-facing-name: Google
          oidc-client-id: 1234567890-abcabacabcabc.apps.googleusercontent.com
          oidc-client-secret: XYZXYZXYZ
          oidc-provider-metadata-url: https://accounts.google.com/.well-known/openid-configuration
          oidc-redirect-uri: https://keystone.example.com:5000/v3/auth/OS-FEDERATION/websso/openid/redirect
      relations:
      # ...
      - [ keystone, keystone-oidc]
      - [ openstack-dashboard, keystone-oidc]
      - [ "openstack-dashboard:websso-trusted-dashboard", "keystone:websso-trusted-dashboard" ]
```

# Post-deployment Configuration

In addition to the above, there are several post-deployment steps that have to
be performed in order to start using federated identity functionality in
Keystone. They depend on the chosen config values.

In order to take the above into account several objects need to be created:

* a domain used for federated users;
* (optional) a project to be used by federated users;
* one or more groups to place federated users into;
* role assignments for the groups above;
* an identity provider object;
* a federation protocol object.

Generate rules.json for mapping federated users into the keystone database. The
following is a simple example. Constraints can be added on the remote side. For
example group membership.
See [mapping documentation](https://docs.openstack.org/keystone/latest/admin/federation/mapping_combinations.html) upstream.

```
    openstack domain create federated_domain
    openstack group create federated_users --domain federated_domain
    # Get the federated_users group id and assign the role Member
    GROUP_ID=$(openstack group show federated_users --domain federated_domain | grep -v domain_id | grep id |awk '{print $4}')
    openstack role add --group ${GROUP_ID} --domain federated_domain Member

    # Use the URL for your idP's metadata for remote-id. The name can be
    # arbitrary.
    openstack identity provider create --remote-id https://accounts.google.com --domain federated_domain google

    # Get the federated_domain id and add it to the rules.json map
    DOMAIN_ID=$(openstack domain show federated_domain |grep id |awk '{print $4}')
    cat > rules.json <<EOF
    [{
            "local": [
                {
                    "user": {
                        "name": "{0}"
                    },
                    "group": {
                        "domain": {
                            "id": "${DOMAIN_ID}"
                        },
                        "name": "federated_users"
                    },
                    "projects": [
                    {
                        "name": "{0}_project",
                        "roles": [
                                     {
                                         "name": "Member"
                                     }
                                 ]
                    }
                    ]
               }
            ],
            "remote": [
                {
                    "type": "OIDC-email"
                }
            ]
    }]
    EOF

    # Use the rules.json created above.
    openstack mapping create --rules rules.json oidc_mapping
    # The name must match the configuration setting protocol-name
    openstack federation protocol create openid --mapping oidc_mapping --identity-provider google
    # list related projects
    openstack federation project list
    # Note and auto generated domain has been created. This is where auto
    # generated users and projects will be created.
    openstack domain list
```

