#
# Copyright 2017 Canonical Ltd
# Copyright 2020 Consortium GARR
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import charmhelpers.core as core
import charmhelpers.core.host as ch_host
import charmhelpers.core.hookenv as hookenv

import charmhelpers.contrib.openstack.templating as os_templating

import charms_openstack.charm
import charms_openstack.adapters

import os
import subprocess


# the /etc/apache2/mellon directory is automatically parsed by keystone
# see https://github.com/openstack/charm-keystone/commit/6f3751cc96a910b07a122171cf43eee0b2852ecb
CONFIGS = (OIDC_LOCATION_CONFIG, OIDC_CONF) = [os.path.join('/etc/apache2/mellon/',
                                                'sp-location-oidc.conf'),
                                               os.path.join('/etc/apache2/conf-enabled/',
                                                'oidc.conf')]

class KeystoneOIDCConfigurationAdapter(
        charms_openstack.adapters.ConfigurationAdapter):

    def __init__(self, charm_instance=None):
        super().__init__(charm_instance=charm_instance)
        self._validation_errors = {}

    @property
    def validation_errors(self):
        return {k: v for k, v in
                self._validation_errors.items() if v}

    @property
    def remote_id_attribute(self):
        return "HTTP_OIDC_ISS"

    @property
    def oidc_location_config(self):
        return OIDC_LOCATION_CONFIG
    
    @property
    def oidc_conf(self):
        return OIDC_CONF

    @property
    def websso_auth_path(self):
        return ('/v3/auth/OS-FEDERATION/websso/{}'.format(
                    self.protocol_name
                ))

    @property
    def websso_auth_protocol_path(self):
        return ('/v3/OS-FEDERATION/identity_providers/.*?'
                '/protocols/{}/auth'.format(
                    self.protocol_name
                ))

    @property
    def websso_auth_idp_protocol_path(self):
        return ('/v3/auth/OS-FEDERATION/identity_providers'
                '/{}/protocols/{}/websso'.format(
                    self.idp_name,
                    self.protocol_name
                ))


class KeystoneSAMLOIDCCharm(charms_openstack.charm.OpenStackCharm):

    # Internal name of charm
    service_name = name = 'keystone-oidc'

    # Package to derive application version from
    version_package = 'keystone'

    # First release supported
    release = 'stein'

    release_pkg = 'keystone-common'

    # Required relations
    required_relations = [
        'keystone-fid-service-provider',
        'websso-fid-service-provider']

    # List of packages to install for this charm
    packages = ['libapache2-mod-auth-openidc']

    configuration_class = KeystoneOIDCConfigurationAdapter

    group = 'www-data'

    restart_map = {
        OIDC_LOCATION_CONFIG: [],
        OIDC_CONF: [],
    }

    def configuration_complete(self):
        """Determine whether sufficient configuration has been provided
        via charm config options and resources.
        :returns: boolean indicating whether configuration is complete
        """
        required_config = {
            'oidc-claim-prefix': self.options.oidc_claim_prefix,
            'oidc-response-type': self.options.oidc_response_type,
            'oidc-scope': self.options.oidc_scope,
            'oidc-provider-metadata-url': self.options.oidc_provider_metadata_url,
            'oidc-client-id': self.options.oidc_client_id,
            'oidc-client-secret': self.options.oidc_client_secret,
            'oidc-crypto-passphrase': self.options.oidc_crypto_passphrase,
            'oidc-redirect-uri': self.options.oidc_redirect_uri,
            'idp-name': self.options.idp_name,
            'protocol-name': self.options.protocol_name,
        }

        return all(required_config.values())

    def custom_assess_status_check(self):
        """Custom asses status.

        Check the configuration is complete.
        """
        if not self.configuration_complete():
            errors = [
                '{}: {}'.format(k, v)
                for k, v in self.options.validation_errors.items()]
            status_msg = 'Configuration is incomplete. {}'.format(
                ','.join(errors))
            return 'blocked', status_msg
        # Nothing to report
        return None, None

    def render_config(self, *args):
        """
        Render Service Provider configuration file to be used by Apache
        and provided to idP out of band to establish mutual trust.
        """
        owner = 'root'
        group = 'www-data'
        # group read and exec is needed for mellon to read the rendered
        # files, otherwise it will fail in a cryptic way
        dperms = 0o650
        # file permissions are a bit more restrictive than defaults in
        # charm-helpers but directory permissions are the main protection
        # mechanism in this case
        fileperms = 0o440
        # ensure that a directory we need is there
        ch_host.mkdir('/etc/apache2/mellon', perms=dperms, owner=owner,
                      group=group)

        core.templating.render(
            source='apache-oidc-location.conf',
            template_loader=os_templating.get_loader(
                'templates/', self.release),
            target=self.options.oidc_location_config,
            context=self.adapters_class(args, charm_instance=self),
            owner=owner,
            group=group,
            perms=fileperms
        )

        core.templating.render(
            source='oidc.conf',
            template_loader=os_templating.get_loader(
                'templates/', self.release),
            target=self.options.oidc_conf,
            context=self.adapters_class(args, charm_instance=self),
            owner=owner,
            group=group,
            perms=fileperms
        )

    def remove_config(self):
        for f in self.restart_map.keys():
            if os.path.exists(f):
                os.unlink(f)

    def enable_module(self):
        subprocess.check_call(['a2enmod', 'auth_openidc'])

    def disable_module(self):
        subprocess.check_call(['a2dismod', 'auth_openidc'])

