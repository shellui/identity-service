// @ts-check

/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
const sidebars = {
  tutorialSidebar: [
    {
      type: 'doc',
      id: 'index',
      label: 'Introduction',
    },
    {
      type: 'doc',
      id: 'oauth-login',
      label: 'OAuth',
    },
    {
      type: 'doc',
      id: 'scim',
      label: 'SCIM',
    },
    {
      type: 'doc',
      id: 'configuration',
      label: 'Configuration',
    },
    {
      type: 'doc',
      id: 'company-access',
      label: 'Company access',
    },
    {
      type: 'doc',
      id: 'jwks',
      label: 'JWKS',
    },
    {
      type: 'doc',
      id: 'security-hardening',
      label: 'Security',
    },
    {
      type: 'doc',
      id: 'metrics',
      label: 'Metrics',
    },
    {
      type: 'doc',
      id: 'RELEASES',
      label: 'Releases',
    },
  ],
};

module.exports = sidebars;
