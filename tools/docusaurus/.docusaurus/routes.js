import React from 'react';
import ComponentCreator from '@docusaurus/ComponentCreator';

export default [
  {
    path: '/',
    component: ComponentCreator('/', 'c54'),
    routes: [
      {
        path: '/',
        component: ComponentCreator('/', '09c'),
        routes: [
          {
            path: '/',
            component: ComponentCreator('/', '07b'),
            routes: [
              {
                path: '/company-access',
                component: ComponentCreator('/company-access', '066'),
                exact: true,
                sidebar: "tutorialSidebar"
              },
              {
                path: '/jwks',
                component: ComponentCreator('/jwks', '84b'),
                exact: true,
                sidebar: "tutorialSidebar"
              },
              {
                path: '/metrics',
                component: ComponentCreator('/metrics', '3e6'),
                exact: true,
                sidebar: "tutorialSidebar"
              },
              {
                path: '/oauth-login',
                component: ComponentCreator('/oauth-login', '40e'),
                exact: true,
                sidebar: "tutorialSidebar"
              },
              {
                path: '/RELEASES',
                component: ComponentCreator('/RELEASES', 'f54'),
                exact: true
              },
              {
                path: '/',
                component: ComponentCreator('/', 'ffe'),
                exact: true,
                sidebar: "tutorialSidebar"
              }
            ]
          }
        ]
      }
    ]
  },
  {
    path: '*',
    component: ComponentCreator('*'),
  },
];
