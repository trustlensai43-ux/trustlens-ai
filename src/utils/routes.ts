export type AppRoute =
  | 'home'
  | 'scan'
  | 'breach'
  | 'matrix'
  | 'scenarios'
  | 'history'
  | 'methodology';

export const ROUTE_HASHES: Record<AppRoute, string> = {
  home: '#/',
  scan: '#/scan',
  breach: '#/breach-check',
  matrix: '#/matrix',
  scenarios: '#/scenarios',
  history: '#/history',
  methodology: '#/methodology',
};

export function getRouteFromHash(hash: string): AppRoute {
  const cleanHash = hash.toLowerCase().trim();
  if (cleanHash === '' || cleanHash === '#' || cleanHash === '#/') return 'home';
  if (cleanHash.startsWith('#/scan') || cleanHash.startsWith('#/workspace')) return 'scan';
  if (cleanHash.startsWith('#/breach-check') || cleanHash.startsWith('#/breach')) return 'breach';
  if (cleanHash.startsWith('#/matrix')) return 'matrix';
  if (cleanHash.startsWith('#/scenarios') || cleanHash.startsWith('#/sandbox')) return 'scenarios';
  if (cleanHash.startsWith('#/history')) return 'history';
  if (cleanHash.startsWith('#/methodology')) return 'methodology';
  return 'home';
}

export function navigateToRoute(route: AppRoute) {
  window.location.hash = ROUTE_HASHES[route];
}
