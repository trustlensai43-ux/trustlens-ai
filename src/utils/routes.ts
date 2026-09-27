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

export interface ParsedHashRoute {
  rawHash: string;
  routePath: string;
  queryString: string;
  cleanRoute: string;
  searchParams: URLSearchParams;
  idParam: string | null;
  dataParam: string | null;
  route: AppRoute;
}

/**
 * Bulletproof hash routing parser conforming to the spec:
 * Parses window.location.hash safely without crashing on edge cases or malformed strings.
 */
export function parseHashRoute(hash?: string): ParsedHashRoute {
  try {
    const rawHash =
      (typeof hash === 'string'
        ? hash
        : typeof window !== 'undefined'
        ? window.location.hash
        : '') || '#/';

    const [routePath = '', queryString = ''] = rawHash.replace(/^#\/?/, '').split('?');
    const cleanRoute = routePath ? `/#/${routePath}` : '/#/';
    const searchParams = new URLSearchParams(queryString || '');
    const idParam = searchParams.get('id')?.trim() || null;
    const dataParam = searchParams.get('data')?.trim() || null;

    const route = getRouteFromPath(routePath);

    return {
      rawHash,
      routePath,
      queryString,
      cleanRoute,
      searchParams,
      idParam,
      dataParam,
      route,
    };
  } catch (err) {
    console.warn('Error in parseHashRoute:', err);
    return {
      rawHash: '#/',
      routePath: '',
      queryString: '',
      cleanRoute: '/#/',
      searchParams: new URLSearchParams(),
      idParam: null,
      dataParam: null,
      route: 'home',
    };
  }
}

/**
 * Match routePath segment to AppRoute
 */
export function getRouteFromPath(routePath: string): AppRoute {
  const clean = (routePath || '').toLowerCase().trim();
  if (!clean || clean === 'home' || clean === '/') return 'home';
  if (clean === 'scan' || clean.startsWith('scan') || clean.startsWith('workspace')) return 'scan';
  if (clean === 'breach-check' || clean === 'breach' || clean.startsWith('breach')) return 'breach';
  if (clean === 'matrix' || clean.startsWith('matrix')) return 'matrix';
  if (clean === 'scenarios' || clean === 'sandbox' || clean.startsWith('scenarios') || clean.startsWith('sandbox')) return 'scenarios';
  if (clean === 'history' || clean.startsWith('history')) return 'history';
  if (clean === 'methodology' || clean.startsWith('methodology')) return 'methodology';
  return 'home';
}

/**
 * Safe getRouteFromHash implementation
 */
export function getRouteFromHash(hash?: string): AppRoute {
  return parseHashRoute(hash).route;
}

/**
 * Safe navigateToRoute
 */
export function navigateToRoute(route: AppRoute) {
  try {
    if (typeof window !== 'undefined') {
      window.location.hash = ROUTE_HASHES[route] || '#/';
    }
  } catch (e) {
    console.warn('Navigation error:', e);
  }
}

/**
 * Safe getIdFromHash
 */
export function getIdFromHash(hash?: string): string | null {
  try {
    const parsed = parseHashRoute(hash);
    if (parsed.idParam) return parsed.idParam;

    // Fallback: check window.location.search if available
    if (typeof window !== 'undefined' && window.location.search) {
      const searchParams = new URLSearchParams(window.location.search);
      const id = searchParams.get('id');
      if (id) return id.trim();
    }
  } catch (e) {
    console.warn('Failed to parse ID from URL:', e);
  }
  return null;
}

/**
 * Safe getDataFromHash
 */
export function getDataFromHash(hash?: string): string | null {
  try {
    const parsed = parseHashRoute(hash);
    if (parsed.dataParam) return parsed.dataParam;

    // Fallback: check window.location.search if available
    if (typeof window !== 'undefined' && window.location.search) {
      const searchParams = new URLSearchParams(window.location.search);
      const data = searchParams.get('data');
      if (data) return data.trim();
    }
  } catch (e) {
    console.warn('Failed to parse data payload from URL:', e);
  }
  return null;
}
