import { ApiError, controlApi } from './api';

export function browserHealthFilters(search: Record<string, string | string[] | undefined>) {
  const filters = new URLSearchParams();
  for (const name of ['rolloutGroup', 'browserVersion']) {
    const value = search[name];
    if (Array.isArray(value)) value.forEach((item) => filters.append(name, item));
    else if (value) filters.set(name, value);
  }
  return filters;
}

export async function loadBrowserHealth(token: string, filters: URLSearchParams) {
  try {
    const health = await controlApi.browserHealth(token, filters);
    return { ...health, filtersAvailable: true, groups: await controlApi.groups(token), error: undefined, cappedTotal: false };
  } catch (error) {
    if (!(error instanceof ApiError) || ![400, 404].includes(error.status)) throw error;
    if (!filters.size && error.status === 404) {
      const [installations, releases] = await Promise.all([controlApi.installations(token), controlApi.browserReleases(token)]);
      const activeInstallations = releases?.reduce((total, row) => total + row.installations, 0)
        ?? installations.filter(({ revokedAt }) => !revokedAt).length;
      return { activeInstallations, releases, installations, composerReadiness: undefined, filtersAvailable: false, groups: [], error: undefined,
        cappedTotal: !releases && installations.length === 100 };
    }
    const groups = await controlApi.groups(token);
    return { activeInstallations: undefined, releases: undefined, installations: [], composerReadiness: undefined, groups, filtersAvailable: true, cappedTotal: false,
      error: error.status === 400 ? 'Choose a rollout group and enter an exact extension version or unreported.'
        : 'This browser rollout view is unavailable. Choose a rollout group from the list or clear the filters.' };
  }
}
