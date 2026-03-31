import axios from 'axios';

export const AUTH_SYNC_EVENT = 'aegis-auth-sync';
const ACCESS_KEY = 'aegis_access';
const REFRESH_KEY = 'aegis_refresh';
const USER_KEY = 'aegis_user';

const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000/api/v1',
  timeout: 15000,
});

function dispatchAuthSync() {
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent(AUTH_SYNC_EVENT));
  }
}

export function storeSessionTokens({ access = '', refresh = '' } = {}) {
  if (access) {
    localStorage.setItem(ACCESS_KEY, access);
  } else {
    localStorage.removeItem(ACCESS_KEY);
  }

  if (refresh) {
    localStorage.setItem(REFRESH_KEY, refresh);
  } else {
    localStorage.removeItem(REFRESH_KEY);
  }

  dispatchAuthSync();
}

export function clearStoredSession() {
  localStorage.removeItem(ACCESS_KEY);
  localStorage.removeItem(REFRESH_KEY);
  localStorage.removeItem(USER_KEY);
  dispatchAuthSync();
}

apiClient.interceptors.request.use((config) => {
  const access = localStorage.getItem(ACCESS_KEY);
  if (access) {
    config.headers.Authorization = `Bearer ${access}`;
  }
  return config;
});

let refreshPromise = null;

apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config || {};
    const refresh = localStorage.getItem(REFRESH_KEY);
    const requestUrl = originalRequest.url || '';
    const isAuthRequest = ['/auth/login/', '/auth/refresh/', '/auth/register/', '/auth/logout/'].some((path) => requestUrl.includes(path));

    if (error.response?.status !== 401 || originalRequest._retry || !refresh || isAuthRequest) {
      return Promise.reject(error);
    }

    originalRequest._retry = true;

    try {
      if (!refreshPromise) {
        refreshPromise = axios.post(
          `${apiClient.defaults.baseURL}/auth/refresh/`,
          { refresh },
          { timeout: apiClient.defaults.timeout }
        );
      }

      const { data } = await refreshPromise;
      storeSessionTokens({ access: data.access, refresh: data.refresh || refresh });
      originalRequest.headers = {
        ...(originalRequest.headers || {}),
        Authorization: `Bearer ${data.access}`,
      };
      return apiClient(originalRequest);
    } catch (refreshError) {
      clearStoredSession();
      return Promise.reject(refreshError);
    } finally {
      refreshPromise = null;
    }
  }
);

export default apiClient;
