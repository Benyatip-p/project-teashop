import axios from 'axios'

const api = axios.create({
  baseURL: '/api/v1',
  timeout: 10000,
})

api.interceptors.request.use((config) => {
  const token =
    localStorage.getItem('access_token') ||
    sessionStorage.getItem('access_token')

  if (token) {
    config.headers = {
      ...(config.headers || {}),
      Authorization: `Bearer ${token}`,
    }
  }

  return config
})

export async function apiFormData(url, formData, config = {}) {
  const res = await api.post(url, formData, {
    ...config,
  })
  return res.data
}

export default api
