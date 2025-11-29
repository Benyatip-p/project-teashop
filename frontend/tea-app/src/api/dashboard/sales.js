// src/api/dashboard/sales.js
import api from '../api'

const toNumber = v => (typeof v === 'number' ? v : Number(v || 0))

const extractAmount = (data, keys) => {
  if (typeof data === 'number') return toNumber(data)
  if (!data || typeof data !== 'object') return 0
  for (const key of keys) {
    if (data[key] != null) return toNumber(data[key])
  }
  return 0
}

export const getDailySales = async () => {
  const { data } = await api.get('/admin/sales/daily')
  return extractAmount(data, ['total_sales', 'daily_sales', 'total', 'amount'])
}

export const getMonthlySales = async () => {
  const { data } = await api.get('/admin/sales/monthly')
  return extractAmount(data, ['total_sales', 'monthly_sales', 'total', 'amount'])
}

export const getYearlySales = async () => {
  const { data } = await api.get('/admin/sales/yearly')
  return extractAmount(data, ['total_sales', 'yearly_sales', 'total', 'amount'])
}

const parseYear = item => {
  if (!item || typeof item !== 'object') return 0
  if (item.year != null) return Number(item.year)
  if (item.sales_year != null) return Number(item.sales_year)
  if (item.order_year != null) return Number(item.order_year)
  if (item.date) {
    const d = new Date(item.date)
    if (!Number.isNaN(d.getTime())) return d.getFullYear()
  }
  return 0
}

const parseMonth = item => {
  if (!item || typeof item !== 'object') return 0
  if (item.month != null) return Number(item.month)
  if (item.sales_month != null) return Number(item.sales_month)
  if (item.order_month != null) return Number(item.order_month)
  if (item.date) {
    const d = new Date(item.date)
    if (!Number.isNaN(d.getTime())) return d.getMonth() + 1
  }
  return 0
}

export const getMonthlySalesHistory = async () => {
  const { data } = await api.get('/admin/sales/history/monthly')
  const raw = data.monthly_sales_history || data.history || data || []
  const result = []
  raw.forEach(yearItem => {
    const yearMonths = yearItem.months || []
    yearMonths.forEach(monthItem => {
      const year = parseYear(monthItem)
      const month = parseMonth(monthItem)
      const amount = extractAmount(monthItem, [
        'total_sales',
        'monthly_sales',
        'total',
        'amount',
        'sum',
      ])
      result.push({ year, month, amount })
    })
  })
  return result
}

export const getYearlySalesHistory = async () => {
  const { data } = await api.get('/admin/sales/history/yearly')
  const raw = data.yearly_sales_history || data.history || data || []
  return raw.map(item => {
    const year = parseYear(item)
    const amount = extractAmount(item, [
      'yearly_sales',
      'total_sales',
      'total',
      'amount',
      'sum',
    ])
    return { year, amount }
  })
}

export const getTopSellingProducts = async () => {
  const { data } = await api.get('/products/top-selling')
  return data.top_selling_products || data.products || []
}

export const getOrderStatusDistribution = async () => {
  const { data } = await api.get('/admin/orders/status-distribution')
  return data.distribution || []
}

export const getAverageOrderValue = async () => {
  const { data } = await api.get('/admin/orders/average-value')
  return data.average_order_value || 0
}

export const getTotalProductsCount = async () => {
  const { data } = await api.get('/admin/products/count')
  return data.total_products || 0
}

export const getRevenueByCategory = async () => {
  const { data } = await api.get('/admin/revenue/by-category')
  return data.revenue_by_category || []
}

export const getRecentActivities = async (limit = 10) => {
  const { data } = await api.get(`/admin/activities/recent?limit=${limit}`)
  return data.activities || []
}
