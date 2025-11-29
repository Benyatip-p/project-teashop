// src/api/sales.js
import api from '../api'

const toNumber = (v) => (typeof v === 'number' ? v : Number(v || 0))

export async function getDailySales() {
  const { data } = await api.get('/admin/sales/daily')
  return toNumber(data.daily_sales)
}

export async function getMonthlySales() {
  const { data } = await api.get('/admin/sales/monthly')
  return toNumber(data.monthly_sales)
}

export async function getYearlySales() {
  const { data } = await api.get('/admin/sales/yearly')
  return toNumber(data.yearly_sales)
}
