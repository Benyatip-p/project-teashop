// src/api/inventory.js
import api from '../api'

export const getLowStockItems = async () => {
  const { data } = await api.get('/admin/items/low-stock')
  return data.low_stock_items || []
}

export const getLowStockVariants = async () => {
  const { data } = await api.get('/admin/variants/low-stock')
  return data.low_stock_variants || []
}
