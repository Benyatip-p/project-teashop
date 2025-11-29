import api from '../api'

const CATEGORY_ID_TO_NAME = {
  3: 'กาชงชา',
  4: 'ชาเขียว',
  5: 'ชาอู่หลง',
  6: 'ชาดำ',
  7: 'ชาขาว',
  8: 'อุปกรณ์กรองชา',
  9: 'ถ้วยชา',
}

function normalizeProduct(p) {
  return {
    id: p.id,
    name: p.name,
    title: p.name,
    categoryId: p.category_id,
    category: CATEGORY_ID_TO_NAME[p.category_id] || 'ทั่วไป',
    brand: p.brand || 'Tea House',
    price: p.price != null ? parseFloat(p.price) : 0,
    coverImage: p.image_url ? `/${p.image_url}` : '/images/placeholder.jpg',
    rating: p.rating || 0,
    reviews: p.reviews_count || p.reviews || 0,
    discount: p.discount_percentage || p.discount || null,
    stock: p.stock,
    description: p.description || '',
    isActive: p.is_active !== false,
    isNew: p.is_new || false,
    createdAt: p.created_at,
    updatedAt: p.updated_at,
  }
}

function normalizeVariant(v) {
  return {
    id: v.id,
    productId: v.product_id,
    weight: v.weight,
    price: v.price != null ? parseFloat(v.price) : 0,
    stock: v.stock ?? 0,
    isActive: v.is_active !== false,
    createdAt: v.created_at,
    updatedAt: v.updated_at,
  }
}

export async function getFeaturedProducts() {
  const { data } = await api.get('/products/featured')

  let list = []

  if (Array.isArray(data)) list = data
  else if (Array.isArray(data.products)) list = data.products
  else if (Array.isArray(data.data)) list = data.data
  else if (Array.isArray(data.results)) list = data.results

  return list.map(normalizeProduct).filter(p => p.isActive)
}

export async function getVariantsByProductId(productId) {
  const { data } = await api.get(`/variants/product/${productId}`)

  let list = []

  if (Array.isArray(data)) list = data
  else if (Array.isArray(data.variants)) list = data.variants
  else if (Array.isArray(data.data)) list = data.data
  else if (Array.isArray(data.results)) list = data.results

  return list.map(normalizeVariant).filter(v => v.isActive)
}

export async function createProduct(productData) {
  const { data } = await api.post('/products', productData)
  return data
}

export async function createVariant(productId, variantData) {
  const { data } = await api.post(`/variants/product/${productId}`, variantData)
  return data
}

export async function uploadProductImage(file) {
  const formData = new FormData()
  formData.append('file', file)
  const { data } = await api.post('/upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  })
  return data
}
