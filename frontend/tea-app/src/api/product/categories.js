import api from '../api'

function normalizeCategory(c) {
  return {
    id: c.id,
    name: c.name || c.category_name || 'Unknown',
    slug: c.name || c.category_name || '',
    image: c.image_url || c.image || null,
    description: c.description || '',
    isActive: c.is_active !== false,
  }
}

export async function getFeaturedCategories() {
  const { data } = await api.get('/categories/featured')

  let list = []

  if (Array.isArray(data)) list = data
  else if (Array.isArray(data.categories)) list = data.categories
  else if (Array.isArray(data.data)) list = data.data
  else if (Array.isArray(data.results)) list = data.results

  const normalized = list.map(normalizeCategory)

  return normalized.filter((c) => c.isActive)
}
