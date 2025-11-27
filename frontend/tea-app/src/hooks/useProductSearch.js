import { useEffect, useState } from 'react'
import { productsData } from '../data/productsData'

const normalizeProduct = p => {
  const img = p.image_url || p.coverImage || p.image || ''
  const normalizedImg =
    img && !img.startsWith('http')
      ? `/${img.replace(/^\/+/, '')}`
      : img || '/images/default-product.jpg'

  return {
    id: p.id,
    title: p.name || p.title || '',
    price: p.price || 0,
    coverImage: normalizedImg,
  }
}

export const useProductSearch = (query, enabled) => {
  const [results, setResults] = useState([])
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    const q = query.trim()

    if (!enabled || q.length < 2) {
      setResults([])
      setLoading(false)
      return
    }

    let cancelled = false
    const controller = new AbortController()

    const timer = setTimeout(async () => {
      try {
        setLoading(true)
        const res = await fetch(
          `/api/v1/products?search=${encodeURIComponent(q)}&limit=6`,
          { signal: controller.signal },
        )

        if (!res.ok) throw new Error()

        const data = await res.json()
        let list = []

        if (Array.isArray(data.products)) list = data.products
        else if (Array.isArray(data.data)) list = data.data
        else if (Array.isArray(data.results)) list = data.results
        else if (Array.isArray(data)) list = data

        const normalized = list.map(normalizeProduct)

        if (!cancelled) {
          setResults(normalized)
          setLoading(false)
        }
      } catch (e) {
        if (cancelled) return
        const qLower = q.toLowerCase()
        const fallback = productsData
          .filter(
            item =>
              item.title?.toLowerCase().includes(qLower) ||
              item.name?.toLowerCase().includes(qLower),
          )
          .slice(0, 6)
          .map(normalizeProduct)

        setResults(fallback)
        setLoading(false)
      }
    }, 250)

    return () => {
      cancelled = true
      controller.abort()
      clearTimeout(timer)
    }
  }, [query, enabled])

  return { results, loading }
}
