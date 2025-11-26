import React, { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { getFeaturedCategories } from '../api/product/categories'

const FeaturedCategories = () => {
  const [categories, setCategories] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [imageErrors, setImageErrors] = useState({})

  useEffect(() => {
    let isMounted = true

    const load = async () => {
      try {
        setLoading(true)
        const list = await getFeaturedCategories()
        if (!isMounted) return
        setCategories(list.slice(0, 4))
        setError(null)
      } catch (err) {
        if (!isMounted) return
        const message = err?.message || 'Error loading categories'
        setError(message)
      } finally {
        if (isMounted) setLoading(false)
      }
    }

    load()

    return () => {
      isMounted = false
    }
  }, [])

  const handleImageError = (id) => {
    setImageErrors((prev) => ({ ...prev, [id]: true }))
  }

  if (loading) {
    return (
      <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
        {Array.from({ length: 4 }).map((_, i) => (
          <div
            key={i}
            className="rounded-2xl bg-gray-100 overflow-hidden shadow animate-pulse"
          >
            <div className="aspect-square bg-gray-300" />
            <div className="p-4">
              <div className="h-4 w-3/4 bg-gray-300 rounded mx-auto" />
            </div>
          </div>
        ))}
      </div>
    )
  }

  if (error) {
    return (
      <div className="py-8 text-center text-red-600">
        <p className="font-semibold text-lg">เกิดข้อผิดพลาด</p>
        <p className="text-sm">{error}</p>
      </div>
    )
  }

  if (categories.length === 0) {
    return (
      <div className="py-8 text-center text-gray-500">
        ไม่พบหมวดหมู่
      </div>
    )
  }

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
      {categories.map((category) => (
        <Link
          key={category.id}
          to={`/products?category=${encodeURIComponent(category.slug)}`}
          className="group rounded-2xl bg-white overflow-hidden shadow-md hover:shadow-xl transition-all"
        >
          <div className="relative aspect-square overflow-hidden bg-gray-200 flex items-center justify-center">
            {category.image && !imageErrors[category.id] ? (
              <>
                <img
                  src={category.image}
                  alt={category.name}
                  onError={() => handleImageError(category.id)}
                  className="w-full h-full object-cover transition-transform duration-700 group-hover:scale-110 group-hover:rotate-1"
                />
                <div className="absolute inset-0 bg-gradient-to-t from-black/70 via-black/20 to-transparent opacity-40 group-hover:opacity-70 transition-opacity duration-500" />
                <div className="absolute inset-0 bg-gradient-to-br from-emerald-400/30 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
                <div className="absolute inset-0 bg-gradient-to-tr from-transparent via-white/0 to-transparent -translate-x-full group-hover:translate-x-full group-hover:via-white/25 transition-all duration-700 pointer-events-none" />
              </>
            ) : (
              <span className="text-4xl">🍵</span>
            )}
          </div>

          <div className="bg-white text-center py-6">
            <h3 className="text-base font-semibold text-gray-900 tracking-wide">
              {category.name}
            </h3>
          </div>
        </Link>
      ))}
    </div>
  )
}

export default FeaturedCategories
