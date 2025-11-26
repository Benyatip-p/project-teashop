import React, { useState, useEffect } from 'react'
import { ChevronLeftIcon, ChevronRightIcon } from '@heroicons/react/outline'
import TeaCard from './ProductCard'
import { getFeaturedProducts } from '../api/product/product'

const PAGE_SIZE = 4

const FeaturedTeas = () => {
  const [featuredTeas, setFeaturedTeas] = useState([])
  const [currentIndex, setCurrentIndex] = useState(0)

  useEffect(() => {
    let isMounted = true

    const load = async () => {
      try {
        const products = await getFeaturedProducts()
        if (!isMounted) return
        setFeaturedTeas(products)
        setCurrentIndex(0)
      } catch (err) {
        console.error(err)
      }
    }

    load()
    return () => { isMounted = false }
  }, [])

  const maxIndex =
    featuredTeas.length > PAGE_SIZE ? featuredTeas.length - PAGE_SIZE : 0

  const handleNext = () => {
    setCurrentIndex(prev => Math.min(prev + 1, maxIndex))
  }

  const handlePrev = () => {
    setCurrentIndex(prev => Math.max(prev - 1, 0))
  }

  if (featuredTeas.length === 0) return null

  const visibleProducts = featuredTeas.slice(currentIndex, currentIndex + PAGE_SIZE)
  const totalPages = featuredTeas.length - PAGE_SIZE + 1

  return (
    <div className="w-full">
      <div className="relative flex items-center">

        {currentIndex > 0 && (
          <button
            onClick={handlePrev}
            className="absolute left-0 z-10 -ml-10 bg-white p-3 rounded-full shadow-lg border hover:bg-gray-100"
          >
            <ChevronLeftIcon className="w-6 h-6 text-gray-700" />
          </button>
        )}

        <div className="flex-1 px-4 md:px-0">
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-6 md:gap-8">
            {visibleProducts.map(product => (
              <TeaCard key={product.id} product={product} />
            ))}
          </div>
        </div>

        {currentIndex < maxIndex && (
          <button
            onClick={handleNext}
            className="absolute right-0 z-10 -mr-10 bg-white p-3 rounded-full shadow-lg border hover:bg-gray-100"
          >
            <ChevronRightIcon className="w-6 h-6 text-gray-700" />
          </button>
        )}
      </div>

      {totalPages > 1 && (
        <div className="flex justify-center gap-2 mt-6">
          {Array.from({ length: totalPages }).map((_, index) => (
            <button
              key={index}
              onClick={() => setCurrentIndex(index)}
              className={`h-2 rounded-full transition-all ${
                currentIndex === index ? 'bg-green-600 w-6' : 'bg-gray-300 w-2'
              }`}
            />
          ))}
        </div>
      )}
    </div>
  )
}

export default FeaturedTeas
