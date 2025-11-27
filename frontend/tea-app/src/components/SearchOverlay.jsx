import React from 'react'
import { Link } from 'react-router-dom'
import { SearchIcon, XIcon } from '@heroicons/react/outline'
import { useProductSearch } from '../hooks/useProductSearch'

const popularKeywords = ['ชาอู่หลง', 'ชาเขียว', 'ชาดำ', 'กาน้ำชา', 'ถ้วยชา', 'อุปกรณ์ชงชา']

const SearchOverlay = ({ value, onChange, onSubmit, onClose }) => {
  const query = value || ''
  const trimmed = query.trim()
  const { results, loading } = useProductSearch(trimmed, true)

  const relatedKeywords = popularKeywords
    .filter(k => trimmed && k.includes(trimmed) && k !== trimmed)
    .slice(0, 3)

  const handleSubmit = e => {
    e.preventDefault()
    const q = trimmed
    if (!q) return
    onSubmit(q)
  }

  const handleKeywordClick = keyword => {
    onChange(keyword)
  }

  const handleProductClick = () => {
    onClose()
  }

  const showContent = trimmed.length >= 1

  return (
    <div className="fixed inset-x-0 top-0 z-[60] bg-white shadow-md">
      <form
        onSubmit={handleSubmit}
        className="container mx-auto flex h-16 items-center px-4"
      >
        <SearchIcon className="mr-3 h-5 w-5 text-gray-400" />
        <input
          type="text"
          autoFocus
          value={query}
          onChange={e => onChange(e.target.value)}
          placeholder="ค้นหาสินค้าของเรา"
          className="flex-1 text-sm text-gray-800 placeholder-gray-400 outline-none"
        />
        <button
          type="button"
          onClick={onClose}
          className="ml-4 text-gray-500 hover:text-gray-700"
        >
          <XIcon className="h-5 w-5" />
        </button>
      </form>

      <div className="border-t border-gray-100">
        <div className="container mx-auto px-4 pb-4 pt-3">
          <p className="text-xs font-semibold uppercase tracking-wide text-gray-400">
            คำค้นหายอดนิยม
          </p>
          <div className="mt-2 flex flex-wrap gap-2">
            {popularKeywords.map(keyword => (
              <button
                key={keyword}
                type="button"
                onClick={() => handleKeywordClick(keyword)}
                className="rounded-full bg-gray-100 px-3 py-1 text-xs text-gray-700 hover:bg-gray-200"
              >
                {keyword}
              </button>
            ))}
          </div>

          {showContent && (
            <div className="mt-5 grid gap-6 md:grid-cols-[minmax(0,1.1fr)_minmax(0,2fr)]">
              <div>
                <p className="text-xs font-semibold uppercase tracking-wide text-gray-400">
                  คำค้นที่ใกล้เคียง
                </p>
                <ul className="mt-2 space-y-1 text-sm text-gray-800">
                  <li className="font-medium">{trimmed}</li>
                  {relatedKeywords.map(k => (
                    <li
                      key={k}
                      className="cursor-pointer text-gray-500 hover:text-gray-800"
                      onClick={() => handleKeywordClick(k)}
                    >
                      {k}
                    </li>
                  ))}
                </ul>
              </div>

              <div>
                <div className="mb-2 flex items-center justify-between">
                  <p className="text-xs font-semibold uppercase tracking-wide text-gray-400">
                    สินค้าที่เกี่ยวข้อง
                  </p>
                  {loading && (
                    <span className="text-[11px] text-gray-400">
                      กำลังค้นหา...
                    </span>
                  )}
                </div>

                {!loading && trimmed.length >= 2 && results.length === 0 && (
                  <p className="text-xs text-gray-400">
                    ไม่พบสินค้าที่ตรงกับคำค้นนี้
                  </p>
                )}

                <div className="grid grid-cols-2 gap-4 md:grid-cols-3">
                  {results.map(item => (
                    <Link
                      key={item.id}
                      to={`/products/${item.id}`}
                      className="group"
                      onClick={handleProductClick}
                    >
                      <div className="overflow-hidden rounded-lg bg-gray-100">
                        <img
                          src={item.coverImage || item.image}
                          alt={item.title}
                          className="h-28 w-full object-cover transition-transform duration-300 group-hover:scale-105 md:h-32"
                        />
                      </div>
                      <div className="mt-1 line-clamp-2 text-xs font-medium text-gray-900">
                        {item.title}
                      </div>
                      {item.price != null && (
                        <div className="text-xs text-gray-600">
                          ฿{Number(item.price).toLocaleString()}
                        </div>
                      )}
                    </Link>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default SearchOverlay
