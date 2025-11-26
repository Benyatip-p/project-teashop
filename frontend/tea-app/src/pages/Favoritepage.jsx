import React, { useState } from 'react'
import { Link } from 'react-router-dom'
import { useShop } from '../context/ShopContext'
import { HeartIcon as HeartSolid } from '@heroicons/react/solid'
import { HeartIcon as HeartOutline } from '@heroicons/react/outline'
import AddToCartModal from '../components/AddToCartModal'

const Favoritepage = () => {
  const { favorites, toggleFavorite, isFavorite } = useShop()
  const [activeItem, setActiveItem] = useState(null)

  const favoritesReversed = [...favorites].reverse()

  const handleToggleFavorite = (e, item) => {
    e.preventDefault()
    e.stopPropagation()
    toggleFavorite(item)
  }

  const handleOpenModal = (e, item) => {
    e.preventDefault()
    e.stopPropagation()
    setActiveItem(item)
  }

  const handleCloseModal = () => {
    setActiveItem(null)
  }

  return (
    <div className="min-h-[calc(100vh-72px)] bg-[#f5f7f5]">
      <div className="container mx-auto px-4 py-10">
        <div className="mb-6 flex flex-col gap-1">
          <h1 className="text-3xl font-semibold text-gray-900">รายการโปรด</h1>
          <span className="text-sm text-gray-500">
            จำนวน {favorites.length} รายการ
          </span>
        </div>

        {favorites.length === 0 ? (
          <div className="flex items-center justify-center pt-10">
            <div className="w-full max-w-xl rounded-2xl border border-dashed border-gray-200 bg-white px-8 py-12 text-center shadow-sm">
              <HeartOutline className="mx-auto mb-4 h-12 w-12 text-gray-300" />
              <p className="text-lg font-medium text-gray-800">
                ยังไม่มีสินค้าในรายการโปรด
              </p>
              <p className="mt-1 text-sm text-gray-500">
                ไปที่หน้าสินค้าแล้วกดหัวใจเพื่อบันทึกสินค้าที่คุณสนใจไว้ดูภายหลัง
              </p>
              <Link
                to="/products"
                className="mt-6 inline-flex items-center justify-center rounded-lg bg-[#0b2f27] px-5 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-[#13493d]"
              >
                เลือกชมสินค้า
              </Link>
            </div>
          </div>
        ) : (
          <>
            <div className="space-y-4">
              {favoritesReversed.map(item => (
                <div
                  key={item.id}
                  className="group flex flex-col gap-4 rounded-xl border border-gray-100 bg-white p-4 shadow-sm transition hover:-translate-y-0.5 hover:shadow-md sm:flex-row sm:items-center"
                >
                  <Link
                    to={`/products/${item.id}`}
                    className="flex flex-1 gap-4 sm:items-center"
                  >
                    <div className="relative h-28 w-28 flex-shrink-0 overflow-hidden rounded-lg bg-gray-100 sm:h-32 sm:w-32">
                      <img
                        src={item.coverImage || item.image}
                        alt={item.title}
                        className="h-full w-full object-cover transition-transform duration-300 group-hover:scale-105"
                      />
                      <button
                        onClick={e => handleToggleFavorite(e, item)}
                        className="absolute right-2 top-2 rounded-full bg-white/90 p-1.5 shadow-sm"
                      >
                        {isFavorite(item.id) ? (
                          <HeartSolid className="h-5 w-5 text-red-500" />
                        ) : (
                          <HeartOutline className="h-5 w-5 text-gray-900" />
                        )}
                      </button>
                    </div>

                    <div className="flex flex-1 flex-col justify-center">
                      <h2 className="line-clamp-1 text-base font-medium text-gray-900">
                        {item.title}
                      </h2>
                      {item.subtitle && (
                        <p className="mt-1 line-clamp-2 text-sm text-gray-500">
                          {item.subtitle}
                        </p>
                      )}
                      <span className="mt-2 text-base font-semibold text-gray-900">
                        ฿{item.price?.toLocaleString()}
                      </span>
                    </div>
                  </Link>

                  <div className="flex w-full justify-end sm:w-auto">
                    <button
                      onClick={e => handleOpenModal(e, item)}
                      className="rounded-lg bg-[#0b2f27] px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-[#13493d]"
                    >
                      เพิ่มลงตะกร้า
                    </button>
                  </div>
                </div>
              ))}
            </div>

            {activeItem && (
              <AddToCartModal
                open
                onClose={handleCloseModal}
                product={activeItem}
              />
            )}
          </>
        )}
      </div>
    </div>
  )
}

export default Favoritepage
