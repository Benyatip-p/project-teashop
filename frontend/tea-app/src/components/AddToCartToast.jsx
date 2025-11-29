import React from 'react'
import { Link } from 'react-router-dom'

function AddToCartToast({ open, product, variant, qty, onClose }) {
  if (!open || !product) return null

  const title = product.title || 'สินค้า'
  const rawPrice = variant?.price ?? product.price ?? 0
  const price =
    typeof rawPrice === 'number' ? rawPrice : Number(rawPrice) || 0
  const weightLabel = variant?.weight ? `${variant.weight}g` : ''

  return (
    <div className="fixed inset-0 z-[999] pointer-events-none flex items-start justify-end px-6 pt-[90px]">
      <div className="pointer-events-auto w-[360px] rounded-2xl border border-gray-200 bg-white p-5 shadow-xl">
        <div className="flex items-center justify-between">
          <p className="text-sm font-bold text-green-600">
            ✓ เพิ่มลงตะกร้าแล้ว
            <span className="ml-1 font-normal text-green-700">
              (+{qty} ชิ้น)
            </span>
          </p>
          <button
            type="button"
            onClick={onClose}
            className="text-lg text-gray-500 transition hover:text-black"
          >
            ×
          </button>
        </div>

        <div className="mt-4 flex items-center gap-4">
          <img
            src={product.coverImage}
            alt={title}
            className="h-16 w-16 rounded-xl object-cover"
          />
          <div className="text-sm leading-tight">
            <p className="font-semibold line-clamp-2">{title}</p>
            {weightLabel && (
              <p className="mt-1 text-xs text-gray-600">ขนาด {weightLabel}</p>
            )}
            <p className="mt-2 text-base font-bold">฿{price}</p>
          </div>
        </div>

        <Link
          to="/cart"
          className="mt-5 block w-full rounded-xl border border-gray-300 py-2 text-center text-sm font-semibold transition hover:bg-gray-100"
        >
          ดูตะกร้า
        </Link>
      </div>
    </div>
  )
}

export default AddToCartToast
