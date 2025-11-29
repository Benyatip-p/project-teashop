import React, { useEffect, useState } from 'react'
import { createPortal } from 'react-dom'
import { useShop } from '../context/ShopContext'
import { getVariantsByProductId } from '../api/product/product'

const AddToCartModal = ({ open, onClose, product }) => {
  const { addToCart } = useShop()
  const [quantity, setQuantity] = useState(1)
  const [variants, setVariants] = useState([])
  const [selectedVariantId, setSelectedVariantId] = useState(null)

  useEffect(() => {
    if (!open || !product?.id) return

    setQuantity(1)

    const load = async () => {
      try {
        const list = await getVariantsByProductId(product.id)
        setVariants(list)
        if (list.length > 0) {
          setSelectedVariantId(list[0].id)
        } else {
          setSelectedVariantId(null)
        }
      } catch {
        setVariants([])
        setSelectedVariantId(null)
      }
    }

    load()
  }, [open, product?.id])

  if (!open || typeof document === 'undefined') return null

  const decreaseQty = () => {
    setQuantity(q => (q > 1 ? q - 1 : 1))
  }

  const increaseQty = () => {
    setQuantity(q => q + 1)
  }

  const selectedVariant =
    variants.find(v => v.id === selectedVariantId) || null

  const displayPrice = selectedVariant ? selectedVariant.price : product.price
  const displayStock =
    selectedVariant?.stock ?? product?.stock ?? null

  const handleConfirm = () => {
    const payload = {
      ...product,
      price: displayPrice,
      variantId: selectedVariant ? selectedVariant.id : null,
      variantWeight: selectedVariant ? selectedVariant.weight : null,
    }
    addToCart(payload, quantity)
    onClose()
  }

  return createPortal(
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/40 px-4">
      <div className="w-full max-w-4xl overflow-hidden rounded-3xl bg-white shadow-2xl">
        <div className="flex flex-col gap-6 p-6 md:flex-row md:items-start">
          <div className="w-full md:w-1/3">
            <img
              src={product.coverImage}
              alt={product.title}
              className="h-full max-h-80 w-full rounded-2xl object-cover"
            />
          </div>

          <div className="flex-1">
            <p className="text-xs font-medium uppercase tracking-wide text-emerald-900">
              เพิ่มลงตะกร้า
            </p>
            <h3 className="mt-1 line-clamp-2 text-xl font-semibold text-gray-900">
              {product.title}
            </h3>
            <p className="mt-2 text-base text-gray-800">฿{displayPrice}</p>

            <div className="mt-4">
              <span className="text-sm text-gray-700">เลือกขนาด:</span>
              <div className="mt-2 flex flex-wrap gap-2">
                {variants.length > 0 ? (
                  variants.map(v => (
                    <button
                      key={v.id}
                      type="button"
                      onClick={() => setSelectedVariantId(v.id)}
                      className={`rounded-full border px-3 py-1 text-sm transition ${
                        selectedVariantId === v.id
                          ? 'border-[#0b2f27] bg-[#0b2f27] text-white'
                          : 'border-gray-300 bg-white text-gray-700 hover:bg-gray-50'
                      }`}
                    >
                      {v.weight}g
                    </button>
                  ))
                ) : (
                  <span className="text-xs text-gray-500">
                    สินค้านี้มีเพียงขนาดเดียว
                  </span>
                )}
              </div>
            </div>

            <div className="mt-6 flex items-center gap-4">
              <span className="text-sm text-gray-700">จำนวน</span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={decreaseQty}
                  className="flex h-9 w-9 items-center justify-center rounded-lg border border-gray-300 text-lg font-semibold text-gray-700 hover:bg-gray-100"
                >
                  −
                </button>
                <span className="w-10 text-center text-sm font-semibold">
                  {quantity}
                </span>
                <button
                  type="button"
                  onClick={increaseQty}
                  className="flex h-9 w-9 items-center justify-center rounded-lg border border-gray-300 text-lg font-semibold text-gray-700 hover:bg-gray-100"
                >
                  +
                </button>
              </div>

              {displayStock != null && (
                <span className="text-xs text-gray-500">
                  มีสินค้าทั้งหมด {displayStock} ชิ้นสำหรับขนาดนี้
                </span>
              )}
            </div>
          </div>
        </div>

        <div className="flex flex-col gap-3 border-t border-gray-100 px-6 py-4 md:flex-row md:items-center md:justify-between">
          <button
            type="button"
            onClick={onClose}
            className="w-full rounded-lg bg-gray-100 px-4 py-2 text-sm font-semibold text-gray-700 hover:bg-gray-200 md:w-auto"
          >
            เลือกสินค้าต่อ
          </button>
          <button
            type="button"
            onClick={handleConfirm}
            className="w-full rounded-lg bg-[#0b2f27] px-6 py-2 text-sm font-semibold text-white hover:bg-[#08231d] md:w-auto"
          >
            เพิ่มลงตะกร้า
          </button>
        </div>
      </div>
    </div>,
    document.body,
  )
}

export default AddToCartModal
