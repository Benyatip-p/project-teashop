import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useShop } from '../context/ShopContext'

const Cartpage = () => {
  const navigate = useNavigate()
  const { cart, removeFromCart, updateCartQty } = useShop()

  const [selectedIds, setSelectedIds] = useState(() => {
    const stored = localStorage.getItem('cartSelectedIds')
    return stored ? JSON.parse(stored) : []
  })

  const [couponInput, setCouponInput] = useState(
    () => localStorage.getItem('couponInput') || '',
  )

  const [appliedCoupon, setAppliedCoupon] = useState(() => {
    const stored = localStorage.getItem('appliedCoupon')
    return stored ? JSON.parse(stored) : null
  })

  const [couponError, setCouponError] = useState(
    () => localStorage.getItem('couponError') || '',
  )

  useEffect(() => {
    setSelectedIds(prev => prev.filter(id => cart.some(item => item.id === id)))
  }, [cart])

  useEffect(() => {
    localStorage.setItem('cartSelectedIds', JSON.stringify(selectedIds))
  }, [selectedIds])

  useEffect(() => {
    localStorage.setItem('couponInput', couponInput)
  }, [couponInput])

  useEffect(() => {
    if (appliedCoupon) {
      localStorage.setItem('appliedCoupon', JSON.stringify(appliedCoupon))
    } else {
      localStorage.removeItem('appliedCoupon')
    }
  }, [appliedCoupon])

  useEffect(() => {
    localStorage.setItem('couponError', couponError)
  }, [couponError])

  const selectedItems = cart.filter(item => selectedIds.includes(item.id))

  const subtotal = selectedItems.reduce(
    (sum, item) => sum + (item.price || 0) * (item.qty || 1),
    0,
  )

  const shipping = subtotal === 0 ? 0 : subtotal >= 1000 ? 0 : 50

  const couponDiscount =
    appliedCoupon && appliedCoupon.code === 'happy20' && subtotal >= 700
      ? 20
      : 0

  const totalBeforeDiscount = subtotal + shipping
  const total = Math.max(totalBeforeDiscount - couponDiscount, 0)

  useEffect(() => {
    if (!appliedCoupon) return

    if (selectedItems.length === 0) {
      setCouponError('กรุณาเลือกสินค้าที่ต้องการใช้คูปอง')
      return
    }

    if (subtotal < 700) {
      setCouponError('โค้ดส่วนลดนี้ต้องมียอดสั่งซื้อขั้นต่ำ 700 บาท')
      return
    }

    setCouponError('')
  }, [subtotal, appliedCoupon, selectedItems.length])

  const handleDecrease = item => {
    const currentQty = item.qty || 1
    if (currentQty <= 1) return
    updateCartQty(item.id, currentQty - 1)
  }

  const handleIncrease = item => {
    const currentQty = item.qty || 1
    updateCartQty(item.id, currentQty + 1)
  }

  const allSelected = selectedIds.length === cart.length && cart.length > 0

  const handleToggleSelectAll = () => {
    if (allSelected) {
      setSelectedIds([])
    } else {
      setSelectedIds(cart.map(item => item.id))
    }
  }

  const handleToggleSelectItem = id => {
    setSelectedIds(prev =>
      prev.includes(id) ? prev.filter(itemId => itemId !== id) : [...prev, id],
    )
  }

  const handleApplyCoupon = () => {
    const code = couponInput.trim().toLowerCase()
    setCouponError('')

    if (!code) {
      setAppliedCoupon(null)
      return
    }

    if (code !== 'happy20') {
      setAppliedCoupon(null)
      setCouponError('ไม่พบรหัสส่วนลดนี้')
      return
    }

    setAppliedCoupon({ code: 'happy20', discount: 20 })
  }

  const handleClearCouponInput = () => {
    setCouponInput('')
    setAppliedCoupon(null)
    setCouponError('')
  }

  const handlePayment = () => {
    if (selectedItems.length === 0) {
      window.alert('กรุณาเลือกสินค้าที่ต้องการชำระเงิน')
      return
    }

    navigate('/payment', {
      state: {
        selectedItems,
        shipping,
        couponDiscount,
        subtotal,
        totalBeforeDiscount,
        total,
      },
    })
  }

  return (
    <div className="min-h-[calc(100vh-72px)] bg-[#f5f7f5]">
      <div className="container mx-auto px-4 py-10">
        <h1 className="mb-2 text-3xl font-semibold text-gray-900">
          ตะกร้าสินค้า
        </h1>
        <p className="mb-6 text-sm text-gray-500">
          เลือกสินค้าที่ต้องการชำระเงิน และกรอกรหัสคูปองหากมี
        </p>

        <div className="grid grid-cols-1 gap-8 lg:grid-cols-3">
          <section className="rounded-2xl bg-white p-5 shadow-sm lg:col-span-2">
            <div className="mb-3 flex items-center justify-between border-b pb-3">
              <label className="flex items-center gap-2 text-sm text-gray-700">
                <input
                  type="checkbox"
                  className="h-4 w-4 accent-[#0b2f27]"
                  checked={allSelected}
                  onChange={handleToggleSelectAll}
                  disabled={cart.length === 0}
                />
                <span>เลือกทั้งหมด</span>
              </label>
              {cart.length > 0 && (
                <span className="text-xs text-gray-500">
                  เลือกแล้ว {selectedItems.length} รายการ จาก {cart.length} รายการ
                </span>
              )}
            </div>

            {cart.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-gray-500">
                <div className="mb-3 flex h-14 w-14 items-center justify-center rounded-full bg-gray-100 text-2xl">
                  🛒
                </div>
                <p className="text-sm">ยังไม่มีสินค้าในตะกร้า</p>
              </div>
            ) : (
              <div className="space-y-3">
                {[...cart].reverse().map(item => (
                  <div
                    key={item.id}
                    className="flex items-center gap-4 rounded-xl border border-gray-100 bg-gray-50/60 px-4 py-3"
                  >
                    <input
                      type="checkbox"
                      className="h-4 w-4 accent-[#0b2f27]"
                      checked={selectedIds.includes(item.id)}
                      onChange={() => handleToggleSelectItem(item.id)}
                    />

                    <div className="h-20 w-20 flex-shrink-0 overflow-hidden rounded-lg bg-white shadow-sm">
                      <img
                        src={item.coverImage || item.image}
                        alt={item.title}
                        className="h-full w-full object-cover"
                      />
                    </div>

                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm font-medium text-gray-900">
                        {item.title}
                      </p>
                      {item.selectedSize && (
                        <p className="mt-0.5 text-xs text-gray-500">
                          ขนาด {item.selectedSize}
                        </p>
                      )}
                      <p className="mt-1 text-sm font-semibold text-gray-900">
                        ฿{item.price?.toFixed(2)}
                      </p>
                    </div>

                    <div className="flex w-32 flex-col items-end gap-2 text-right">
                      <div className="inline-flex items-center rounded-lg border border-gray-300 bg-white">
                        <button
                          type="button"
                          className="px-3 py-1 text-sm text-gray-500 hover:bg-gray-50"
                          onClick={() => handleDecrease(item)}
                        >
                          −
                        </button>
                        <span className="border-l border-r border-gray-300 bg-gray-50 px-4 py-1 text-sm font-medium">
                          {item.qty || 1}
                        </span>
                        <button
                          type="button"
                          className="px-3 py-1 text-sm text-gray-500 hover:bg-gray-50"
                          onClick={() => handleIncrease(item)}
                        >
                          +
                        </button>
                      </div>
                      <div className="text-xs text-gray-600">
                        ฿
                        {(
                          (item.price || 0) * (item.qty || 1)
                        ).toFixed(2)}
                      </div>
                      <button
                        className="text-xs text-red-500 hover:underline"
                        onClick={() => removeFromCart(item.id)}
                      >
                        ลบ
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>

          <section className="space-y-4 lg:col-span-1">
            <div className="rounded-2xl bg-white p-5 shadow-sm">
              <div className="mb-2 text-sm font-medium text-gray-900">
                คูปองส่วนลด
              </div>
              <p className="mb-3 text-xs text-gray-500">
                ใช้โค้ด{' '}
                <span className="font-semibold text-[#0b2f27]">HAPPY20</span>{' '}
                ลด 20 บาท เมื่อยอดสั่งซื้อรวมตั้งแต่ 700 บาทขึ้นไป
              </p>

              <div className="flex items-center">
                <div className="relative flex-1">
                  <input
                    type="text"
                    placeholder="กรอกรหัสคูปอง"
                    className="w-full rounded-lg border border-gray-300 px-3 py-2 pr-8 text-sm focus:border-[#0b2f27] focus:outline-none"
                    value={couponInput}
                    onChange={e => setCouponInput(e.target.value)}
                  />
                  {couponInput && (
                    <button
                      type="button"
                      onClick={handleClearCouponInput}
                      className="absolute right-2 top-1/2 -translate-y-1/2 text-sm text-gray-400 hover:text-gray-600"
                    >
                      ✕
                    </button>
                  )}
                </div>
                <button
                  type="button"
                  onClick={handleApplyCoupon}
                  className="ml-2 rounded-lg bg-gray-800 px-4 py-2 text-sm font-medium text-white hover:bg-black"
                >
                  ใช้คูปอง
                </button>
              </div>

              {couponError && (
                <p className="mt-2 text-xs text-red-500">{couponError}</p>
              )}
              {appliedCoupon && !couponError && (
                <p className="mt-2 text-xs text-green-600">
                  ใช้คูปอง {appliedCoupon.code.toUpperCase()} แล้ว
                </p>
              )}
            </div>

            <div className="rounded-2xl border border-gray-200 bg-white p-5 text-sm shadow-sm">
              <div className="mb-4 text-sm font-semibold text-gray-900">
                สรุปรายการสั่งซื้อ
              </div>

              <div className="mb-2 flex justify-between">
                <span className="text-gray-600">ราคาสินค้ารวม</span>
                <span className="font-medium">
                  ฿{subtotal.toFixed(2)}
                </span>
              </div>

              <div className="mb-1 flex justify-between">
                <span className="text-gray-600">ค่าจัดส่ง</span>
                <span className="font-medium">
                  {shipping === 0 && subtotal > 0
                    ? 'ฟรี'
                    : `฿${shipping.toFixed(2)}`}
                </span>
              </div>

              <div className="mb-4 text-xs text-gray-500">
                ยอดรวม 1,000 บาทขึ้นไป ส่งฟรีอัตโนมัติ
              </div>

              <div className="mb-1 flex justify-between text-xs text-gray-500">
                <span>ยอดรวมก่อนหักส่วนลด</span>
                <span>฿{totalBeforeDiscount.toFixed(2)}</span>
              </div>

              {couponDiscount > 0 && (
                <div className="mb-2 flex justify-between text-xs text-green-600">
                  <span>ส่วนลดจากคูปอง</span>
                  <span>- ฿{couponDiscount.toFixed(2)}</span>
                </div>
              )}

              <div className="mb-6 flex justify-between text-base font-semibold text-gray-900">
                <span>ยอดรวมทั้งสิ้น</span>
                <span>฿{total.toFixed(2)}</span>
              </div>

              <button
                className={`w-full rounded-xl py-3 text-sm font-semibold text-white transition-colors ${
                  selectedItems.length === 0
                    ? 'cursor-not-allowed bg-gray-300'
                    : 'bg-[#0b2f27] hover:bg-[#13493d]'
                }`}
                disabled={selectedItems.length === 0}
                onClick={handlePayment}
              >
                ชำระเงิน
              </button>
            </div>
          </section>
        </div>
      </div>
    </div>
  )
}

export default Cartpage
