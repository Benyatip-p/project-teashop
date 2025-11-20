import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useShop } from '../context/ShopContext';

const Cartpage = () => {
  const navigate = useNavigate();
  const { cart, removeFromCart, updateCartQty } = useShop();

  // ✅ โหลดรายการที่เคยติ้ก จาก localStorage
  const [selectedIds, setSelectedIds] = useState(() => {
    const stored = localStorage.getItem('cartSelectedIds');
    return stored ? JSON.parse(stored) : [];
  });

  // ✅ โหลดคูปอง/ข้อความจาก localStorage
  const [couponInput, setCouponInput] = useState(() => {
    return localStorage.getItem('couponInput') || '';
  });
  const [appliedCoupon, setAppliedCoupon] = useState(() => {
    const stored = localStorage.getItem('appliedCoupon');
    return stored ? JSON.parse(stored) : null;
  });
  const [couponError, setCouponError] = useState(() => {
    return localStorage.getItem('couponError') || '';
  });

  // ---------- useEffect ทั้งหมดต้องอยู่ก่อนคำนวณ/return ----------

  // sync selectedIds กับ cart (ลบ id ที่ไม่มีใน cart แล้ว)
  useEffect(() => {
    setSelectedIds(prev =>
      prev.filter(id => cart.some(item => item.id === id))
    );
  }, [cart]);

  // บันทึก selectedIds ลง localStorage
  useEffect(() => {
    localStorage.setItem('cartSelectedIds', JSON.stringify(selectedIds));
  }, [selectedIds]);

  // บันทึก couponInput ลง localStorage
  useEffect(() => {
    localStorage.setItem('couponInput', couponInput);
  }, [couponInput]);

  // บันทึก appliedCoupon ลง localStorage
  useEffect(() => {
    if (appliedCoupon) {
      localStorage.setItem('appliedCoupon', JSON.stringify(appliedCoupon));
    } else {
      localStorage.removeItem('appliedCoupon');
    }
  }, [appliedCoupon]);

  // บันทึก couponError ลง localStorage
  useEffect(() => {
    localStorage.setItem('couponError', couponError);
  }, [couponError]);

  // คำนวณรายการที่เลือก
  const selectedItems = cart.filter(item => selectedIds.includes(item.id));

  const subtotal = selectedItems.reduce(
    (sum, item) => sum + (item.price || 0) * (item.qty || 1),
    0
  );

  const shipping = subtotal === 0 ? 0 : (subtotal >= 1000 ? 0 : 50);

  // ส่วนลดจากคูปอง (ใช้เฉพาะตอนมียอด >= 700)
  const couponDiscount =
    appliedCoupon && appliedCoupon.code === 'happy20' && subtotal >= 700
      ? 20
      : 0;

  const totalBeforeDiscount = subtotal + shipping;
  const total = Math.max(totalBeforeDiscount - couponDiscount, 0);

  // ถ้ามียอดเปลี่ยน ให้เช็กเงื่อนไขของคูปองอัตโนมัติ
  useEffect(() => {
    if (!appliedCoupon) return;

    // ยังไม่ได้เลือกสินค้าเลย
    if (selectedItems.length === 0) {
      setCouponError('กรุณาเลือกสินค้าที่ต้องการใช้คูปอง');
      return;
    }

    // เลือกสินค้าแล้ว แต่ยอดยังไม่ถึง 700
    if (subtotal < 700) {
      setCouponError('โค้ดส่วนลดนี้ต้องมียอดสั่งซื้อขั้นต่ำ 700 บาท');
      return;
    }

    // ยอดถึง 700 และเลือกสินค้าแล้ว → ไม่มี error
    setCouponError('');
  }, [subtotal, appliedCoupon, selectedItems.length]);

  // ---------- handler ต่าง ๆ ----------

  const handleDecrease = (item) => {
    const currentQty = item.qty || 1;
    if (currentQty <= 1) return;
    updateCartQty(item.id, currentQty - 1);
  };

  const handleIncrease = (item) => {
    const currentQty = item.qty || 1;
    updateCartQty(item.id, currentQty + 1);
  };

  const allSelected = selectedIds.length === cart.length && cart.length > 0;

  const handleToggleSelectAll = () => {
    if (allSelected) {
      setSelectedIds([]);
    } else {
      setSelectedIds(cart.map(item => item.id));
    }
  };

  const handleToggleSelectItem = (id) => {
    setSelectedIds(prev =>
      prev.includes(id)
        ? prev.filter(itemId => itemId !== id)
        : [...prev, id]
    );
  };

  const handleApplyCoupon = () => {
    const code = couponInput.trim().toLowerCase();
    setCouponError('');

    // ไม่กรอกอะไร → เคลียร์คูปอง
    if (!code) {
      setAppliedCoupon(null);
      return;
    }

    // ใส่โค้ดผิด
    if (code !== 'happy20') {
      setAppliedCoupon(null);
      setCouponError('ไม่พบรหัสส่วนลดนี้');
      return;
    }

    // โค้ดถูก → “จำคูปองไว้ทันที” แล้วใช้ useEffect เป็นคนเช็กยอดกับการเลือกสินค้า
    setAppliedCoupon({ code: 'happy20', discount: 20 });

    // ถ้า ณ ตอนกด ยอดยังไม่ถึง หรือยังไม่ได้เลือกสินค้า
    // useEffect ด้านบนจะเป็นคนตั้งข้อความ error ให้เอง
  };

  // ปุ่มกากบาท ล้างโค้ด
  const handleClearCouponInput = () => {
    setCouponInput('');
    setAppliedCoupon(null);
    setCouponError('');
    // localStorage จะอัปเดตจาก useEffect เอง
  };

  const handlePayment = () => {
    if (selectedItems.length === 0) {
      alert('กรุณาเลือกสินค้าที่ต้องการชำระเงิน');
      return;
    }

    navigate('/payment', {
      state: {
        selectedItems,
        shipping,
        couponDiscount,
        subtotal,
        totalBeforeDiscount,
        total,
      }
    });
  };


  // ---------- render ----------

  return (
    <div className="container mx-auto px-4 py-8">
      <h1 className="text-4xl font-semibold mb-6">ตะกร้าสินค้า</h1>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* ซ้าย: รายการสินค้า */}
        <div className="lg:col-span-2">
          <div className="flex items-center gap-2 border-b pb-3 mb-2">
            <input
              type="checkbox"
              className="w-4 h-4 accent-red-500"
              checked={allSelected}
              onChange={handleToggleSelectAll}
              disabled={cart.length === 0}   // ถ้าตะกร้าว่าง ติ๊กไม่ได้
            />
            <span className="text-sm">เลือกทั้งหมด</span>
          </div>

          <div className="space-y-4">
            {cart.length === 0 ? (
              <div className="py-10 text-center text-gray-500">
                ไม่มีสินค้าในตะกร้า
              </div>
            ) : (
              [...cart].reverse().map((item, index) => (
                <div key={item.id}>
                  <div className="flex items-center py-4 gap-4">
                    <input
                      type="checkbox"
                      className="w-4 h-4 mr-2 accent-red-500"
                      checked={selectedIds.includes(item.id)}
                      onChange={() => handleToggleSelectItem(item.id)}
                    />

                    <div className="w-24 flex-shrink-0">
                      <img
                        src={item.coverImage || item.image}
                        alt={item.title}
                        className="w-20 h-20 object-cover"
                      />
                    </div>

                    <div className="flex-1 min-w-0">
                      <div className="font-medium truncate">
                        {item.title}
                      </div>
                    </div>

                    <div className="w-32 flex items-center justify-center">
                      <div className="inline-flex items-center border border-gray-300">
                        <button
                          type="button"
                          className="px-3 py-1 text-sm text-gray-500"
                          onClick={() => handleDecrease(item)}
                        >
                          -
                        </button>
                        <span className="px-4 py-1 text-sm border-l border-r border-gray-300 bg-gray-50">
                          {item.qty || 1}
                        </span>
                        <button
                          type="button"
                          className="px-3 py-1 text-sm text-gray-500"
                          onClick={() => handleIncrease(item)}
                        >
                          +
                        </button>
                      </div>
                    </div>

                    <div className="w-32 text-right text-sm">
                      <div className="font-medium">
                        ฿{((item.price || 0) * (item.qty || 1)).toFixed(2)}
                      </div>
                      <button
                        className="mt-1 text-xs text-red-500 hover:underline"
                        onClick={() => removeFromCart(item.id)}
                      >
                        ลบ
                      </button>
                    </div>
                  </div>

                  {index !== cart.length - 1 && <hr />}
                </div>
              ))
            )}
          </div>
        </div>

        {/* ขวา: คูปอง + สรุปยอด */}
        <div className="space-y-4">
          {/* คูปอง */}
          <div>
            <div className="text-sm font-medium mb-2">คูปองส่วนลด</div>

            <div className="flex items-center">
              <div className="relative flex-1">
                <input
                  type="text"
                  placeholder="กรอกรหัสคูปอง"
                  className="w-full border border-gray-300 px-3 py-2 text-sm pr-8 focus:outline-none"
                  value={couponInput}
                  onChange={(e) => setCouponInput(e.target.value)}
                />
                {couponInput && (
                  <button
                    type="button"
                    onClick={handleClearCouponInput}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600 text-sm"
                  >
                    ✕
                  </button>
                )}
              </div>

              <button
                className="ml-2 px-4 py-2 bg-gray-500 text-white text-sm"
                type="button"
                onClick={handleApplyCoupon}
              >
                ใช้คูปอง
              </button>
            </div>

            {couponError && (
              <p className="mt-1 text-xs text-red-500">{couponError}</p>
            )}
            {appliedCoupon && !couponError && (
              <p className="mt-1 text-xs text-green-600">
                ใช้คูปอง {appliedCoupon.code.toUpperCase()} แล้ว
              </p>
            )}
          </div>

          {/* สรุปคำสั่งซื้อ */}
          <div className="border border-gray-300 p-5 text-sm">
            <div className="font-medium mb-4">สรุปรายการสั่งซื้อ</div>

            <div className="flex justify-between mb-2">
              <span>ราคาสินค้ารวม</span>
              <span>฿{subtotal.toFixed(2)}</span>
            </div>

            <div className="flex justify-between mb-2 ">
              <span>ค่าจัดส่ง</span>
              <span>
                {shipping === 0 && subtotal > 0 ? 'ฟรี' : `฿${shipping.toFixed(2)}`}
              </span>
            </div>
            <div className="flex justify-between mb-1 text-xs text-gray-500">
              <span>ยอดรวม 1,000 บาทขึ้นไปฟรีค่าจัดส่ง</span>
            </div>

            <hr className="my-4" />

            <div className="flex justify-between mb-1 text-xs text-gray-500">
              <span>ยอดรวม</span>
              <span>฿{totalBeforeDiscount.toFixed(2)}</span>
            </div>
            
            {couponDiscount > 0 && (
              <div className="flex justify-between mb-2 text-xs text-green-600">
                <span>ส่วนลด (คูปอง)</span>
                <span>- ฿{couponDiscount.toFixed(2)}</span>
              </div>
            )}

            <div className="flex justify-between mb-6 font-semibold">
              <span>ยอดรวมทั้งสิ้น</span>
              <span>฿{total.toFixed(2)}</span>
            </div>

            <button
              className="w-full py-3 bg-green-600 hover:bg-green-700 text-white text-sm font-medium"
              disabled={selectedItems.length === 0}
              onClick={handlePayment}
            >
              ชำระเงิน
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Cartpage;