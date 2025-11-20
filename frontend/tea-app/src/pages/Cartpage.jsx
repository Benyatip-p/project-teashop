import React from 'react';
import { useShop } from '../context/ShopContext';

const Cartpage = () => {
  const { cart, removeFromCart, updateCartQty } = useShop();

  if (cart.length === 0) {
    return (
      <div className="container mx-auto px-4 py-8">
        ตะกร้าสินค้าว่าง
      </div>
    );
  }

  const subtotal = cart.reduce(
    (sum, item) => sum + (item.price || 0) * (item.qty || 1),
    0
  );
  const shipping = 50; // ใส่ค่าคงที่ไปก่อน
  const total = subtotal + shipping;

  const handleDecrease = (item) => {
    const currentQty = item.qty || 1;
    if (currentQty <= 1) return; // ไม่ให้ต่ำกว่า 1
    updateCartQty(item.id, currentQty - 1);
  };

  const handleIncrease = (item) => {
    const currentQty = item.qty || 1;
    updateCartQty(item.id, currentQty + 1);
  };

  return (
    <div className="container mx-auto px-4 py-8">
      {/* หัวข้อ */}
      <h1 className="text-2xl font-semibold mb-6">ตะกร้าสินค้า</h1>

      {/* layout 2 คอลัมน์ */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* ซ้าย: รายการสินค้า */}
        <div className="lg:col-span-2">
          {/* แถวเลือกทั้งหมด */}
          <div className="flex items-center gap-2 border-b pb-3 mb-2">
            <input type="checkbox" className="w-4 h-4" />
            <span className="text-sm">เลือกทั้งหมด</span>
          </div>

          <div className="space-y-4">
            {cart.map((item, index) => (
              <div key={item.id}>
                <div className="flex items-center py-4 gap-4">
                  {/* checkbox ต่อชิ้น */}
                  <input type="checkbox" className="w-4 h-4 mr-2" />

                  {/* รูป */}
                  <div className="w-24 flex-shrink-0">
                    <img
                      src={item.coverImage || item.image}
                      alt={item.title}
                      className="w-20 h-20 object-cover"
                    />
                  </div>

                  {/* ชื่อ */}
                  <div className="flex-1 min-w-0">
                    <div className="font-medium truncate">
                      {item.title}
                    </div>
                  </div>

                  {/* จำนวน + ปุ่ม - / + */}
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

                  {/* ราคา & ปุ่มลบ */}
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
            ))}
          </div>
        </div>

        {/* ขวา: คูปอง + สรุปยอด */}
        <div className="space-y-4">
          {/* คูปอง */}
          <div>
            <div className="text-sm font-medium mb-2">คูปองส่วนลด</div>
            <div className="flex">
              <input
                type="text"
                placeholder="coupon code"
                className="flex-1 border border-gray-300 px-3 py-2 text-sm focus:outline-none"
              />
              <button className="ml-2 px-4 py-2 bg-gray-500 text-white text-sm">
                ใช้คูปอง
              </button>
            </div>
          </div>

          {/* สรุปคำสั่งซื้อ */}
          <div className="border border-gray-300 p-5 text-sm">
            <div className="font-medium mb-4">สรุปรายการสั่งซื้อ</div>

            <div className="flex justify-between mb-2">
              <span>ราคาสินค้ารวม</span>
              <span>฿{subtotal.toFixed(2)}</span>
            </div>

            <div className="flex justify-between mb-4">
              <span>ค่าจัดส่ง</span>
              <span>฿{shipping.toFixed(2)}</span>
            </div>

            <hr className="my-4" />

            <div className="flex justify-between mb-6 font-semibold">
              <span>ยอดรวมทั้งสิ้น</span>
              <span>฿{total.toFixed(2)}</span>
            </div>

            <button className="w-full py-3 bg-gray-500 text-white text-sm font-medium">
              ชำระเงิน
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Cartpage;