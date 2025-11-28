import React, { useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";

const Paymentpage = () => {
  const location = useLocation();
  const navigate = useNavigate();

  const selectedItems = location.state?.selectedItems || [];
  const cartSubtotal = location.state?.subtotal || 0;
  const cartShipping = location.state?.shipping || 0;
  const cartCouponDiscount = location.state?.couponDiscount || 0;
  const cartTotalBeforeDiscount = location.state?.totalBeforeDiscount || 0;
  const cartTotal = location.state?.total || 0;

  const [shipping, setShipping] = useState({
    name: "",
    phone: "",
    address: "",
    province: "",
    district: "",
    subDistrict: "",
    zipcode: "",
  });

  const [paymentMethod, setPaymentMethod] = useState("");
  const [triedSubmit, setTriedSubmit] = useState(false);

  if (!selectedItems || selectedItems.length === 0) {
    return (
      <div className="container mx-auto px-4 py-8">
        <h1 className="mb-6 text-4xl font-semibold">หน้าชำระเงิน</h1>
        <div className="text-center text-gray-500">
          ไม่มีสินค้าเลือกมาชำระเงิน
        </div>
      </div>
    );
  }

  const calculateSubtotal = () =>
    selectedItems.reduce((sum, item) => {
      const qty = item.qty || 1;
      return sum + item.price * qty;
    }, 0);

  const subtotal = calculateSubtotal();

  const handleChange = e => {
    const { name, value } = e.target;
    setShipping(prev => ({ ...prev, [name]: value }));
  };

  const handleSubmit = e => {
    e.preventDefault();

    if (!triedSubmit) {
      setTriedSubmit(true);
    }

    if (!paymentMethod) {
      return;
    }

    console.log("ORDER DATA:", {
      items: selectedItems,
      shipping,
      paymentMethod,
      subtotal: cartSubtotal,
      shippingFee: cartShipping,
      couponDiscount: cartCouponDiscount,
      totalBeforeDiscount: cartTotalBeforeDiscount,
      total: cartTotal,
    });

    alert("สั่งซื้อเรียบร้อย (ตัวอย่าง)");
  };

  return (
    <div className="container mx-auto px-4 py-8">
      <h1 className="mb-6 text-4xl font-semibold">หน้าชำระเงิน</h1>

      <button
        type="button"
        onClick={() => navigate("/cart")}
        className="mb-6 rounded bg-gray-500 px-4 py-2 text-sm text-white hover:bg-gray-700"
      >
        ← ย้อนกลับ
      </button>

      <form onSubmit={handleSubmit}>
        <div className="grid grid-cols-1 gap-8 lg:grid-cols-3">
          <div className="space-y-8 lg:col-span-2">
            <div className="space-y-4 rounded-lg bg-white p-6 shadow">
              <h2 className="mb-4 text-xl font-semibold">ที่อยู่ในการจัดส่ง</h2>

              <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                <div>
                  <label className="mb-1 block text-sm">
                    ชื่อ <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    name="name"
                    value={shipping.name}
                    onChange={handleChange}
                    className="w-full rounded border px-3 py-2"
                    required
                  />
                </div>

                <div>
                  <label className="mb-1 block text-sm">
                    โทรศัพท์ <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="tel"
                    name="phone"
                    value={shipping.phone}
                    onChange={handleChange}
                    className="w-full rounded border px-3 py-2"
                    required
                  />
                </div>

                <div className="md:col-span-2">
                  <label className="mb-1 block text-sm">
                    ที่อยู่ <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    name="address"
                    value={shipping.address}
                    onChange={handleChange}
                    className="h-20 w-full rounded border px-3 py-2"
                    required
                  />
                </div>

                <div>
                  <label className="mb-1 block text-sm">
                    จังหวัด <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    name="province"
                    value={shipping.province}
                    onChange={handleChange}
                    className="w-full rounded border px-3 py-2"
                    required
                  />
                </div>

                <div>
                  <label className="mb-1 block text-sm">
                    อำเภอ <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    name="district"
                    value={shipping.district}
                    onChange={handleChange}
                    className="w-full rounded border px-3 py-2"
                    required
                  />
                </div>

                <div>
                  <label className="mb-1 block text-sm">
                    ตำบล <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    name="subDistrict"
                    value={shipping.subDistrict}
                    onChange={handleChange}
                    className="w-full rounded border px-3 py-2"
                    required
                  />
                </div>

                <div>
                  <label className="mb-1 block text-sm">
                    รหัสไปรษณีย์ <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    name="zipcode"
                    value={shipping.zipcode}
                    onChange={handleChange}
                    className="w-full rounded border px-3 py-2"
                    required
                  />
                </div>
              </div>
            </div>

            <section className="rounded-lg bg-white p-6 shadow">
              <h2 className="mb-4 text-xl font-semibold">วิธีการชำระเงิน</h2>

              <div className="space-y-4">
                <label className="flex cursor-pointer items-start gap-3">
                  <input
                    type="radio"
                    name="paymentMethod"
                    value="card"
                    checked={paymentMethod === "card"}
                    onChange={e => setPaymentMethod(e.target.value)}
                    className="mt-1"
                  />
                  <div>
                    <div className="font-medium">
                      ชำระผ่านบัตรเครดิต / เดบิต
                    </div>
                    <div className="text-sm text-gray-500">
                      Visa, MasterCard, JCB
                    </div>
                  </div>
                </label>

                {paymentMethod === "card" && (
                  <div className="mt-2 grid grid-cols-1 gap-4 md:grid-cols-2">
                    <div className="md:col-span-2">
                      <label className="mb-1 block text-sm text-gray-700">
                        เลขที่บัตร
                      </label>
                      <input
                        type="text"
                        className="w-full rounded-md border px-3 py-2 focus:outline-none focus:ring-2 focus:ring-green-500"
                        placeholder="XXXX XXXX XXXX XXXX"
                      />
                    </div>
                    <div>
                      <label className="mb-1 block text-sm text-gray-700">
                        วันหมดอายุ
                      </label>
                      <input
                        type="text"
                        className="w-full rounded-md border px-3 py-2 focus:outline-none focus:ring-2 focus:ring-green-500"
                        placeholder="MM/YY"
                      />
                    </div>
                    <div>
                      <label className="mb-1 block text-sm text-gray-700">
                        CVV
                      </label>
                      <input
                        type="password"
                        className="w-full rounded-md border px-3 py-2 focus:outline-none focus:ring-2 focus:ring-green-500"
                        placeholder="XXX"
                      />
                    </div>
                  </div>
                )}

                <label className="flex cursor-pointer items-start gap-3">
                  <input
                    type="radio"
                    name="paymentMethod"
                    value="bank"
                    checked={paymentMethod === "bank"}
                    onChange={e => setPaymentMethod(e.target.value)}
                    className="mt-1"
                  />
                  <div>
                    <div className="font-medium">โอนเงินผ่านธนาคาร</div>
                    <div className="text-sm text-gray-500">
                      โอนเข้าบัญชีธนาคาร แล้วแนบหลักฐานการโอน
                    </div>
                  </div>
                </label>

                {paymentMethod === "bank" && (
                  <div className="mt-2 space-y-2 text-sm text-gray-700">
                    <p>เลขบัญชี: 123-4-56789-0 ธนาคารตัวอย่าง สาขากรุงเทพ</p>
                    <p>
                      หลังโอนเงินแล้ว กรุณาอัปโหลดสลิปในหน้าตรวจสอบคำสั่งซื้อ
                    </p>
                  </div>
                )}

                <label className="flex cursor-pointer items-start gap-3">
                  <input
                    type="radio"
                    name="paymentMethod"
                    value="cod"
                    checked={paymentMethod === "cod"}
                    onChange={e => setPaymentMethod(e.target.value)}
                    className="mt-1"
                  />
                  <div>
                    <div className="font-medium">ชำระเงินปลายทาง (COD)</div>
                    <div className="text-sm text-gray-500">
                      จ่ายกับพนักงานจัดส่งเมื่อได้รับสินค้า
                    </div>
                  </div>
                </label>
              </div>
            </section>
          </div>

          <div className="h-fit space-y-4 rounded-lg bg-white p-6 shadow">
            <h2 className="mb-4 text-xl font-semibold">สรุปรายการสั่งซื้อ</h2>

            {selectedItems.map(item => (
              <div key={item.id} className="flex items-center gap-4">
                <img
                  src={item.coverImage || item.image}
                  alt={item.title}
                  className="h-16 w-16 rounded object-cover"
                />
                <div className="flex-1">
                  <div className="text-sm font-medium">{item.title}</div>
                  <div className="text-xs text-gray-600">
                    จำนวน: {item.qty || 1}
                  </div>
                </div>
                <div className="text-sm font-semibold text-green-700">
                  ฿{(item.price * (item.qty || 1)).toLocaleString()}
                </div>
              </div>
            ))}

            <hr />

            <div className="flex justify-between text-sm">
              <span>ราคารวมสินค้า</span>
              <span>฿{subtotal.toLocaleString()}</span>
            </div>

            <div className="flex justify-between text-sm">
              <span>ค่าจัดส่ง</span>
              <span>
                {cartShipping === 0 && cartSubtotal > 0
                  ? "ฟรี"
                  : `฿${cartShipping.toFixed(2)}`}
              </span>
            </div>

            <div className="flex justify-between text-xs text-gray-500">
              <span>ยอดรวม</span>
              <span>฿{cartTotalBeforeDiscount.toFixed(2)}</span>
            </div>

            {cartCouponDiscount > 0 && (
              <div className="flex justify-between text-xs text-green-600">
                <span>ส่วนลด (คูปอง)</span>
                <span>- ฿{cartCouponDiscount.toFixed(2)}</span>
              </div>
            )}

            <div className="mt-2 flex justify-between font-semibold">
              <span>ยอดรวมทั้งสิ้น</span>
              <span>฿{cartTotal.toFixed(2)}</span>
            </div>

            {triedSubmit && !paymentMethod && (
              <div className="mt-2 text-left text-sm text-red-500">
                กรุณาเลือกวิธีการชำระเงิน
              </div>
            )}

            <button
              type="submit"
              className={`mt-4 w-full rounded py-2 text-white ${
                triedSubmit && !paymentMethod
                  ? "cursor-not-allowed bg-green-300"
                  : "bg-green-600 hover:bg-green-700"
              }`}
              disabled={triedSubmit && !paymentMethod}
            >
              ยืนยันการสั่งซื้อ
            </button>
          </div>
        </div>
      </form>
    </div>
  );
};

export default Paymentpage;
