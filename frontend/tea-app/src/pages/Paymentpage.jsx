import React, { useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";

const Paymentpage = () => {
  const location = useLocation();
  const navigate = useNavigate();

  const selectedItems = location.state?.selectedItems || [];

  // รับค่าจัดส่งจาก Cart (ถ้าส่งมาด้วย)
  const initialShippingFee = location.state?.shippingFee || 0;
  const initialShippingMethod = location.state?.shippingMethod || "";

  // ดึงค่าที่ส่งมาจาก Cart
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

  const [shippingMethod, setShippingMethod] = useState(initialShippingMethod);
  const [shippingFee] = useState(initialShippingFee);

  // "", "card", "bank", "cod"
  const [paymentMethod, setPaymentMethod] = useState("");

  // เช็กว่ามีการกด submit มาแล้วหรือยัง
  const [triedSubmit, setTriedSubmit] = useState(false);

  if (!selectedItems || selectedItems.length === 0) {
    return (
      <div className="container mx-auto px-4 py-8">
        <h1 className="text-4xl font-semibold mb-6">หน้าชำระเงิน</h1>
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
  const total = subtotal + shippingFee;

  const handleChange = (e) => {
    const { name, value } = e.target;
    setShipping((prev) => ({ ...prev, [name]: value }));
  };

  const handleSubmit = (e) => {
    e.preventDefault();

    // กด submit ครั้งแรก / ครั้งถัดๆ ไป ให้ตั้งค่านี้เป็น true
    if (!triedSubmit) {
      setTriedSubmit(true);
    }

    // ถ้ายังไม่เลือกวิธีชำระเงิน ให้หยุดแค่นี้ (ไม่ alert)
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
      <h1 className="text-4xl font-semibold mb-6">หน้าชำระเงิน</h1>

      <button
        type="button"
        onClick={() => navigate("/cart")}
        className="text-sm text-white px-4 py-2 rounded bg-gray-500 hover:bg-gray-700 mb-6"
      >
        ← ย้อนกลับ
      </button>

      <form onSubmit={handleSubmit}>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* ซ้าย: ที่อยู่ + วิธีชำระเงิน */}
          <div className="lg:col-span-2 space-y-8">
            {/* ที่อยู่จัดส่ง */}
            <div className="bg-white shadow rounded-lg p-6 space-y-4">
              <h2 className="text-xl font-semibold mb-4">
                ที่อยู่ในการจัดส่ง
              </h2>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm mb-1">
                    ชื่อ <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    name="name"
                    value={shipping.name}
                    onChange={handleChange}
                    className="w-full border rounded px-3 py-2"
                    required
                  />
                </div>

                <div>
                  <label className="block text-sm mb-1">
                    โทรศัพท์ <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="tel"
                    name="phone"
                    value={shipping.phone}
                    onChange={handleChange}
                    className="w-full border rounded px-3 py-2"
                    required
                  />
                </div>

                <div className="md:col-span-2">
                  <label className="block text-sm mb-1">
                    ที่อยู่ <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    name="address"
                    value={shipping.address}
                    onChange={handleChange}
                    className="w-full border rounded px-3 py-2 h-20"
                    required
                  />
                </div>

                <div>
                  <label className="block text-sm mb-1">
                    จังหวัด <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    name="province"
                    value={shipping.province}
                    onChange={handleChange}
                    className="w-full border rounded px-3 py-2"
                    required
                  />
                </div>

                <div>
                  <label className="block text-sm mb-1">
                    อำเภอ <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    name="district"
                    value={shipping.district}
                    onChange={handleChange}
                    className="w-full border rounded px-3 py-2"
                    required
                  />
                </div>

                <div>
                  <label className="block text-sm mb-1">
                    ตำบล <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    name="subDistrict"
                    value={shipping.subDistrict}
                    onChange={handleChange}
                    className="w-full border rounded px-3 py-2"
                    required
                  />
                </div>

                <div>
                  <label className="block text-sm mb-1">
                    รหัสไปรษณีย์ <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    name="zipcode"
                    value={shipping.zipcode}
                    onChange={handleChange}
                    className="w-full border rounded px-3 py-2"
                    required
                  />
                </div>
              </div>
            </div>

            {/* วิธีชำระเงิน */}
            <section className="bg-white rounded-lg shadow p-6">
              <h2 className="text-xl font-semibold mb-4">
                วิธีการชำระเงิน
              </h2>

              <div className="space-y-4">
                {/* ชำระผ่านบัตร */}
                <label className="flex items-start gap-3 cursor-pointer">
                  <input
                    type="radio"
                    name="paymentMethod"
                    value="card"
                    checked={paymentMethod === "card"}
                    onChange={(e) => setPaymentMethod(e.target.value)}
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
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-2">
                    <div className="md:col-span-2">
                      <label className="block text-sm text-gray-700 mb-1">
                        เลขที่บัตร
                      </label>
                      <input
                        type="text"
                        className="w-full border rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-green-500"
                        placeholder="XXXX XXXX XXXX XXXX"
                      />
                    </div>
                    <div>
                      <label className="block text-sm text-gray-700 mb-1">
                        วันหมดอายุ
                      </label>
                      <input
                        type="text"
                        className="w-full border rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-green-500"
                        placeholder="MM/YY"
                      />
                    </div>
                    <div>
                      <label className="block text-sm text-gray-700 mb-1">
                        CVV
                      </label>
                      <input
                        type="password"
                        className="w-full border rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-green-500"
                        placeholder="XXX"
                      />
                    </div>
                  </div>
                )}

                {/* โอนเงินผ่านธนาคาร */}
                <label className="flex items-start gap-3 cursor-pointer">
                  <input
                    type="radio"
                    name="paymentMethod"
                    value="bank"
                    checked={paymentMethod === "bank"}
                    onChange={(e) => setPaymentMethod(e.target.value)}
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

                {/* เก็บเงินปลายทาง */}
                <label className="flex items-start gap-3 cursor-pointer">
                  <input
                    type="radio"
                    name="paymentMethod"
                    value="cod"
                    checked={paymentMethod === "cod"}
                    onChange={(e) => setPaymentMethod(e.target.value)}
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

          {/* ขวา: สรุปรายการสั่งซื้อ */}
          <div className="bg-white shadow rounded-lg p-6 h-fit space-y-4">
            <h2 className="text-xl font-semibold mb-4">สรุปรายการสั่งซื้อ</h2>

            {selectedItems.map((item) => (
              <div key={item.id} className="flex items-center gap-4">
                <img
                  src={item.coverImage || item.image}
                  alt={item.title}
                  className="w-16 h-16 object-cover rounded"
                />
                <div className="flex-1">
                  <div className="font-medium text-sm">{item.title}</div>
                  <div className="text-gray-600 text-xs">
                    จำนวน: {item.qty || 1}
                  </div>
                </div>
                <div className="text-green-700 font-semibold text-sm">
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

            <div className="flex justify-between mt-2 font-semibold">
              <span>ยอดรวมทั้งสิ้น</span>
              <span>฿{cartTotal.toFixed(2)}</span>
            </div>

            {/* ข้อความแดงด้านขวา โผล่เฉพาะตอนกด submit แล้วแต่ยังไม่เลือกวิธีชำระเงิน */}
            {triedSubmit && !paymentMethod && (
              <div className="mt-2 text-left text-sm text-red-500">
                กรุณาเลือกวิธีการชำระเงิน
              </div>
            )}

            <button
              type="submit"
              className={`w-full mt-4 text-white py-2 rounded
                ${
                  triedSubmit && !paymentMethod
                    ? "bg-green-300 cursor-not-allowed"
                    : "bg-green-600 hover:bg-green-700"
                }`}
              // disable หลังจากกดแล้ว 1 ครั้งขึ้นไป แต่ยังไม่เลือก method
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