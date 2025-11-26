import React, { useState, useEffect } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { ToastContainer, toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import Select from "react-select"; 

const Paymentpage = () => {
  const location = useLocation();
  const navigate = useNavigate();

  const selectedItems = location.state?.selectedItems || [];

  const initialShippingFee = location.state?.shippingFee || 0;
  const initialShippingMethod = location.state?.shippingMethod || "";

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

  const [errors, setErrors] = useState({});
  const [provinces, setProvinces] = useState([]);

  const [shippingMethod, setShippingMethod] = useState(initialShippingMethod);
  const [shippingFee] = useState(initialShippingFee);

  const [paymentMethod, setPaymentMethod] = useState("");

  // state สำหรับบัตร
  const [cardNumber, setCardNumber] = useState("");
  const [cardError, setCardError] = useState("");
  const [cardType, setCardType] = useState(""); // "visa" | "master" | ""

  const [triedSubmit, setTriedSubmit] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);

  // โหลดรายการจังหวัดจากไฟล์ / API
  useEffect(() => {
    const fetchProvinces = async () => {
      try {
        const res = await fetch("/provinces.json");
        const data = await res.json();
        // แปลงข้อมูลให้มี key เป็น value และ label
        const formattedProvinces = data.map((p) => ({
          value: p.name, // ค่าจริงที่จะใช้
          label: p.name, // ข้อความที่แสดงให้ผู้ใช้เห็นและใช้ค้นหา
        }));
        setProvinces(formattedProvinces);
      } catch (err) {
        console.error("โหลดจังหวัดไม่สำเร็จ:", err);
      }
    };
    fetchProvinces();
  }, []);

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

  // validate เฉพาะ field เดียว (ไม่รวม phone)
  const validateField = (name, value) => {
    let error = "";

    if (name === "name") {
      if (!value.trim()) {
        error = "กรุณากรอกชื่อ";
      }
    }

    if (name === "address") {
      if (!value.trim()) {
        error = "กรุณากรอกที่อยู่";
      }
    }

    if (name === "province") {
      if (!value) {
        error = "กรุณาเลือกจังหวัด";
      }
    }

    if (name === "district") {
      if (!value.trim()) {
        error = "กรุณากรอกอำเภอ";
      }
    }

    if (name === "subDistrict") {
      if (!value.trim()) {
        error = "กรุณากรอกตำบล";
      }
    }

    if (name === "zipcode") {
      if (!value.trim()) {
        error = "กรุณากรอกรหัสไปรษณีย์";
      } else if (!/^[0-9]{5}$/.test(value.trim())) {
        error = "รหัสไปรษณีย์ต้องเป็นตัวเลข 5 หลัก";
      }
    }

    // ไม่จัดการ phone ที่นี่
    if (name !== "phone") {
      setErrors((prev) => ({
        ...prev,
        [name]: error,
      }));
    }

    return !error;
  };

  // validate เบอร์โทร ใช้ทั้งตอน blur และตอน submit
  const validatePhone = (value) => {
    let error = "";
    const v = value.trim();

    if (!v) {
      error = "กรุณากรอกเบอร์โทรศัพท์";
    } else if (!/^\d+$/.test(v)) {
      error = "เบอร์โทรศัพท์ต้องเป็นตัวเลขเท่านั้น";
    } else if (v.length < 9) {
      // ปรับจำนวนหลักได้ตามต้องการ
      error = "เบอร์โทรศัพท์ต้องมีอย่างน้อย 9 หลัก";
    }

    setErrors((prev) => ({
      ...prev,
      phone: error,
    }));

    return !error;
  };

  // handle เปลี่ยนค่า input
  const handleChange = (e) => {
    const { name, value } = e.target;

    // เบอร์โทร: ให้พิมพ์ได้เฉพาะตัวเลข
    if (name === "phone") {
      if (!/^\d*$/.test(value)) {
        // ถ้าไม่ใช่ตัวเลข ไม่อัปเดต state
        return;
      }
    }

    setShipping((prev) => ({
      ...prev,
      [name]: value,
    }));

    // validate ทันทีสำหรับ field อื่น ๆ ยกเว้น phone
    if (name !== "phone") {
      validateField(name, value);
    }
  };
  const handleProvinceChange = (selectedOption) => {
    // selectedOption จะเป็น object { value: '...', label: '...' } หรือ null ถ้าผู้ใช้ลบค่า
    const provinceValue = selectedOption ? selectedOption.value : "";
    setShipping((prev) => ({
      ...prev,
      province: provinceValue,
    }));
    // เรียกใช้ validation ทันที
    validateField("province", provinceValue);
  };

  // validate ทั้งฟอร์มที่อยู่ (รวม phone ด้วย)
  const validateShipping = () => {
    const fields = [
      "name",
      "phone",
      "address",
      "province",
      "district",
      "subDistrict",
      "zipcode",
    ];

    let isValid = true;

    fields.forEach((field) => {
      const value = shipping[field];
      if (field === "phone") {
        const ok = validatePhone(value);
        if (!ok) isValid = false;
      } else {
        const ok = validateField(field, value);
        if (!ok) isValid = false;
      }
    });

    return isValid;
  };

  // ตรวจสอบเลขบัตร
  const validateCardNumber = () => {
    if (paymentMethod !== "card") {
      setCardError("");
      return true;
    }

    const clean = cardNumber.replace(/\s+/g, "");

    if (!clean) {
      setCardError("กรุณากรอกเลขบัตร");
      return false;
    }

    if (!/^\d+$/.test(clean)) {
      setCardError("เลขบัตรต้องเป็นตัวเลขเท่านั้น");
      return false;
    }

    if (clean.startsWith("4")) {
      if (clean.length !== 16) {
        setCardError("บัตร Visa ต้องมี 16 หลัก");
        return false;
      }
      setCardError("");
      return true;
    }

    if (clean.startsWith("5")) {
      if (clean.length !== 10) {
        setCardError("บัตร MasterCard ต้องมี 10 หลัก");
        return false;
      }
      setCardError("");
      return true;
    }

    setCardError(
      "รองรับเฉพาะบัตร Visa (ขึ้นต้น 4) และ MasterCard (ขึ้นต้น 5)"
    );
    return false;
  };

  const handleSubmit = (e) => {
    e.preventDefault();

    if (!triedSubmit) setTriedSubmit(true);

    // validate ที่อยู่ก่อน (รวมเบอร์โทร)
    const shippingOK = validateShipping();
    if (!shippingOK) return;

    // ต้องเลือกวิธีชำระเงิน
    if (!paymentMethod) {
      return;
    }

    // ถ้าเลือกบัตรให้เช็คเลขบัตรด้วย
    if (paymentMethod === "card") {
      const ok = validateCardNumber();
      if (!ok) return;
    }

    setIsProcessing(true);

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

    setTimeout(() => {
      setIsProcessing(false);

      toast.success("ชำระเงินสำเร็จ", {
        position: "top-right",
        autoClose: 2000,
        hideProgressBar: false,
        closeOnClick: true,
        pauseOnHover: false,
        draggable: true,
        className: "bg-green-900 text-white",
        bodyClassName: "text-sm",
      });

      setTimeout(() => {
        navigate("/");
      }, 2000);
    }, 2000);
  };

  // จัดการเลขบัตร
  const handleCardNumberChange = (e) => {
    const raw = e.target.value;
    if (!/^[0-9\s]*$/.test(raw)) return;

    let digits = raw.replace(/\s+/g, "");

    let currentType = cardType;
    if (!currentType && digits.length > 0) {
      if (digits.startsWith("4")) currentType = "visa";
      else if (digits.startsWith("5")) currentType = "master";
      else currentType = "";
      setCardType(currentType);
    }

    if (currentType === "visa") {
      digits = digits.slice(0, 16);
    } else if (currentType === "master") {
      digits = digits.slice(0, 10);
    }

    let formatted = digits;

    if (currentType === "visa") {
      formatted = digits.match(/.{1,4}/g)?.join(" ") || "";
    } else if (currentType === "master") {
      const part1 = digits.slice(0, 4);
      const part2 = digits.slice(4, 9);
      const part3 = digits.slice(9, 10);
      formatted = [part1, part2, part3].filter(Boolean).join(" ");
    } else {
      formatted = digits.match(/.{1,4}/g)?.join(" ") || "";
    }

    setCardNumber(formatted);
    setCardError("");
  };

  const handleCardFocus = () => {};

  return (
    <div className="container mx-auto px-4 py-8">
      <ToastContainer />

      <h1 className="text-4xl font-semibold mb-6">หน้าชำระเงิน</h1>

      <button
        type="button"
        onClick={() => navigate("/cart")}
        className="text-sm text-white px-4 py-2 rounded bg-gray-500 hover:bg-gray-700 mb-6"
        disabled={isProcessing}
      >
        ← ย้อนกลับ
      </button>

      <form onSubmit={handleSubmit}>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* ซ้าย: ฟอร์มที่อยู่ + วิธีชำระเงิน */}
          <div className="lg:col-span-2 space-y-8">
            {/* ที่อยู่จัดส่ง */}
            <div className="bg-white shadow rounded-lg p-6 space-y-4">
              <h2 className="text-xl font-semibold mb-4">
                ที่อยู่ในการจัดส่ง
              </h2>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* ชื่อ */}
                <div>
                  <label className="block text-sm mb-1">
                    ชื่อ <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    name="name"
                    value={shipping.name}
                    onChange={handleChange}
                    className={`w-full border rounded px-3 py-2 ${
                      errors.name ? "border-red-500" : "border-gray-300"
                    }`}
                  />
                  {errors.name && (
                    <p className="mt-1 text-xs text-red-500">
                      {errors.name}
                    </p>
                  )}
                </div>

                {/* โทรศัพท์ */}
                <div>
                  <label className="block text-sm mb-1">
                    โทรศัพท์ <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="tel"
                    name="phone"
                    value={shipping.phone}
                    onChange={handleChange}
                    onBlur={(e) => validatePhone(e.target.value)}
                    className={`w-full border rounded px-3 py-2 ${
                      errors.phone ? "border-red-500" : "border-gray-300"
                    }`}
                  />
                  {errors.phone && (
                    <p className="mt-1 text-xs text-red-500">
                      {errors.phone}
                    </p>
                  )}
                </div>

                {/* ที่อยู่ */}
                <div className="md:col-span-2">
                  <label className="block text-sm mb-1">
                    ที่อยู่ <span className="text-red-500">*</span>
                  </label>
                  <textarea
                    name="address"
                    value={shipping.address}
                    onChange={handleChange}
                    className={`w-full border rounded px-3 py-2 h-20 ${
                      errors.address ? "border-red-500" : "border-gray-300"
                    }`}
                  />
                  {errors.address && (
                    <p className="mt-1 text-xs text-red-500">
                      {errors.address}
                    </p>
                  )}
                </div>

                {/* จังหวัด (Dropdown) */}
                <div> {/* ไม่ต้องใช้ relative แล้ว */}
                  <label className="block text-sm mb-1">
                    จังหวัด <span className="text-red-500">*</span>
                  </label>
                  
                  {/* ใช้คอมโพเนนท์ Select ที่นี่ */}
                  <Select
                    instanceId="province-select" // ID เฉพาะสำหรับ accessibility
                    options={provinces}
                    onChange={handleProvinceChange}
                    value={provinces.find((p) => p.value === shipping.province)}
                    placeholder="-- เลือกจังหวัด --"
                    isClearable // อนุญาตให้ผู้ใช้กด x เพื่อลบค่าที่เลือก
                    noOptionsMessage={() => 'ไม่พบจังหวัดที่ค้นหา'}
                    styles={{
                      // ปรับแต่งสไตล์ให้เข้ากับ input อื่นๆ และแสดง error border
                      control: (baseStyles, state) => ({
                        ...baseStyles,
                        minHeight: '42px', // ปรับความสูงให้เท่า input อื่น
                        borderColor: errors.province ? '#ef4444' : (state.isFocused ? '#6366f1' : '#d1d5db'), // สีขอบตอน error, focus, ปกติ
                        boxShadow: state.isFocused ? '0 0 0 1px #6366f1' : 'none', // ใส่เงาตอน focus
                        '&:hover': {
                          borderColor: errors.province ? '#ef4444' : '#9ca3af',
                        },
                      }),
                      // แก้ปัญหา dropdown โดนบัง
                      menu: (baseStyles) => ({
                        ...baseStyles,
                        zIndex: 20, 
                      }),
                    }}
                  />

                  {errors.province && (
                    <p className="mt-1 text-xs text-red-500">
                      {errors.province}
                    </p>
                  )}
                </div>

                {/* อำเภอ */}
                <div>
                  <label className="block text-sm mb-1">
                    อำเภอ <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    name="district"
                    value={shipping.district}
                    onChange={handleChange}
                    className={`w-full border rounded px-3 py-2 ${
                      errors.district ? "border-red-500" : "border-gray-300"
                    }`}
                  />
                  {errors.district && (
                    <p className="mt-1 text-xs text-red-500">
                      {errors.district}
                    </p>
                  )}
                </div>

                {/* ตำบล */}
                <div>
                  <label className="block text-sm mb-1">
                    ตำบล <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    name="subDistrict"
                    value={shipping.subDistrict}
                    onChange={handleChange}
                    className={`w-full border rounded px-3 py-2 ${
                      errors.subDistrict
                        ? "border-red-500"
                        : "border-gray-300"
                    }`}
                  />
                  {errors.subDistrict && (
                    <p className="mt-1 text-xs text-red-500">
                      {errors.subDistrict}
                    </p>
                  )}
                </div>

                {/* รหัสไปรษณีย์ */}
                <div>
                  <label className="block text-sm mb-1">
                    รหัสไปรษณีย์ <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    name="zipcode"
                    value={shipping.zipcode}
                    onChange={handleChange}
                    className={`w-full border rounded px-3 py-2 ${
                      errors.zipcode ? "border-red-500" : "border-gray-300"
                    }`}
                  />
                  {errors.zipcode && (
                    <p className="mt-1 text-xs text-red-500">
                      {errors.zipcode}
                    </p>
                  )}
                </div>
              </div>
            </div>

            {/* วิธีชำระเงิน */}
            <section className="bg-white rounded-lg shadow p-6">
              <h2 className="text-xl font-semibold mb-4">
                วิธีการชำระเงิน
              </h2>

              <div className="space-y-4">
                {/* บัตร */}
                <label className="flex items-start gap-3 cursor-pointer">
                  <input
                    type="radio"
                    name="paymentMethod"
                    value="card"
                    checked={paymentMethod === "card"}
                    onChange={(e) => {
                      setPaymentMethod(e.target.value);
                      setCardError("");
                    }}
                    className="mt-1"
                    disabled={isProcessing}
                  />
                  <div>
                    <div className="font-medium">
                      ชำระผ่านบัตรเครดิต / เดบิต
                    </div>
                    <div className="text-sm text-gray-500">
                      Visa (ขึ้นต้น 4, 16 หลัก), MasterCard (ขึ้นต้น 5,
                      10 หลัก)
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
                        value={cardNumber}
                        onChange={handleCardNumberChange}
                        onBlur={validateCardNumber}
                        onFocus={handleCardFocus}
                        className={`w-full border rounded-md px-3 py-2 focus:outline-none focus:ring-2 ${
                          cardError
                            ? "border-red-500 focus:ring-red-400"
                            : "focus:ring-green-500"
                        }`}
                        placeholder="4xxx xxxx xxxx xxxx หรือ 5xxx xxxxx x"
                        disabled={isProcessing}
                      />
                      {cardError && (
                        <p className="text-xs text-red-500 mt-1">
                          {cardError}
                        </p>
                      )}
                    </div>

                    <div>
                      <label className="block text-sm text-gray-700 mb-1">
                        วันหมดอายุ
                      </label>
                      <input
                        type="text"
                        className="w-full border rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-green-500"
                        placeholder="MM/YY"
                        disabled={isProcessing}
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
                        disabled={isProcessing}
                      />
                    </div>
                  </div>
                )}

                {/* โอนธนาคาร */}
                <label className="flex items-start gap-3 cursor-pointer">
                  <input
                    type="radio"
                    name="paymentMethod"
                    value="bank"
                    checked={paymentMethod === "bank"}
                    onChange={(e) => {
                      setPaymentMethod(e.target.value);
                      setCardError("");
                    }}
                    className="mt-1"
                    disabled={isProcessing}
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
              </div>
            </section>
          </div>

          {/* ขวา: สรุปออเดอร์ */}
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

            {/* เตือนถ้ายังไม่เลือกวิธีชำระเงิน */}
            {triedSubmit && !paymentMethod && (
              <div className="mt-2 text-left text-sm text-red-500">
                กรุณาเลือกวิธีการชำระเงิน
              </div>
            )}

            {/* สถานะกำลังประมวลผล แบบ Loading UI */}
            {isProcessing && (
              <div className="mt-4 mx-auto max-w-xs rounded-md border border-blue-200 bg-blue-50 px-4 py-3 text-center text-sm text-blue-800">
                <div className="flex items-center justify-center gap-2">
                  <svg
                    className="h-4 w-4 animate-spin text-blue-500"
                    xmlns="http://www.w3.org/2000/svg"
                    fill="none"
                    viewBox="0 0 24 24"
                  >
                    <circle
                      className="opacity-25"
                      cx="12"
                      cy="12"
                      r="10"
                      stroke="currentColor"
                      strokeWidth="4"
                    ></circle>
                    <path
                      className="opacity-75"
                      fill="currentColor"
                      d="M4 12a8 8 0 018-8v4l3.5-3.5L12 1v4a7 7 0 00-7 7h-1z"
                    ></path>
                  </svg>
                  <span>กำลังตรวจสอบการชำระเงิน โปรดรอสักครู่...</span>
                </div>
              </div>
            )}

            <button
              type="submit"
              className={`w-full mt-4 text-white py-2 rounded ${
                triedSubmit && !paymentMethod
                  ? "bg-green-300 cursor-not-allowed"
                  : "bg-green-600 hover:bg-green-700"
              } ${isProcessing ? "opacity-70 cursor-wait" : ""}`}
              disabled={(triedSubmit && !paymentMethod) || isProcessing}
            >
              {isProcessing ? "กำลังดำเนินการ..." : "ยืนยันการสั่งซื้อ"}
            </button>
          </div>
        </div>
      </form>
    </div>
  );
};

export default Paymentpage;