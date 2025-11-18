import React from "react";
import { useLocation } from "react-router-dom";

const Paymentpage = () => {
  const location = useLocation();
  const selectedItems = location.state?.selectedItems || [];

  // กัน error
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

  const calculateTotal = () => {
    return selectedItems.reduce((sum, item) => {
      const qty = item.qty || 1;
      return sum + item.price * qty;
    }, 0);
  };

  return (
    <div className="container mx-auto px-4 py-8">
      <h1 className="text-4xl font-semibold mb-6">หน้าชำระเงิน</h1>

      <div className="space-y-6">
        {selectedItems.map((item) => (
          <div key={item.id} className="flex items-center gap-6">
            <img
              src={item.coverImage || item.image}
              alt={item.title}
              className="w-20 h-20 object-cover rounded"
            />
            <div className="flex-1">
              <div className="font-medium">{item.title}</div>
              <div className="text-gray-600">จำนวน: {item.qty}</div>
            </div>
            <div className="text-green-700 font-semibold text-lg">
              ฿{(item.price * item.qty).toLocaleString()}
            </div>
          </div>
        ))}

        <hr />

        <div className="text-right text-xl font-semibold">
          ราคารวม: ฿{calculateTotal().toLocaleString()}
        </div>
      </div>
    </div>
  );
};

export default Paymentpage;
