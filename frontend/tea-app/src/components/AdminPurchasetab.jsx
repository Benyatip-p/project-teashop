import React from 'react';
import { Link } from "react-router-dom";

const AdminPurchasetab = ({ activeTab, onTabChange }) => {
  const tabs = [
    "All",
    "ที่ต้องจัดส่ง",
    "จัดส่งแล้ว",
    "สำเร็จแล้ว",
    "ยกเลิก",
    "คืนเงิน/คืนสินค้า"
  ];

  return (
    <div>
      <div className="mb-4">
        <Link
          to="/admin/dashboard"
          className="inline-flex items-center gap-2 rounded-full border bg-white px-4 py-2 text-sm shadow-sm hover:bg-slate-50 text-gray-700 transition-all"
        >
          <span>←</span> กลับไปหน้าแดชบอร์ด
        </Link>
      </div>
      <div className="bg-white sticky top-0 z-10 shadow-sm mb-4">
        <div className="flex overflow-x-auto no-scrollbar">
          {tabs.map((tab) => (
            <button
              key={tab}
              onClick={() => onTabChange(tab)}
              className={`flex-shrink-0 whitespace-nowrap py-3 px-6 text-sm font-medium text-center transition-colors border-b-2 ${
                activeTab === tab
                  ? "border-viridian-500 text-viridian-500"
                  : "border-transparent text-gray-600 hover:text-viridian-500"
              }`}
            >
              {tab}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
};

export default AdminPurchasetab;