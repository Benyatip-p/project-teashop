import React from 'react';

const PurchaseTabs = ({ activeTab, onTabChange }) => {
  const tabs = [
    "All",
    "ที่ต้องจัดส่ง",
    "ที่ต้องได้รับ",
    "สำเร็จแล้ว",
    "ยกเลิก",
    "คืนเงิน/คืนสินค้า"
  ];

  return (
    <div className="bg-white sticky top-0 z-10 shadow-sm mb-4">
      <div className="flex overflow-x-auto no-scrollbar border-b border-gray-200">
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
  );
};

export default PurchaseTabs;