import React from "react";
import StatCard from "./StatCard";
import ProductCard from "./AdminProductCard";
import { PlusIcon } from "@heroicons/react/outline";
import { useNavigate } from "react-router-dom";

const DashboardContent = ({ stats, products }) => {
  const navigate = useNavigate();

  return (
    <main className="p-6">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        {stats.map((s, i) => <StatCard key={i} {...s} />)}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-white rounded-xl shadow-sm border p-6">
            <h3 className="font-semibold text-lg">สรุปยอดขายประจำเดือน</h3>
            <div className="mt-4 h-56 rounded-md bg-gray-50 border-dashed border-2 border-gray-200 flex items-center justify-center text-gray-400">
              (แทรก Chart library)
            </div>
          </div>

          <div className="bg-white rounded-xl shadow-sm border p-6">
            <div className="flex items-center justify-between">
              <h3 className="font-semibold text-lg">กิจกรรมล่าสุด</h3>
              <button className="text-sm text-green-600">ดูทั้งหมด</button>
            </div>

            <ul className="mt-4 space-y-3">
              <li className="flex items-start space-x-3">
                <div className="h-9 w-9 rounded-full bg-green-100 flex items-center justify-center text-green-600">A</div>
                <div>
                  <p className="text-sm font-medium">สั่งซื้อใหม่: #10234</p>
                  <p className="text-xs text-gray-500">2 ชั่วโมงที่แล้ว</p>
                </div>
              </li>
              <li className="flex items-start space-x-3">
                <div className="h-9 w-9 rounded-full bg-indigo-100 flex items-center justify-center text-indigo-600">P</div>
                <div>
                  <p className="text-sm font-medium">สินค้าเพิ่มสต็อก: มัทฉะแฟรป</p>
                  <p className="text-xs text-gray-500">เมื่อวานนี้</p>
                </div>
              </li>
            </ul>
          </div>
        </div>

        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <h3 className="font-semibold text-lg">สินค้าขายดี</h3>
            <button onClick={() => navigate('/store-manager/add-Tea')} className="px-3 py-2 rounded-md bg-green-600 text-white text-sm flex items-center space-x-2">
              <PlusIcon className="h-4 w-4" />
              <span>เพิ่มสินค้า</span>
            </button>
          </div>

          <div className="grid grid-cols-1 gap-4">
            {products.map((p, i) => <ProductCard key={i} {...p} />)}
          </div>
        </div>
      </div>
    </main>
  );
};

export default DashboardContent;
