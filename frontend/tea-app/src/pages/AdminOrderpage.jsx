import React, { useState, useEffect } from 'react';
import { SearchIcon } from '@heroicons/react/outline';
import api from '../api/api';

import PurchaseTabs from '../components/AdminPurchasetab';
import AdminOrderCard from '../components/AdminOrderCard';
import AdminLayout from '../components/AdminLayout';

const AdminOrderpage = () => {
  const [activeTab, setActiveTab] = useState("All");
  const [orders, setOrders] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchTerm, setSearchTerm] = useState("");

     // ฟังก์ชันดึงข้อมูลจาก API
  const fetchOrders = async () => {
    try {
      setLoading(true);
      setError(null);

      
      const response = await api.get('/orders'); 

      const orderList = response.data?.orders || [];
      setOrders(orderList);
      
    } catch (err) {
      console.error("Error fetching orders:", err);
      setError("ไม่สามารถโหลดข้อมูลคำสั่งซื้อได้ กรุณาลองใหม่อีกครั้ง");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchOrders();
  }, []);

  // ฟังก์ชันตรวจสอบสถานะ
  const checkStatus = (orderStatus, tabName) => {
    switch (tabName) {
      case "All": return true;
      case "ที่ต้องจัดส่ง":
        return orderStatus === "paid" || orderStatus === "processing";
      case "จัดส่งแล้ว":
        return orderStatus === "shipped";
      case "สำเร็จแล้ว":
        return orderStatus === "completed";
      case "ยกเลิก":
        return orderStatus === "cancelled";
      case "คืนเงิน/คืนสินค้า":
        return orderStatus === "refunded";
      default: return false;
    }
  };

  // Logic การกรองข้อมูล (Filter)
  const filteredOrders = orders.filter((order) => {
    // กรองชั้นที่ 1: ตรวจสอบสถานะตาม Tab
    const matchesTab = checkStatus(order.status, activeTab);

    // กรองชั้นที่ 2: ตรวจสอบคำค้นหา
    const term = searchTerm.toLowerCase().trim();
    
    // Admin อาจต้องการค้นหาเพิ่ม เช่น ชื่อลูกค้า (customer_name) ถ้า API ส่งมาให้
    const matchesSearch = term === "" || (
      // 1. Order ID
      order.id.toString().includes(term) ||
      // 2. ชื่อสินค้า
      (order.items && order.items.some(item => 
        item.product_name && item.product_name.toLowerCase().includes(term)
      )) 
    );

    return matchesTab && matchesSearch;
  });

  return (
    <AdminLayout>
      <div className="font-sans w-full p-4"> 
        <h1 className="text-2xl font-bold mb-6 text-gray-800">จัดการคำสั่งซื้อ</h1>

        {/* ส่วน Tabs เมนู */}
        <PurchaseTabs activeTab={activeTab} onTabChange={setActiveTab} />

        {/* ส่วนช่องค้นหา */}
        <div className="bg-white p-3 rounded-xl mb-6 flex items-center border border-gray-200 shadow-sm focus-within:ring-2 focus-within:ring-viridian-500 transition-all">
          <SearchIcon className="h-5 w-5 text-gray-400 ml-2" />
          <input
            type="text"
            placeholder="ค้นหา: เลขคำสั่งซื้อ, ชื่อสินค้า"
            className="w-full bg-transparent p-2 text-sm outline-none text-gray-700 placeholder-gray-400"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
          {searchTerm && (
            <button 
              onClick={() => setSearchTerm("")}
              className="text-gray-400 hover:text-red-500 mr-2 text-sm font-medium transition-colors"
            >
              ล้าง
            </button>
          )}
        </div>

        {/* ส่วนรายการออเดอร์ */}
        <div className="flex flex-col min-h-[300px]">
          {loading ? (
            <div className="flex justify-center items-center py-20">
              <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-viridian-600"></div>
            </div>
          ) : error ? (
            <div className="text-center text-red-500 py-10 bg-red-50 rounded-lg border border-red-100">
              {error}
            </div>
          ) : filteredOrders.length > 0 ? (
            <div className="space-y-4">
              {filteredOrders.map((order) => (
                <AdminOrderCard key={order.id} order={order} isAdmin={true} />
              ))}
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-20 bg-white shadow-sm rounded-xl border border-gray-100">
              <div className="bg-gray-50 p-4 rounded-full mb-4">
                <SearchIcon className="h-10 w-10 text-gray-300" />
              </div>
              <p className="text-gray-500 text-lg">
                {searchTerm ? `ไม่พบรายการที่ค้นหา "${searchTerm}"` : "ไม่มีคำสั่งซื้อในสถานะนี้"}
              </p>
            </div>
          )}
        </div>

      </div>
    </AdminLayout>
  );
};

export default AdminOrderpage;