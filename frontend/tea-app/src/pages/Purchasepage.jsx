import React, { useState, useEffect } from 'react';
import { SearchIcon } from '@heroicons/react/outline';
import api from '../api/api';

import PurchaseTabs from '../components/Purchasetab';
import OrderCard from '../components/OrderCard';

const Purchasepage = () => {
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

      const storedUser = JSON.parse(localStorage.getItem('user'));
      const userId = storedUser?.id;

      if (!userId) {
         setLoading(false);
         return;
      }

      const response = await api.get('/orders', {
        params: {
          user_id: userId
        }
      });

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
      case "ที่ต้องได้รับ":
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

  // 2. ปรับปรุง Logic การกรองข้อมูล (Filter)
  const filteredOrders = orders.filter((order) => {
    // กรองชั้นที่ 1: ตรวจสอบสถานะตาม Tab
    const matchesTab = checkStatus(order.status, activeTab);

    // กรองชั้นที่ 2: ตรวจสอบคำค้นหา (ถ้ามี)
    const term = searchTerm.toLowerCase().trim();
    const matchesSearch = term === "" || (
      // ค้นหาจาก Order ID
      order.id.toString().includes(term) ||
      // หรือ ค้นหาจากชื่อสินค้า (Product Name) ใน items
      (order.items && order.items.some(item => 
        item.product_name && item.product_name.toLowerCase().includes(term)
      ))
    );

    // ต้องผ่านเงื่อนไขทั้งคู่
    return matchesTab && matchesSearch;
  });

  return (
    <div className="font-sans w-full">

      {/* ส่วน Tabs เมนู */}
      <PurchaseTabs activeTab={activeTab} onTabChange={setActiveTab} />

      {/* ส่วนช่องค้นหา */}
      <div className="bg-gray-100 p-2 rounded-xl mb-4 flex items-center border border-gray-200 focus-within:ring-1 focus-within:ring-viridian-500 focus-within:border-viridian-500 transition-all">
        <SearchIcon className="h-5 w-5 text-gray-500 ml-2" />
        <input
          type="text"
          placeholder="คุณสามารถค้นหาโดยใช้ หมายเลขคำสั่งซื้อ หรือชื่อสินค้า"
          className="w-full bg-transparent p-2 text-sm outline-none text-gray-700 placeholder-gray-400"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)} // 3. ผูก Input กับ State
        />
        {/* ปุ่มล้างคำค้นหา */}
        {searchTerm && (
          <button 
            onClick={() => setSearchTerm("")}
            className="text-gray-400 hover:text-gray-600 mr-2 text-sm font-medium"
          >
            ล้าง
          </button>
        )}
      </div>

      {/* ส่วนรายการออเดอร์ */}
      <div className="flex flex-col min-h-[300px]">
        {loading ? (
          <div className="flex justify-center items-center py-20">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-orange-500"></div>
          </div>
        ) : error ? (
          <div className="text-center text-red-500 py-10 bg-red-50 rounded-md border border-red-100">
            {error}
          </div>
        ) : filteredOrders.length > 0 ? (
          filteredOrders.map((order) => (
            <OrderCard key={order.id} order={order} />
          ))
        ) : (
          <div className="flex flex-col items-center justify-center py-20 bg-white shadow-lg rounded-xl border border-gray-100">
            <div className="bg-gray-100 p-4 rounded-full mb-4">
              <SearchIcon className="h-10 w-10 text-gray-300" />
            </div>
            <p className="text-gray-500 text-lg">
              {searchTerm ? `ไม่พบรายการที่ค้นหา "${searchTerm}"` : "ไม่มีคำสั่งซื้อในสถานะนี้"}
            </p>
          </div>
        )}
      </div>

    </div>
  );
};

export default Purchasepage;