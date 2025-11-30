import React from 'react';
import { 
  TruckIcon, 
  ClipboardListIcon 
} from '@heroicons/react/outline';

const AdminOrderCard = ({ order, onUpdateStatus }) => {

  const { items } = order;
  const API_BASE_URL = "http://localhost:3001"; 

  const getStatusText = (status) => {
    switch (status) {
      case 'paid': 
      case 'processing': 
        return 'ที่ต้องจัดส่ง';
      case 'shipped': return 'จัดส่งแล้ว';
      case 'completed': return 'สำเร็จแล้ว';
      case 'cancelled': return 'ยกเลิก';
      case 'refunded': return 'คืนเงิน/คืนสินค้า';
      default: return status;
    }
  };

  // จัดรูปแบบวันที่
  const formatDate = (dateString) => {
    if (!dateString) return "";
    const date = new Date(dateString);
    return date.toLocaleDateString('th-TH', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  return (
    <div className="bg-white shadow-sm rounded-sm mb-4 border border-gray-100 overflow-hidden">
      {/* --- Header: เลขคำสั่งซื้อ & สถานะ --- */}
      <div className="flex justify-between items-center bg-gray-50/80 px-6 py-3 border-b border-gray-100">
        
        {/* เลขคำสั่งซื้อ */}
        <div className="flex items-center gap-2 text-gray-700 font-medium">
          <ClipboardListIcon className="h-5 w-5 text-gray-500" />
          <span>คำสั่งซื้อ #{order.id.toString().padStart(6, '0')}</span> 
        </div>

        {/* สถานะสินค้า */}
        <div className="flex items-center gap-2 text-sm">
          <div className="flex items-center text-teal-600 gap-1">
            <TruckIcon className="h-4 w-4" />
            
            {/* ✅ แก้ไขตรงนี้: ลบ truncate, max-w ออก และเพิ่ม select-all เพื่อให้ copy ง่าย */}
            <span className="font-medium select-all whitespace-nowrap">
              {order.tracking_number ? `Tracking: ${order.tracking_number}` : getStatusText(order.status)}
            </span>

          </div>
          <span className={`border-l pl-2 ml-2 border-gray-300 uppercase font-bold 
            ${order.status === 'cancelled' ? 'text-red-500' : 'text-viridian-500'}`}>
            {getStatusText(order.status)}
          </span>
        </div>
      </div>

      {/* --- Body: รายการสินค้า --- */}
      <div className="p-6 pt-4">
        {items && items.length > 0 ? (
          items.map((item, index) => (
            <div key={item.id || index} className="flex gap-4 mb-4 items-start border-b border-dashed border-gray-100 last:border-0 pb-4 last:pb-0">
              <img
                src={item.image_url 
                  ? (item.image_url.startsWith('http') ? item.image_url : `${API_BASE_URL}/${item.image_url}`)
                  : "https://placehold.co/100x100?text=No+Image"
                } 
                alt={item.product_name}
                className="w-20 h-20 object-cover border border-gray-200 rounded-md bg-gray-50"
                onError={(e) => {e.target.src = "https://placehold.co/100x100?text=Error"}} 
              />
              
              <div className="flex-1 min-w-0">
                <h3 className="text-sm font-medium text-gray-800 line-clamp-2 leading-relaxed">
                  {item.product_name}
                </h3>
                {item.weight && (
                   <p className="text-gray-500 text-xs mt-1 bg-gray-100 inline-block px-2 py-0.5 rounded-sm">
                     น้ำหนัก: {item.weight}g
                   </p>
                )}
                <div className="flex justify-between mt-1">
                  <p className="text-gray-500 text-xs">x{item.quantity}</p>
                </div>
              </div>

              <div className="text-right flex flex-col">
                <span className="text-viridian-500 font-medium text-base">
                  ฿{Number(item.price_per_unit).toLocaleString()}
                </span>
              </div>
            </div>
          ))
        ) : (
          <p className="text-gray-400 text-center py-4">ไม่พบรายการสินค้า</p>
        )}
      </div>

      {/* --- Footer: ยอดรวม & ปุ่ม Action ของ Admin --- */}
      <div className="bg-gray-50 px-6 py-4 border-t border-gray-100">
        
        <div className="flex justify-end items-center mb-4">
          <span className="text-gray-700 text-sm mr-2">ยอดคำสั่งซื้อทั้งหมด:</span>
          <span className="text-2xl font-bold text-viridian-500">
            ฿{Number(order.total_amount).toLocaleString()}
          </span>
        </div>

        <div className="flex flex-col sm:flex-row justify-between items-end sm:items-center gap-4">
          <div className="text-xs text-gray-500 hidden sm:block">
            <p>วันที่สั่งซื้อ: <span className="font-medium text-gray-700">{formatDate(order.created_at)}</span></p>
          </div>
          
          <div className="flex gap-2 w-full sm:w-auto">
             
             {/* ปุ่ม Action สำหรับ Admin */}
             {(order.status === 'paid' || order.status === 'processing') && (
                <button 
                  onClick={() => onUpdateStatus && onUpdateStatus(order.id, 'shipped')}
                  className="w-full sm:w-auto px-6 py-2 bg-viridian-500 text-white text-sm rounded hover:bg-viridian-600 transition shadow-sm font-medium"
                >
                  จัดส่งสินค้าแล้ว
                </button>
             )}

          </div>
        </div>
      </div>
    </div>
  );
};

export default AdminOrderCard;