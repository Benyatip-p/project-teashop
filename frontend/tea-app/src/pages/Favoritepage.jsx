import React from 'react';
import { Link } from 'react-router-dom';
import { useShop } from '../context/ShopContext';

const Favoritepage = () => {
  const { favorites, toggleFavorite } = useShop();

  /*if (favorites.length === 0) {
    return (
      <div className="container mx-auto px-4 py-8">
        ยังไม่มีสินค้าในรายการโปรด
      </div>
    );
  }*/

  // กลับลำดับ
  const favoritesReversed = [...favorites].reverse();
  
  return (
    <div className="container mx-auto px-4 py-8">
      <h1 className="text-4xl font-semibold mb-1">รายการโปรด</h1>

      <span className="text-sm text-gray-500">
        จำนวน {favorites.length} รายการ
      </span>

      <hr className="mb-4 mt-2" />

      <div className="space-y-4">
        {/* ใช้ favoritesReversed แทน favorites */}
        {favoritesReversed.map((item, index) => (
          <div key={item.id}>
            <div className="flex items-center gap-6 py-4">

              {/* รูปสินค้า */}
              <img
                src={item.coverImage || item.image}
                alt={item.title}
                className="w-20 h-20 object-cover rounded"
              />

              {/* ชื่อ + ราคา */}
              <Link
                to={`/products/${item.id}`}
                state={{ from: 'favorites' }}
                className="flex items-center gap-4 flex-1 group"
              >
                <div className="font-medium hover:underline">
                  {item.title}
                </div>

                {/* ราคาก่อนลด + หลังลด */}
                <div className="flex items-center gap-2 mt-1">
                  {item.originalPrice && (
                    <span className="text-gray-400 line-through text-sm">
                      ฿{item.originalPrice.toLocaleString()}
                    </span>
                  )}

                  <span className="text-green-700 font-semibold text-lg">
                    ฿{item.price?.toLocaleString()}
                  </span>
                </div>
              </Link>

              {/* ปุ่มลบ */}
              <button
                className="ml-auto text-sm text-red-500 hover:underline"
                onClick={() => toggleFavorite(item)}
              >
                ลบสินค้าออก
              </button>
            </div>

            {/* ใช้ length ของ favoritesReversed ด้วย */}
            {index !== favoritesReversed.length - 1 && <hr />}
          </div>
        ))}
      </div>
    </div>
  );
};

export default Favoritepage;