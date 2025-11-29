import React from 'react';
import { StarIcon } from '@heroicons/react/outline';
import { StarIcon as StarSolidIcon } from '@heroicons/react/solid';
import { Link } from 'react-router-dom';
import { XIcon } from '@heroicons/react/outline';

const ProductCardAdmin = ({ product, onDeleted }) => {
  if (!product) return null;

  const handleDelete = async () => {
    if (!window.confirm("คุณแน่ใจหรือว่าต้องการลบสินค้านี้?")) return;

    try {
      const res = await fetch(`/api/v1/products/${product.id}`, {
        method: "DELETE",
        headers: {
          "Content-Type": "application/json",
        },
      });
      if (!res.ok) throw new Error("เกิดข้อผิดพลาดในการลบสินค้า");

      alert("ลบสินค้าสำเร็จ");
      if (onDeleted) onDeleted(product.id); // แจ้ง parent component ให้ลบออกจาก state
    } catch (err) {
      alert(err.message);
    }
  };

  return (
    <div className="bg-white rounded-xl shadow-card overflow-hidden group
      hover:shadow-card-lg transition-all duration-300 transform hover:-translate-y-1
      h-full flex flex-col relative">

      {/* Product Cover */}
      <div className="relative w-full aspect-[4/5] bg-gray-50 overflow-hidden">
        <img
          src={product.coverImage || '/placeholder.png'}
          alt={product.title || 'No title'}
          className="w-full h-full object-cover transition-transform duration-300 group-hover:scale-105"
        />

        {/* New Badge */}
        {product.isNew && (
          <span className="absolute top-2 left-2 bg-gradient-to-r from-green-500 to-viridian-700
            text-white px-2 py-0.5 rounded-full text-xs font-semibold shadow-md">
            ใหม่
          </span>
        )}

        {/* Delete Button */}
        <button
          onClick={handleDelete}
          className="absolute top-1 right-1 bg-red-600 hover:bg-red-700 text-white p-1 rounded-full shadow-lg
            transition-colors duration-200 flex items-center justify-center"
          title="ลบสินค้า"
        >
          <XIcon className="h-5 w-5" />
        </button>
      </div>

      {/* Product Details */}
      <div className="p-4 flex flex-col flex-1 gap-2">
        {/* Category */}
        <p className="text-xs md:text-sm text-viridian-600 font-semibold uppercase tracking-wider">
          {product.category || 'ไม่ระบุหมวดหมู่'}
        </p>

        {/* Title */}
        <h3 className="text-sm md:text-base font-bold text-gray-900 line-clamp-1
          group-hover:text-viridian-600 transition-colors">
          {product.title || 'ไม่มีชื่อสินค้า'}
        </h3>

        {/* Rating */}
        <div className="flex items-center gap-1 text-yellow-400 text-xs md:text-sm">
          {[...Array(5)].map((_, i) =>
            i < Math.floor(product.rating || 0) ? (
              <StarSolidIcon key={i} className="h-4 w-4" />
            ) : (
              <StarIcon key={i} className="h-4 w-4" />
            )
          )}
          <span className="text-gray-600 ml-1 text-[0.65rem] md:text-sm">
            ({product.reviews || 0} รีวิว)
          </span>
        </div>

        <div className="flex-1"></div>

        {/* Price & Edit Button */}
        <div className="flex items-center justify-between gap-2 mt-2">
          {/* Price */}
          <div className="flex flex-col">
            {product.originalPrice && product.originalPrice !== product.price && (
              <span className="text-xs md:text-sm text-gray-400 line-through">
                ฿{product.originalPrice}
              </span>
            )}
            <span className="text-lg md:text-xl font-bold text-black">
              ฿{product.price || 0}
            </span>
          </div>

          {/* Edit Button */}
          <Link
            to={`/admin/update-products/${product.id}`}
            className="inline-flex items-center justify-center px-4 py-2
              bg-gradient-to-r from-green-500 to-viridian-700
              text-white font-semibold text-sm md:text-sm
              rounded-lg shadow-md
              hover:scale-105 hover:shadow-xl active:scale-100
              transition-transform duration-200 ease-in-out"
          >
            แก้ไข
          </Link>
        </div>
      </div>
    </div>
  );
};

export default ProductCardAdmin;
