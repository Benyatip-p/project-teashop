import React, { useEffect, useState } from 'react';
import { createPortal } from 'react-dom';
import { useShop } from '../context/ShopContext';

const sizeOptions = [
  { size: '20g', stock: 12 },
  { size: '50g', stock: 8 },
  { size: '100g', stock: 3 },
];

const AddToCartModal = ({ open, onClose, product }) => {
  const { addToCart } = useShop();
  const [quantity, setQuantity] = useState(1);
  const [selectedSize, setSelectedSize] = useState(sizeOptions[sizeOptions.length - 1].size);

  useEffect(() => {
    if (open) {
      setQuantity(1);
      setSelectedSize(sizeOptions[sizeOptions.length - 1].size);
    }
  }, [open]);

  if (!open || typeof document === 'undefined') return null;

  const decreaseQty = () => {
    setQuantity((q) => (q > 1 ? q - 1 : 1));
  };

  const increaseQty = () => {
    setQuantity((q) => q + 1);
  };

  const handleConfirm = () => {
    addToCart({ ...product, selectedSize }, quantity);
    onClose();
  };

  const selectedSizeData = sizeOptions.find((s) => s.size === selectedSize);

  return createPortal(
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/40 px-4">
      <div className="w-full max-w-4xl overflow-hidden rounded-3xl bg-white shadow-2xl">
        <div className="flex flex-col gap-6 p-6 md:flex-row md:items-start">
          <div className="w-full md:w-1/3">
            <img
              src={product.coverImage}
              alt={product.title}
              className="h-full max-h-80 w-full rounded-2xl object-cover"
            />
          </div>

          <div className="flex-1">
            <p className="text-xs font-medium uppercase tracking-wide text-emerald-900">
              เพิ่มลงตะกร้า
            </p>
            <h3 className="mt-1 line-clamp-2 text-xl font-semibold text-gray-900">
              {product.title}
            </h3>
            <p className="mt-2 text-base text-gray-800">฿{product.price}</p>

            <div className="mt-4">
              <span className="text-sm text-gray-700">เลือกขนาด:</span>
              <div className="mt-2 flex flex-wrap gap-2">
                {sizeOptions.map((item) => (
                  <button
                    key={item.size}
                    type="button"
                    onClick={() => setSelectedSize(item.size)}
                    className={`rounded-full border px-3 py-1 text-sm transition ${
                      selectedSize === item.size
                        ? 'border-[#0b2f27] bg-[#0b2f27] text-white'
                        : 'border-gray-300 bg-white text-gray-700 hover:bg-gray-50'
                    }`}
                  >
                    {item.size}
                  </button>
                ))}
              </div>
            </div>

            <div className="mt-6 flex items-center gap-4">
              <span className="text-sm text-gray-700">จำนวน</span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={decreaseQty}
                  className="flex h-9 w-9 items-center justify-center rounded-lg border border-gray-300 text-lg font-semibold text-gray-700 hover:bg-gray-100"
                >
                  −
                </button>
                <span className="w-10 text-center text-sm font-semibold">{quantity}</span>
                <button
                  type="button"
                  onClick={increaseQty}
                  className="flex h-9 w-9 items-center justify-center rounded-lg border border-gray-300 text-lg font-semibold text-gray-700 hover:bg-gray-100"
                >
                  +
                </button>
              </div>

              {selectedSizeData && (
                <span className="text-xs text-gray-500">
                  มีสินค้าทั้งหมด {selectedSizeData.stock} ชิ้น
                </span>
              )}
            </div>
          </div>
        </div>

        <div className="flex flex-col gap-3 border-t border-gray-100 px-6 py-4 md:flex-row md:items-center md:justify-between">
          <button
            type="button"
            onClick={onClose}
            className="w-full rounded-lg bg-gray-100 px-4 py-2 text-sm font-semibold text-gray-700 hover:bg-gray-200 md:w-auto"
          >
            เลือกสินค้าต่อ
          </button>
          <button
            type="button"
            onClick={handleConfirm}
            className="w-full rounded-lg bg-[#0b2f27] px-6 py-2 text-sm font-semibold text-white hover:bg-[#08231d] md:w-auto"
          >
            เพิ่มลงตะกร้า
          </button>
        </div>
      </div>
    </div>,
    document.body
  );
};

export default AddToCartModal;
