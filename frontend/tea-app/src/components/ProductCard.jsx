import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { HeartIcon, ShoppingCartIcon, StarIcon } from '@heroicons/react/outline';
import {
  HeartIcon as HeartSolidIcon,
  StarIcon as StarSolidIcon,
} from '@heroicons/react/solid';
import { useShop } from '../context/ShopContext';
import AddToCartModal from './AddToCartModal';

const ProductCard = ({ product }) => {
  const { toggleFavorite, addToCart, isFavorite, isInCart } = useShop();
  const [openAddModal, setOpenAddModal] = useState(false);

  const favorite = isFavorite(product.id);
  const inCart = isInCart(product.id);

  const handleQuickAddToCart = (e) => {
    e.preventDefault();
    e.stopPropagation();
    addToCart(product, 1);
  };

  const handleToggleFavorite = (e) => {
    e.preventDefault();
    e.stopPropagation();
    toggleFavorite(product);
  };

  const handleOpenModal = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setOpenAddModal(true);
  };

  const handleCloseModal = () => {
    setOpenAddModal(false);
  };

  return (
    <>
      <div className="group overflow-hidden rounded-xl bg-white shadow-lg transition-all duration-300 hover:-translate-y-1 hover:shadow-2xl">
        <Link to={`/products/${product.id}`} className="block">
          <div className="relative h-80 bg-gray-100">
            <img
              src={product.coverImage}
              alt={product.title}
              className="h-full w-full object-cover"
            />

            {product.isNew && (
              <span className="absolute left-3 top-3 rounded-full bg-green-600 px-3 py-1 text-xs font-semibold text-white">
                ใหม่
              </span>
            )}

            {product.discount && (
              <span className="absolute right-3 top-3 rounded-full bg-red-500 px-3 py-1 text-xs font-semibold text-white">
                -{product.discount}%
              </span>
            )}

            <div className="absolute inset-0 flex items-center justify-center bg-black/0 transition-all duration-300 group-hover:bg-black/30">
              <div className="flex gap-3 opacity-0 transition-opacity duration-300 group-hover:opacity-100">
                <button
                  onClick={handleToggleFavorite}
                  className="rounded-full bg-white p-3 transition-colors hover:bg-green-50"
                >
                  {favorite ? (
                    <HeartSolidIcon className="h-6 w-6 text-red-500" />
                  ) : (
                    <HeartIcon className="h-6 w-6 text-gray-700" />
                  )}
                </button>

                <button
                  onClick={handleQuickAddToCart}
                  className={`rounded-full p-3 transition-colors ${
                    inCart ? 'bg-green-900 hover:bg-green-800' : 'bg-white hover:bg-green-50'
                  }`}
                >
                  <ShoppingCartIcon
                    className={`h-6 w-6 ${inCart ? 'text-white' : 'text-gray-700'}`}
                  />
                </button>
              </div>
            </div>
          </div>

          <div className="p-5">
            <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-green-900">
              {product.category}
            </p>

            <h3 className="mb-1 line-clamp-1 text-lg font-bold text-gray-900 transition-colors group-hover:text-green-900">
              {product.title}
            </h3>

            <div className="mb-3 flex items-center">
              <div className="flex text-yellow-400">
                {Array.from({ length: 5 }).map((_, i) =>
                  i < Math.floor(product.rating || 0) ? (
                    <StarSolidIcon key={i} className="h-4 w-4" />
                  ) : (
                    <StarIcon key={i} className="h-4 w-4" />
                  )
                )}
              </div>
              <span className="ml-2 text-sm text-gray-600">
                ({product.reviews || 0} รีวิว)
              </span>
            </div>

            <div className="flex items-center justify-between">
              <div>
                {product.originalPrice && product.originalPrice !== product.price && (
                  <span className="mr-2 text-sm text-gray-400 line-through">
                    ฿{product.originalPrice}
                  </span>
                )}
                <span className="text-2xl font-bold text-black">฿{product.price}</span>
              </div>

              <button
                onClick={handleOpenModal}
                className="rounded-lg bg-[#0b2f27] px-4 py-2 text-sm font-semibold text-white transition-all duration-200 hover:bg-[#13493d]"
              >
                เพิ่มลงตะกร้า
              </button>
            </div>
          </div>
        </Link>
      </div>

      <AddToCartModal open={openAddModal} onClose={handleCloseModal} product={product} />
    </>
  );
};

export default ProductCard;
