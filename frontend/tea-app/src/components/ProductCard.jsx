import React from 'react';
import { HeartIcon, ShoppingCartIcon, StarIcon } from '@heroicons/react/outline';
import { HeartIcon as HeartSolidIcon, StarIcon as StarSolidIcon } from '@heroicons/react/solid';
import { Link, useNavigate } from 'react-router-dom'; 
import { useShop } from '../context/ShopContext';

const ProductCard = ({ product }) => {
  const {
    toggleFavorite,
    addToCart,
    isFavorite,
    isInCart,
  } = useShop();

  const navigate = useNavigate(); 

  const favorite = isFavorite(product.id);
  const inCart = isInCart(product.id);

  const handleAddToCart = (e) => {
    e.preventDefault();   
    e.stopPropagation();
    addToCart(product);
  };

  const handleToggleFavorite = (e) => {
    e.preventDefault();
    e.stopPropagation();
    toggleFavorite(product);
  };

  const handleBottomButtonClick = (e) => {
    e.preventDefault();
    e.stopPropagation();

    if (inCart) {
      navigate('/cart');
    } else {
      addToCart(product);
    }
  };

  return (
    <Link
      to={`/products/${product.id}`}
      state={{ from: 'list' }}
      className="block"
    >
      <div className="bg-white rounded-xl shadow-lg overflow-hidden group 
        hover:shadow-2xl transition-all duration-300 transform hover:-translate-y-1">
        
        {/* Product Cover */}
        <div className="relative h-80 bg-gradient-to-br from-gray-100 to-gray-200">
          <img 
            src={product.coverImage} 
            alt={product.title}
            className="w-full h-full object-cover"
          />
          
          {/* Badges */}
          {product.isNew && (
            <span className="absolute top-3 left-3 bg-green-500 text-white px-3 py-1 
              rounded-full text-xs font-semibold">
              ใหม่
            </span>
          )}
          {product.discount && (
            <span className="absolute top-3 right-3 bg-red-500 text-white px-3 py-1 
              rounded-full text-xs font-semibold">
              -{product.discount}%
            </span>
          )}
          
          {/* Quick Actions - Show on Hover */}
          <div className="absolute inset-0 bg-black bg-opacity-0 group-hover:bg-opacity-40 
            transition-all duration-300 flex items-center justify-center">
            <div className="opacity-0 group-hover:opacity-100 transition-opacity duration-300 
              flex gap-3">
              <button 
                onClick={handleToggleFavorite}
                className="p-3 bg-white rounded-full hover:bg-red-50 transition-colors"
              >
                {favorite ? (
                  <HeartSolidIcon className="h-6 w-6 text-red-500" />
                ) : (
                  <HeartIcon className="h-6 w-6 text-gray-700" />
                )}
              </button>
              <button 
                onClick={handleAddToCart}
                className={`p-3 rounded-full transition-colors
                  ${inCart
                    ? 'bg-green-500 hover:bg-green-600'
                    : 'bg-white hover:bg-green-50'
                  }`}
              >
                <ShoppingCartIcon
                  className={`h-6 w-6 ${
                    inCart ? 'text-white' : 'text-gray-700'
                  }`}
                />
              </button>
            </div>
          </div>
        </div>
        
        {/* Product Details */}
        <div className="p-5">
          <p className="text-xs text-viridian-600 font-semibold uppercase tracking-wider mb-2">
            {product.category}
          </p>
          
          <h3 className="text-lg font-bold text-gray-900 mb-1 line-clamp-1 
            group-hover:text-viridian-600 transition-colors">
            {product.title}
          </h3>
          
          {/* Rating */}
          <div className="flex items-center mb-3">
            <div className="flex text-yellow-400">
              {[...Array(5)].map((_, i) => (
                i < Math.floor(product.rating || 0) ? (
                  <StarSolidIcon key={i} className="h-4 w-4" />
                ) : (
                  <StarIcon key={i} className="h-4 w-4" />
                )
              ))}
            </div>
            <span className="text-sm text-gray-600 ml-2">
              ({product.reviews || 0} รีวิว)
            </span>
          </div>
          
          {/* Price */}
          <div className="flex items-center justify-between">
            <div>
              {product.originalPrice && product.originalPrice !== product.price && (
                <span className="text-sm text-gray-400 line-through mr-2">
                  ฿{product.originalPrice}
                </span>
              )}
              <span className="text-2xl font-bold text-black">
                ฿{product.price}
              </span>
            </div>
            
            <button 
              onClick={handleBottomButtonClick}
              className="px-4 py-2 rounded-lg font-semibold transition-all duration-200 
                bg-green-700 text-white hover:bg-green-900"
            >
              {inCart ? 'ในตะกร้า' : 'เพิ่มลงตะกร้า'}
            </button>
          </div>
        </div>
      </div>
    </Link>
  );
};

export default ProductCard;