import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';

const FeaturedCategories = () => {
  const [categories, setCategories] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [imageErrors, setImageErrors] = useState({});

  useEffect(() => {
    const fetchCategories = async () => {
      try {
        setLoading(true);

        const response = await fetch('/api/v1/categories/featured');
        if (!response.ok) {
          throw new Error('Failed to fetch featured categories');
        }

        const data = await response.json();

        let categoriesData = [];
        if (data && data.categories && Array.isArray(data.categories)) {
          categoriesData = data.categories;
        } else {
          throw new Error('Invalid data format from API');
        }

        const formattedCategories = categoriesData.map((category) => {
          const rawImage =
            (category.image_url &&
              category.image_url.Valid &&
              category.image_url.String) ||
            category.image ||
            null;

          const image = rawImage
            ? rawImage.startsWith('http')
              ? rawImage
              : `/${rawImage}`
            : null;

          return {
            id: category.id,
            name: category.name || category.category_name,
            image,
            isActive: category.is_active !== false,
          };
        });

        const activeCategories = formattedCategories.filter(c => c.isActive);
        const selected = activeCategories.slice(0, 4);
        
        setCategories(selected);
        setError(null);
      } catch (err) {
        setError(err.message);
        console.error('Error fetching categories:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchCategories();
  }, []);

  const handleImageError = (categoryId) => {
    setImageErrors(prev => ({ ...prev, [categoryId]: true }));
  };

  if (loading) {
    return (
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[...Array(4)].map((_, index) => (
          <div key={index} className="bg-gray-200 rounded-lg overflow-hidden animate-pulse">
            <div className="aspect-square bg-gray-300"></div>
            <div className="p-4">
              <div className="h-4 bg-gray-300 rounded w-3/4 mx-auto"></div>
            </div>
          </div>
        ))}
      </div>
    );
  }

  if (error) {
    return (
      <div className="text-center py-8 text-red-600">
        <p className="text-lg font-semibold">เกิดข้อผิดพลาด</p>
        <p className="text-sm">{error}</p>
      </div>
    );
  }

  if (categories.length === 0) {
    return (
      <div className="text-center py-8 text-gray-500">
        <p>ไม่พบหมวดหมู่</p>
      </div>
    );
  }

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
      {categories.map((category) => (
        <Link
          key={category.id}
          to={`/category/${encodeURIComponent(category.name)}`}
          className="bg-gray-100 rounded-lg overflow-hidden shadow hover:shadow-lg transition-shadow"
        >
          <div className="aspect-square bg-gray-300 flex items-center justify-center overflow-hidden">
            {category.image && !imageErrors[category.id] ? (
              <img
                src={category.image}
                alt={category.name}
                className="w-full h-full object-cover hover:scale-105 transition-transform duration-300"
                onError={() => handleImageError(category.id)}
              />
            ) : (
              <span className="text-4xl">🍵</span>
            )}
          </div>
          <div className="p-4 text-center bg-white">
            <h3 className="font-semibold text-gray-900">
              {category.name}
            </h3>
          </div>
        </Link>
      ))}
    </div>
  );
};

export default FeaturedCategories;