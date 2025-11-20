import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import ProductCard from '../AdminDashboard/AdminProductCard';
import LoadingSpinner from '../../components/LoadingSpinner';
import { ChevronDownIcon } from '@heroicons/react/outline';
import { Link } from 'react-router-dom';

const AdminProductpage = () => {
  const [products, setProducts] = useState([]);
  const [filteredProducts, setFilteredProducts] = useState([]);
  const [sortBy, setSortBy] = useState('newest');
  const [selectedCategory, setSelectedCategory] = useState('all');
  const [loading, setLoading] = useState(true);
  const [currentPage, setCurrentPage] = useState(1);
  const productsPerPage = 12;

  const [hoverCategory, setHoverCategory] = useState(null);
  const [openDropdown, setOpenDropdown] = useState(false);
  const [openSort, setOpenSort] = useState(false);

  const categories = {
    'TEA': ['Green Tea', 'White Tea', 'Oolong Tea', 'Black Tea', 'Red Tea', 'Flower Tea', 'Matcha'],
    'TEA Pot': ['Small Pot', 'Medium Pot', 'Large Pot'],
    'TEA Accessories': ['Spoons', 'Filters', 'Cups']
  };

  const dropdownRef = useRef(null);
  const sortRef = useRef(null);

  // ปิด dropdown เมื่อคลิกรอบนอก
  useEffect(() => {
    const handler = (e) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target)) {
        setOpenDropdown(false);
        setHoverCategory(null);
      }
      if (sortRef.current && !sortRef.current.contains(e.target)) {
        setOpenSort(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  // ดึงสินค้าจาก backend
  useEffect(() => {
    const fetchProducts = async () => {
      try {
        setLoading(true);
        const res = await axios.get('/api/v1/products', {
          headers: {
            'Authorization': 'Bearer ' + localStorage.getItem('token'),
          },
        });

        // backend ส่ง { products: [...] } → ต้องใช้ res.data.products
        const productsArray = res.data.products || [];

        // map field ให้ตรงกับ AdminProductCard
        const normalized = productsArray.map(p => ({
          ...p,
          title: p.name,
          coverImage: p.image_url || p.coverImage || 'https://shop.chaipoint.com/cdn/shop/files/TeaBagsListingImages-25.jpg?v=1694165024', // <-- default image
          category: p.category_name || 'Uncategorized',
          originalPrice: p.price,
          discount: null,
          rating: 5,
          reviews: 0,
          isNew: false,
        }));

        setProducts(normalized);
        setFilteredProducts(normalized);
      } catch (err) {
        console.error('เกิดข้อผิดพลาดในการดึงข้อมูลสินค้า:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchProducts();
  }, []);

  const handleCategoryFilter = (category) => {
    setSelectedCategory(category);
    if (category === 'all') {
      setFilteredProducts(products);
    } else if (categories[category]) {
      const subCats = categories[category].map(c => c.toLowerCase());
      setFilteredProducts(products.filter(p => subCats.includes(p.category.toLowerCase())));
    } else {
      setFilteredProducts(products.filter(p => p.category.toLowerCase() === category.toLowerCase()));
    }
    setCurrentPage(1);
  };

  const handleSort = (sortValue) => {
    setSortBy(sortValue);
    const sorted = [...filteredProducts];
    switch (sortValue) {
      case 'price-low':
        sorted.sort((a, b) => a.price - b.price);
        break;
      case 'price-high':
        sorted.sort((a, b) => b.price - a.price);
        break;
      case 'popular':
        sorted.sort((a, b) => b.reviews - a.reviews);
        break;
      case 'newest':
      default:
        sorted.sort((a, b) => b.id - a.id);
    }
    setFilteredProducts(sorted);
  };

  const indexOfLastProduct = currentPage * productsPerPage;
  const indexOfFirstProduct = indexOfLastProduct - productsPerPage;
  const currentProducts = filteredProducts.slice(indexOfFirstProduct, indexOfLastProduct);
  const totalPages = Math.ceil(filteredProducts.length / productsPerPage);
  const paginate = (pageNumber) => setCurrentPage(pageNumber);

  const handleClearFilters = () => {
    setSelectedCategory('all');
    setSortBy('newest');
    setFilteredProducts(products);
    setCurrentPage(1);
  };

  if (loading) return <LoadingSpinner />;

  return (
    <div className="min-h-screen bg-gradient-to-r from-viridian-700 to-viridian-500 py-8">
      <div className="container mx-auto px-4">
        {/* Header + Add Product + Back Button */}
        <div className="flex flex-col md:flex-row justify-between items-center mb-8 gap-4">
          <div className="flex items-center gap-4">
            <Link
              to="/store-manager/dashboard"
              className="inline-flex items-center justify-center px-3 py-2 bg-gray-800 hover:bg-gray-700 text-white font-medium rounded-lg shadow-sm transition duration-200"
            >
              ← ย้อนกลับ
            </Link>
            <h1 className="text-3xl font-bold text-gray-900">จัดการสินค้าทั้งหมด</h1>
          </div>
          <Link
            to="/store-manager/add-product"
            className="inline-flex items-center justify-center px-7 py-3 bg-gradient-to-r from-green-600 to-viridian-700 text-white font-semibold text-sm md:text-base rounded-lg shadow-md hover:shadow-xl hover:scale-105 transition transform duration-200 ease-in-out"
          >
            เพิ่มสินค้า
          </Link>
        </div>

        {/* Filters */}
        <div className="bg-white rounded-lg shadow-md p-6 mb-8">
          <div className="flex flex-col lg:flex-row gap-4 justify-between items-end">
            <div className="flex items-end gap-4 flex-wrap">
              {/* Category Dropdown */}
              <div className="relative" ref={dropdownRef}>
                <label className="block text-sm font-medium text-gray-700 mb-1">หมวดหมู่</label>
                <button
                  onClick={() => setOpenDropdown(!openDropdown)}
                  className="px-4 py-2 border border-gray-300 rounded-lg text-gray-600 bg-white hover:bg-gray-100 flex items-center justify-between w-[260px]"
                >
                  {selectedCategory === 'all' ? "รายการสินค้าทั้งหมด" : selectedCategory}
                  <ChevronDownIcon className="w-5 h-5 text-gray-500" />
                </button>
                {openDropdown && (
                  <div className="absolute mt-2 bg-white shadow-lg rounded-lg p-3 w-[260px] z-50">
                    <p className="p-2 hover:bg-gray-100 cursor-pointer"
                      onClick={() => { handleCategoryFilter("all"); setOpenDropdown(false); setHoverCategory(null); }}
                    >
                      รายการสินค้าทั้งหมด
                    </p>
                    {Object.keys(categories).map(cat => (
                      <div key={cat}
                        className="p-2 hover:bg-gray-100 cursor-pointer relative"
                        onMouseEnter={() => setHoverCategory(cat)}
                        onMouseLeave={() => setHoverCategory(null)}
                        onClick={() => { handleCategoryFilter(cat); setOpenDropdown(false); }}
                      >
                        {cat}
                        {hoverCategory === cat && (
                          <div className="absolute left-full top-0 bg-gray-100 shadow-lg rounded-lg p-2 min-w-[150px] z-50">
                            {categories[cat].map((sub, idx) => (
                              <div key={idx}
                                className="p-2 hover:bg-gray-200 cursor-pointer whitespace-nowrap"
                                onClick={e => { e.stopPropagation(); handleCategoryFilter(sub); setOpenDropdown(false); }}
                              >
                                {sub}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Sort Dropdown */}
              <div className="relative" ref={sortRef}>
                <label className="block text-sm font-medium text-gray-700 mb-1">จัดเรียงตาม</label>
                <button
                  onClick={() => setOpenSort(!openSort)}
                  className="px-4 py-2 border border-gray-300 rounded-lg text-gray-600 bg-white hover:bg-gray-100 flex items-center justify-between w-[260px]"
                >
                  {sortBy === "newest" ? "ใหม่ล่าสุด"
                    : sortBy === "price-low" ? "ราคาต่ำ-สูง"
                      : sortBy === "price-high" ? "ราคาสูง-ต่ำ"
                        : "ยอดนิยม"}
                  <ChevronDownIcon className="w-5 h-5 text-gray-500" />
                </button>
                {openSort && (
                  <div className="absolute mt-2 bg-white shadow-lg rounded-lg p-3 w-64 z-50">
                    {["newest", "price-low", "price-high", "popular"].map(option => (
                      <div key={option}
                        className="p-2 hover:bg-gray-100 cursor-pointer"
                        onClick={() => { handleSort(option); setOpenSort(false); }}
                      >
                        {option === "newest" ? "ใหม่ล่าสุด"
                          : option === "price-low" ? "ราคาต่ำ-สูง"
                            : option === "price-high" ? "ราคาสูง-ต่ำ"
                              : "ยอดนิยม"}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Clear Filters */}
              <button
                onClick={handleClearFilters}
                className="px-4 py-2 bg-gray-200 hover:bg-gray-300 text-gray-700 rounded-lg font-medium transition duration-200"
              >
                ล้าง
              </button>
            </div>

            <div className="text-sm text-gray-600 mt-2 lg:mt-0">
              พบสินค้า {filteredProducts.length} ชิ้น{selectedCategory !== 'all' && ` ในหมวด ${selectedCategory}`}
            </div>
          </div>
        </div>

        {/* Products Grid */}
        {currentProducts.length > 0 ? (
          <div className="grid sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6 gap-6">
            {currentProducts.map(product => (
              <ProductCard key={product.id} product={product} />
            ))}
          </div>
        ) : (
          <div className="text-center py-12">
            <p className="text-gray-500 text-lg">ไม่พบสินค้าที่ค้นหา</p>
          </div>
        )}

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="mt-12 flex justify-center">
            <nav className="flex items-center space-x-2">
              <button
                onClick={() => paginate(currentPage - 1)}
                disabled={currentPage === 1}
                className="px-4 py-2 border border-gray-300 rounded-lg hover:bg-green-50 disabled:opacity-50 disabled:cursor-not-allowed transition-colors duration-200"
              >
                ก่อนหน้า
              </button>
              {[...Array(Math.min(5, totalPages))].map((_, index) => {
                let pageNumber = index + 1;
                if (totalPages > 5) {
                  if (currentPage > 3) pageNumber = currentPage - 2 + index;
                  if (currentPage > totalPages - 3) pageNumber = totalPages - 4 + index;
                }
                if (pageNumber > 0 && pageNumber <= totalPages) {
                  return (
                    <button
                      key={pageNumber}
                      onClick={() => paginate(pageNumber)}
                      className={`px-4 py-2 rounded-lg transition-colors duration-200
                                 ${currentPage === pageNumber
                          ? "bg-gradient-to-r from-green-600 to-viridian-700 text-white shadow-md"
                          : "border border-gray-300 hover:bg-green-50 text-gray-700"
                        }`}
                    >
                      {pageNumber}
                    </button>
                  );
                }
                return null;
              })}
              <button
                onClick={() => paginate(currentPage + 1)}
                disabled={currentPage === totalPages}
                className="px-4 py-2 border border-gray-300 rounded-lg hover:bg-green-50 disabled:opacity-50 disabled:cursor-not-allowed transition-colors duration-200"
              >
                ถัดไป
              </button>
            </nav>
          </div>
        )}
      </div>
    </div>
  );
};

export default AdminProductpage;
