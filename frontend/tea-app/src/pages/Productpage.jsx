import React, { useState, useEffect, useRef } from 'react';
import ProductCard from '../components/ProductCard';
import { useLocation } from 'react-router-dom'; 
import LoadingSpinner from '../components/LoadingSpinner';
import { ChevronDownIcon } from '@heroicons/react/outline';

const Productpage = () => {
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
  const [error, setError] = useState(null);

  const dropdownRef = useRef(null);
  const sortRef = useRef(null);

  // ดึง query 
  const location = useLocation(); 
  const queryParams = new URLSearchParams(location.search);
  const searchQuery = queryParams.get('search')?.toLowerCase() || '';

  // map category_id จาก API -> ชื่อหมวดใน UI / filter
  const categoryIdToName = {
    4: 'ชาเขียว',
    5: 'ชาอู่หลง',
    6: 'ชาดำ',
    3: 'กาชงชา',
    8: 'ที่กรองชา',
    9: 'ถ้วยชา',
  };

  // หมวดหลัก + หมวดย่อย (กาชงชา ไม่มีหมวดย่อย)
  const categories = {
    'ชา': ['ชาเขียว', 'ชาขาว', 'ชาอู่หลง', 'ชาดำ'],
    'กาชงชา': [], // ไม่มีหมวดย่อย
    'อุปกรณ์ชา': ['ที่กรองชา', 'ถ้วยชา'],
  };

  // ปิด dropdown หมวดหมู่เมื่อคลิกข้างนอก
  useEffect(() => {
    const handler = (e) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target)) {
        setOpenDropdown(false);
        setHoverCategory(null);
      }
    };

    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  // ปิด dropdown sort เมื่อคลิกข้างนอก
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (sortRef.current && !sortRef.current.contains(event.target)) {
        setOpenSort(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // ดึงข้อมูลสินค้าจาก API + map field ให้ตรงกับ ProductCard
  useEffect(() => {
    const fetchProducts = async () => {
      try {
        setLoading(true);
        setError(null);

        const response = await fetch('/api/v1/products', {
          method: 'GET',
          headers: {
            'Content-Type': 'application/json',
          },
        });

        if (!response.ok) {
          throw new Error('ไม่สามารถดึงข้อมูลสินค้า');
        }

        const resJson = await response.json();
        const productsArray = resJson.products || [];

        const normalized = productsArray.map((p) => {
          const categoryName = categoryIdToName[p.category_id] || 'ชา';
          const rawImg = p.image_url?.String || '';

          const normalizedImg = rawImg.startsWith('http')
            ? rawImg
            : rawImg.startsWith('/')
            ? rawImg                           
            : `/${rawImg}`;  

          return {
            ...p,
            id: p.id,
            title: p.name,          
            coverImage: normalizedImg,  
            price: p.price,
            originalPrice: p.price, 
            discount: null,       
            category: categoryName, 
            rating: 5,            
            reviews: 0,            
            isNew: false,        
            createdAt: p.created_at,
          };
        });

        setProducts(normalized);
        setFilteredProducts(normalized);
      } catch (err) {
        console.error('เกิดข้อผิดพลาดในการดึงข้อมูลสินค้า:', err);
        setError(err.message || 'เกิดข้อผิดพลาดในการดึงข้อมูลสินค้า');
        setProducts([]);
        setFilteredProducts([]);
      } finally {
        setLoading(false);
      }
    };

    fetchProducts();
  }, []);

  useEffect(() => {
    if (!products.length) return;

    // ถ้าไม่มีคำค้น ให้ใช้ filter เดิม (ทั้งหมด)
    if (!searchQuery) {
      setFilteredProducts(products);
      setSelectedCategory('all');
      setCurrentPage(1);
      return;
    }
    //เพิ่ม query เอาไว้ search
    const filtered = products.filter((p) => {
      const name = (p.title || p.name || '').toLowerCase();
      const category = (p.category || '').toLowerCase();
      return (
        name.includes(searchQuery) ||
        category.includes(searchQuery)
      );
    });

    setFilteredProducts(filtered);
    setSelectedCategory('all');
    setCurrentPage(1);
  }, [products, searchQuery]);

  const handleCategoryFilter = (category) => {
    setSelectedCategory(category);

    if (category === 'all') {
      setFilteredProducts(products);
    }
    // หมวดใหญ่ เช่น "ชา", "กาชงชา", "อุปกรณ์ชา"
    else if (categories[category] !== undefined) {
      if (categories[category].length > 0) {
        const subCats = categories[category].map((c) => c.toLowerCase());
        const filtered = products.filter((product) =>
          subCats.includes(product.category.toLowerCase())
        );
        setFilteredProducts(filtered);
      } else {
 
        const filtered = products.filter(
          (product) => product.category.toLowerCase() === category.toLowerCase()
        );
        setFilteredProducts(filtered);
      }
    }

    else {
      const filtered = products.filter(
        (product) => product.category.toLowerCase() === category.toLowerCase()
      );
      setFilteredProducts(filtered);
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

  // pagination
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

  if (loading) {
    return <LoadingSpinner />;
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="container mx-auto px-4 py-8">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900 mb-4">สินค้าทั้งหมด</h1>
        </div>

        {/* Error */}
        {error && (
          <div className="mb-4 p-3 bg-red-100 text-red-700 rounded">
            {error}
          </div>
        )}

        {/* Filters */}
        <div className="bg-white rounded-lg shadow-md p-6 mb-8">
          <div className="flex flex-col lg:flex-row gap-4">
            <div className="flex items-end gap-4">
              {/* Dropdown หมวดหมู่ */}
              <div className="relative" ref={dropdownRef}>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  หมวดหมู่
                </label>
                <button
                  onClick={() => setOpenDropdown(!openDropdown)}
                  className="px-4 py-2 border border-gray-300 rounded-lg text-gray-500 bg-white hover:bg-gray-100 cursor-pointer flex items-center gap-2 w-[300px] justify-between"
                >
                  {selectedCategory === 'all' ? 'รายการสินค้าทั้งหมด' : selectedCategory}
                  <ChevronDownIcon className="w-5 h-5" />
                </button>

                {openDropdown && (
                  <div className="absolute mt-2 bg-white shadow-lg rounded-lg p-3 w-[300px] z-50">
                    <p
                      className="p-2 hover:bg-gray-200 cursor-pointer"
                      onClick={() => {
                        handleCategoryFilter('all');
                        setOpenDropdown(false);
                        setHoverCategory(null);
                      }}
                    >
                      รายการสินค้าทั้งหมด
                    </p>

                    {Object.keys(categories).map((cat) => (
                      <div
                        key={cat}
                        className="p-2 hover:bg-gray-200 cursor-pointer relative"
                        onMouseEnter={() =>
                          categories[cat].length > 0 && setHoverCategory(cat)
                        }
                        onMouseLeave={() =>
                          categories[cat].length > 0 && setHoverCategory(null)
                        }
                        onClick={() => {
                          handleCategoryFilter(cat);
                          setOpenDropdown(false);
                        }}
                      >
                        {cat}

                        {/* panel ย่อย: แสดงเฉพาะหมวดที่มี subcategories */}
                        {hoverCategory === cat && categories[cat].length > 0 && (
                          <div
                            className="absolute left-full top-0 bg-gray-100 shadow-lg rounded-lg p-3 min-w-[150px] z-50"
                            onMouseEnter={() => setHoverCategory(cat)}
                            onMouseLeave={() => setHoverCategory(null)}
                          >
                            {categories[cat].map((sub, index) => (
                              <div
                                key={index}
                                className="p-2 hover:bg-gray-200 cursor-pointer whitespace-nowrap"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  handleCategoryFilter(sub);
                                  setOpenDropdown(false);
                                }}
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
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  จัดเรียงตาม
                </label>

                <button
                  onClick={() => setOpenSort(!openSort)}
                  className="px-4 py-2 border border-gray-300 rounded-lg text-gray-500 bg-white hover:bg-gray-100 cursor-pointer flex items-center gap-2 w-[300px] justify-between"
                >
                  {sortBy === 'newest'
                    ? 'ใหม่ล่าสุด'
                    : sortBy === 'price-low'
                    ? 'ราคาต่ำ-สูง'
                    : sortBy === 'price-high'
                    ? 'ราคาสูง-ต่ำ'
                    : sortBy === 'popular'
                    ? 'ยอดนิยม'
                    : 'เลือกการจัดเรียง'}
                  <ChevronDownIcon className="w-5 h-5" />
                </button>

                {openSort && (
                  <div className="absolute mt-2 bg-white shadow-lg rounded-lg p-3 w-72 z-50">
                    <div
                      className="p-2 hover:bg-gray-200 cursor-pointer "
                      onClick={() => {
                        handleSort('newest');
                        setOpenSort(false);
                      }}
                    >
                      ใหม่ล่าสุด
                    </div>

                    <div
                      className="p-2 hover:bg-gray-200 cursor-pointer"
                      onClick={() => {
                        handleSort('price-low');
                        setOpenSort(false);
                      }}
                    >
                      ราคาต่ำ-สูง
                    </div>

                    <div
                      className="p-2 hover:bg-gray-200 cursor-pointer"
                      onClick={() => {
                        handleSort('price-high');
                        setOpenSort(false);
                      }}
                    >
                      ราคาสูง-ต่ำ
                    </div>

                    <div
                      className="p-2 hover:bg-gray-200 cursor-pointer"
                      onClick={() => {
                        handleSort('popular');
                        setOpenSort(false);
                      }}
                    >
                      ยอดนิยม
                    </div>
                  </div>
                )}
              </div>

              {/* ปุ่มล้าง */}
              <button
                onClick={handleClearFilters}
                className="px-4 py-2 bg-gray-200 hover:bg-gray-300 text-gray-700 rounded-lg 
                          transition font-medium h-[42px]"
              >
                ล้าง
              </button>
            </div>
          </div>

          {/* จำนวนสินค้า */}
          <div className="mt-4 text-sm text-gray-600">
            พบสินค้า {filteredProducts.length} ชิ้น
            {selectedCategory !== 'all' && ` ในหมวด ${selectedCategory}`}
          </div>
        </div>

        {/* Products Grid */}
        {currentProducts.length > 0 ? (
          <div className="grid md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
            {currentProducts.map((product) => (
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
                className="px-4 py-2 border border-gray-300 rounded-lg 
                  hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                ก่อนหน้า
              </button>

              {[...Array(Math.min(5, totalPages))].map((_, index) => {
                let pageNumber = index + 1;
                if (totalPages > 5) {
                  if (currentPage > 3) {
                    pageNumber = currentPage - 2 + index;
                  }
                  if (currentPage > totalPages - 3) {
                    pageNumber = totalPages - 4 + index;
                  }
                }

                if (pageNumber > 0 && pageNumber <= totalPages) {
                  return (
                    <button
                      key={pageNumber}
                      onClick={() => paginate(pageNumber)}
                      className={`px-4 py-2 rounded-lg ${
                        currentPage === pageNumber
                          ? 'bg-viridian-600 text-white'
                          : 'border border-gray-300 hover:bg-gray-50'
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
                className="px-4 py-2 border border-gray-300 rounded-lg 
                  hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
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

export default Productpage;