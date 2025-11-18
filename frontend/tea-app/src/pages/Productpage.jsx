import React, { useState, useEffect } from 'react';
import ProductCard from '../components/ProductCard';
import LoadingSpinner from '../components/LoadingSpinner';
import { ChevronDownIcon } from '@heroicons/react/outline';
import { getAllProducts } from '../data/productsData';
import { useRef } from "react";

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
  
  const categories = {
  'TEA': ['Green Tea', 'White Tea', 'Oolong Tea', 'Black Tea', 'Red Tea', 'Flower Tea', 'Matcha'],
  'TEA Pot': ['Small Pot', 'Medium Pot', 'Large Pot'],
  'TEA Accessories': ['Spoons', 'Filters', 'Cups']
};

  const [error, setError] = useState(null);

  //คลิกนอก dropdown ให้ปิดของ หมวดหมู่
  const dropdownRef = useRef(null);
  useEffect(() => {
  const handler = (e) => {
    if (dropdownRef.current && !dropdownRef.current.contains(e.target)) {
      setOpenDropdown(false);
      setHoverCategory(null);
    }
  };

    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);
  //คลิกนอก dropdown ให้ปิดของ sort
  const [openSort, setOpenSort] = useState(false);
  const sortRef = useRef(null);

  useEffect(() => {
  const handleClickOutside = (event) => {
    if (sortRef.current && !sortRef.current.contains(event.target)) {
      setOpenSort(false);
    }
  };

    document.addEventListener("mousedown", handleClickOutside);

    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
    };
  }, []);


  /*useEffect(() => {
  // เริ่มโหลดข้อมูล
  setLoading(true);

  // ใช้ฟังก์ชัน fetch เพื่อดึงข้อมูลจากฐานข้อมูล
  const fetchBooks = async () => {
    try {
      // เรียก API เพื่อดึงข้อมูลหนังสือ
      const response = await fetch('/api/v1/books');
      
      if (!response.ok) {
        throw new Error('ไม่สามารถดึงข้อมูลหนังสือ');
      }

      const data = await response.json();

      // เก็บข้อมูลหนังสือทั้งหมดใน state
      setBooks(data);
      setFilteredBooks(data);
    } catch (err) {
      console.error('เกิดข้อผิดพลาดในการดึงข้อมูลหนังสือ:', err);
      setError(err.message); // เก็บข้อความข้อผิดพลาด
    } finally {
      setLoading(false); // ปิดสถานะการโหลด
    }
  };*/

  useEffect(() => {
  const fetchProducts = async () => {
    try {
      setLoading(true);
      const data = await getAllProducts();   // ← ใช้ mock แทน fetch
      setProducts(data);
      setFilteredProducts(data);
    } catch (err) {
      console.error("เกิดข้อผิดพลาดในการดึงข้อมูลสินค้า:", err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };


  // เรียกใช้ฟังก์ชันดึงข้อมูล
  fetchProducts();
}, []);


  const handleCategoryFilter = (category) => {
  setSelectedCategory(category);

      if (category === "all") {
        setFilteredProducts(products);
      }
      // หมวดหมู่ใหญ่ เช่น TEA, TEA Pot, TEA Accessories
      else if (categories[category]) {
        const subCats = categories[category].map(c => c.toLowerCase());

        const filtered = products.filter(product =>
          subCats.includes(product.category.toLowerCase())
        );

        setFilteredProducts(filtered);
      }
      // หมวดหมู่ย่อย เช่น Green Tea, Matcha
      else {
        const filtered = products.filter(product =>
          product.category.toLowerCase() === category.toLowerCase()
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

  // Pagination logic
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
  }

  if (loading) {
    return <LoadingSpinner />;
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="container mx-auto px-4 py-8">
        {/* Page Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900 mb-4">สินค้าทั้งหมด</h1>
        </div>
        
        {/* Filters */}
        <div className="bg-white rounded-lg shadow-md p-6 mb-8">
          <div className="flex flex-col lg:flex-row gap-4">
            
            <div className="flex items-end gap-4">

              {/* Dropdown filter หมวดหมู่ */}
              <div className="relative" ref={dropdownRef}>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  หมวดหมู่
                </label>
                <button
                  onClick={() => setOpenDropdown(!openDropdown)}
                  className="px-4 py-2 border border-gray-300 rounded-lg text-gray-500 bg-white hover:bg-gray-100 cursor-pointer flex items-center gap-2 w-[300px] justify-between"
                >
                  {selectedCategory === 'all' ? "รายการสินค้าทั้งหมด" : selectedCategory}
                  <ChevronDownIcon className="w-5 h-5" />
                </button>

                {openDropdown && (
                  <div className="absolute mt-2 bg-white shadow-lg rounded-lg p-3 w-[300px] z-50">
                    <p
                      className="p-2 hover:bg-gray-200 cursor-pointer"
                      onClick={() => {
                        handleCategoryFilter("all");
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
                        onMouseEnter={() => setHoverCategory(cat)}
                        onMouseLeave={() => setHoverCategory(null)}
                        onClick={() => {
                          handleCategoryFilter(cat);
                          setOpenDropdown(false);
                        }}
                      >
                        {cat}

                        {hoverCategory === cat && (
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
                  {sortBy === "newest"
                    ? "ใหม่ล่าสุด"
                    : sortBy === "price-low"
                    ? "ราคาต่ำ-สูง"
                    : sortBy === "price-high"
                    ? "ราคาสูง-ต่ำ"
                    : sortBy === "popular"
                    ? "ยอดนิยม"
                    : "เลือกการจัดเรียง"}
                  <ChevronDownIcon className="w-5 h-5" />
                </button>

                {openSort && (
                  <div className="absolute mt-2 bg-white shadow-lg rounded-lg p-3 w-72 z-50">
                    <div
                      className="p-2 hover:bg-gray-200 cursor-pointer "
                      onClick={() => {
                        handleSort("newest");
                        setOpenSort(false);
                      }}
                    >
                      ใหม่ล่าสุด
                    </div>

                    <div
                      className="p-2 hover:bg-gray-200 cursor-pointer"
                      onClick={() => {
                        handleSort("price-low");
                        setOpenSort(false);
                      }}
                    >
                      ราคาต่ำ-สูง
                    </div>

                    <div
                      className="p-2 hover:bg-gray-200 cursor-pointer"
                      onClick={() => {
                        handleSort("price-high");
                        setOpenSort(false);
                      }}
                    >
                      ราคาสูง-ต่ำ
                    </div>

                    <div
                      className="p-2 hover:bg-gray-200 cursor-pointer"
                      onClick={() => {
                        handleSort("popular");
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
          
          {/* Results count */}
          <div className="mt-4 text-sm text-gray-600">
            พบสินค้า {filteredProducts.length} ชิ้น
            {selectedCategory !== 'all' && ` ในหมวด ${selectedCategory}`}
          </div>
        </div>
        
        {/* Products Grid */}
        {currentProducts.length > 0 ? (
          <div className="grid md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
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
                className="px-4 py-2 border border-gray-300 rounded-lg 
                  hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed">
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
                  hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed">
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