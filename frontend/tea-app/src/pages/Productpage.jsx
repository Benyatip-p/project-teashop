import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useLocation } from 'react-router-dom';
import { ChevronDownIcon } from '@heroicons/react/outline';
import ProductCard from '../components/ProductCard';
import LoadingSpinner from '../components/LoadingSpinner';

const categoryIdToName = {
  4: 'ชาเขียว',
  5: 'ชาอู่หลง',
  6: 'ชาดำ',
  3: 'กาชงชา',
  8: 'ที่กรองชา',
  9: 'ถ้วยชา',
};

const categories = {
  ชา: ['ชาเขียว', 'ชาขาว', 'ชาอู่หลง', 'ชาดำ'],
  กาชงชา: [],
  อุปกรณ์ชา: ['ที่กรองชา', 'ถ้วยชา'],
};

const sortLabelMap = {
  newest: 'ใหม่ล่าสุด',
  'price-low': 'ราคาต่ำ-สูง',
  'price-high': 'ราคาสูง-ต่ำ',
  popular: 'ยอดนิยม',
};

const productsPerPage = 12;

const Productpage = () => {
  const [products, setProducts] = useState([]);
  const [filteredProducts, setFilteredProducts] = useState([]);
  const [sortBy, setSortBy] = useState('newest');
  const [selectedCategory, setSelectedCategory] = useState('all');
  const [loading, setLoading] = useState(true);
  const [currentPage, setCurrentPage] = useState(1);
  const [openSort, setOpenSort] = useState(false);
  const [error, setError] = useState(null);

  const sortRef = useRef(null);

  const location = useLocation();
  const queryParams = new URLSearchParams(location.search);
  const searchQuery = queryParams.get('search')?.toLowerCase() || '';
  const categoryQuery = queryParams.get('category') || '';

  useEffect(() => {
    window.scrollTo(0, 0);
  }, [location.pathname]);

  useEffect(() => {
    const handleClickOutsideSort = (event) => {
      if (sortRef.current && !sortRef.current.contains(event.target)) {
        setOpenSort(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutsideSort);
    return () => document.removeEventListener('mousedown', handleClickOutsideSort);
  }, []);

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
          const rawImg = p.image_url || '';

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

    if (!searchQuery) {
      setFilteredProducts(products);
      setSelectedCategory('all');
      setCurrentPage(1);
      return;
    }

    const filtered = products.filter((p) => {
      const name = (p.title || p.name || '').toLowerCase();
      const category = (p.category || '').toLowerCase();
      return name.includes(searchQuery) || category.includes(searchQuery);
    });

    setFilteredProducts(filtered);
    setSelectedCategory('all');
    setCurrentPage(1);
  }, [products, searchQuery]);

  const handleCategoryFilter = useCallback(
    (category) => {
      setSelectedCategory(category);

      if (category === 'all') {
        setFilteredProducts(products);
      } else if (categories[category] !== undefined) {
        if (categories[category].length > 0) {
          const subCats = categories[category].map((c) => c.toLowerCase());
          const filtered = products.filter((product) =>
            subCats.includes((product.category || '').toLowerCase())
          );
          setFilteredProducts(filtered);
        } else {
          const filtered = products.filter(
            (product) => (product.category || '').toLowerCase() === category.toLowerCase()
          );
          setFilteredProducts(filtered);
        }
      } else {
        const filtered = products.filter(
          (product) => (product.category || '').toLowerCase() === category.toLowerCase()
        );
        setFilteredProducts(filtered);
      }

      setCurrentPage(1);
    },
    [products]
  );

  useEffect(() => {
    if (categoryQuery && products.length > 0) {
      handleCategoryFilter(categoryQuery);
    }
  }, [categoryQuery, products, handleCategoryFilter]);

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
    setOpenSort(false);
  };

  const sortLabel = sortLabelMap[sortBy] || 'เลือกการจัดเรียง';

  if (loading) {
    return <LoadingSpinner />;
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="container mx-auto px-4 py-8">
        <div className="mb-6">
          <h1 className="text-3xl font-bold text-gray-900">สินค้าทั้งหมด</h1>
        </div>

        {error && (
          <div className="mb-4 rounded bg-red-100 p-3 text-red-700">
            {error}
          </div>
        )}

        <div className="flex flex-col gap-8 md:flex-row md:items-start">
          <aside className="w-full flex-none rounded-xl bg-white p-5 shadow-sm md:w-64 lg:w-72 md:sticky md:top-24 md:self-start">
            <p className="text-base font-semibold text-gray-900 mb-4">
              หมวดหมู่
            </p>

            <button
              onClick={() => handleCategoryFilter('all')}
              className={`w-full text-left text-sm px-3 py-2 rounded-lg mb-3 ${
                selectedCategory === 'all'
                  ? 'bg-viridian-600 text-white'
                  : 'text-gray-800 hover:bg-gray-100'
              }`}
            >
              รายการสินค้าทั้งหมด
            </button>

            <div className="space-y-6">
              {Object.entries(categories).map(([parent, subs]) => (
                <div key={parent} className="border-t border-gray-200 pt-4">
                  <button
                    onClick={() => handleCategoryFilter(parent)}
                    className={`w-full text-left text-sm font-semibold px-2 py-1.5 rounded-lg ${
                      selectedCategory === parent
                        ? 'bg-viridian-50 text-viridian-700'
                        : 'text-gray-900 hover:bg-gray-100'
                    }`}
                  >
                    {parent}
                  </button>

                  {subs.length > 0 && (
                    <div className="mt-2 space-y-1 pl-4">
                      {subs.map((sub) => (
                        <button
                          key={sub}
                          onClick={() => handleCategoryFilter(sub)}
                          className={`w-full text-left text-sm px-2 py-1.5 rounded-lg ${
                            selectedCategory === sub
                              ? 'bg-viridian-600 text-white'
                              : 'text-gray-700 hover:bg-gray-100'
                          }`}
                        >
                          {sub}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>

            <div className="border-t border-gray-200 mt-6 pt-4">
              <button
                onClick={handleClearFilters}
                className="w-full rounded-lg border border-gray-300 px-4 py-2 text-sm text-gray-700 hover:bg-gray-50"
              >
                รีเซ็ตฟิลเตอร์
              </button>
            </div>
          </aside>

          <main className="flex-1">
            <div className="mb-4 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
              <p className="text-sm text-gray-600">
                พบสินค้า {filteredProducts.length} ชิ้น
                {selectedCategory !== 'all' && ` ในหมวด ${selectedCategory}`}
              </p>

              <div className="flex items-center gap-3" ref={sortRef}>
                <span className="text-sm text-gray-600">จัดเรียงตาม</span>
                <div className="relative">
                  <button
                    onClick={() => setOpenSort((prev) => !prev)}
                    className="flex w-48 items-center justify-between rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm text-gray-800 hover:bg-gray-50"
                  >
                    {sortLabel}
                    <ChevronDownIcon className="h-4 w-4" />
                  </button>

                  {openSort && (
                    <div className="absolute right-0 z-50 mt-2 w-48 rounded-lg bg-white p-2 shadow-lg">
                      <button
                        className="block w-full rounded px-2 py-2 text-left text-sm hover:bg-gray-100"
                        onClick={() => {
                          handleSort('newest');
                          setOpenSort(false);
                        }}
                      >
                        ใหม่ล่าสุด
                      </button>
                      <button
                        className="block w-full rounded px-2 py-2 text-left text-sm hover:bg-gray-100"
                        onClick={() => {
                          handleSort('price-low');
                          setOpenSort(false);
                        }}
                      >
                        ราคาต่ำ-สูง
                      </button>
                      <button
                        className="block w-full rounded px-2 py-2 text-left text-sm hover:bg-gray-100"
                        onClick={() => {
                          handleSort('price-high');
                          setOpenSort(false);
                        }}
                      >
                        ราคาสูง-ต่ำ
                      </button>
                      <button
                        className="block w-full rounded px-2 py-2 text-left text-sm hover:bg-gray-100"
                        onClick={() => {
                          handleSort('popular');
                          setOpenSort(false);
                        }}
                      >
                        ยอดนิยม
                      </button>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {currentProducts.length > 0 ? (
              <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
                {currentProducts.map((product) => (
                  <ProductCard key={product.id} product={product} />
                ))}
              </div>
            ) : (
              <div className="py-12 text-center">
                <p className="text-lg text-gray-500">ไม่พบสินค้าที่ค้นหา</p>
              </div>
            )}

            {totalPages > 1 && (
              <div className="mt-12 flex justify-center">
                <nav className="flex items-center space-x-2">
                  <button
                    onClick={() => paginate(currentPage - 1)}
                    disabled={currentPage === 1}
                    className="rounded-lg border border-gray-300 px-4 py-2 text-sm hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-50"
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
                          className={`rounded-lg px-4 py-2 text-sm ${
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
                    className="rounded-lg border border-gray-300 px-4 py-2 text-sm hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    ถัดไป
                  </button>
                </nav>
              </div>
            )}
          </main>
        </div>
      </div>
    </div>
  );
};

export default Productpage;
