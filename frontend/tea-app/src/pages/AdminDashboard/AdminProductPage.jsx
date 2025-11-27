// src/pages/AdminDashboard/AdminProductPage.jsx
import React, { useState, useEffect, useRef } from "react";
import { Link } from "react-router-dom";
import { ChevronDownIcon } from "@heroicons/react/outline";
import api from "../../api/api";
import ProductCard from "../AdminDashboard/AdminProductCard";
import LoadingSpinner from "../../components/LoadingSpinner";

const AdminProductpage = () => {
  const [products, setProducts] = useState([]);
  const [filteredProducts, setFilteredProducts] = useState([]);
  const [sortBy, setSortBy] = useState("newest");
  const [selectedCategory, setSelectedCategory] = useState("all");
  const [loading, setLoading] = useState(true);
  const [currentPage, setCurrentPage] = useState(1);

  const productsPerPage = 12;
  const [openSort, setOpenSort] = useState(false);
  const sortRef = useRef(null);

  const categories = {
    TEA: [
      "Green Tea",
      "White Tea",
      "Oolong Tea",
      "Black Tea",
      "Red Tea",
      "Flower Tea",
      "Matcha",
    ],
    "TEA Pot": ["Small Pot", "Medium Pot", "Large Pot"],
    "TEA Accessories": ["Spoons", "Filters", "Cups"],
  };

  const sortOptions = [
    { value: "newest", label: "ใหม่ล่าสุด" },
    { value: "price-low", label: "ราคาต่ำ-สูง" },
    { value: "price-high", label: "ราคาสูง-ต่ำ" },
    { value: "popular", label: "ยอดนิยม" },
  ];

  const categorySidebar = [
    { key: "all", label: "รายการสินค้าทั้งหมด", type: "all" },
    { key: "TEA", label: "ชา" },
    { key: "TEA Pot", label: "กาชงชา" },
    { key: "TEA Accessories", label: "อุปกรณ์ชา" },
  ];

  useEffect(() => {
    const handler = (e) => {
      if (sortRef.current && !sortRef.current.contains(e.target)) {
        setOpenSort(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  useEffect(() => {
    const fetchProducts = async () => {
      try {
        setLoading(true);
        const res = await api.get("/products");
        const productsArray = res.data.products || [];

        const normalized = productsArray.map((p) => ({
          ...p,
          title: p.name,
          coverImage:
            p.image_url ||
            p.coverImage ||
            "https://shop.chaipoint.com/cdn/shop/files/TeaBagsListingImages-25.jpg?v=1694165024",
          category: p.category_name || "Uncategorized",
          originalPrice: p.price,
          discount: null,
          rating: 5,
          reviews: 0,
          isNew: false,
        }));

        setProducts(normalized);
        setFilteredProducts(normalized);
      } catch (err) {
        console.error("เกิดข้อผิดพลาดในการดึงข้อมูลสินค้า:", err);
      } finally {
        setLoading(false);
      }
    };
    fetchProducts();
  }, []);

  const applyCategoryFilter = (category) => {
    setSelectedCategory(category);

    if (category === "all") {
      setFilteredProducts(products);
    } else if (categories[category]) {
      const subCats = categories[category].map((c) => c.toLowerCase());
      setFilteredProducts(
        products.filter((p) =>
          subCats.includes((p.category || "").toLowerCase())
        )
      );
    } else {
      setFilteredProducts(
        products.filter(
          (p) => (p.category || "").toLowerCase() === category.toLowerCase()
        )
      );
    }

    setCurrentPage(1);
  };

  const handleSort = (sortValue) => {
    setSortBy(sortValue);
    const sorted = [...filteredProducts];

    switch (sortValue) {
      case "price-low":
        sorted.sort((a, b) => (a.price || 0) - (b.price || 0));
        break;
      case "price-high":
        sorted.sort((a, b) => (b.price || 0) - (a.price || 0));
        break;
      case "popular":
        sorted.sort((a, b) => (b.reviews || 0) - (a.reviews || 0));
        break;
      case "newest":
      default:
        sorted.sort((a, b) => (b.id || 0) - (a.id || 0));
    }

    setFilteredProducts(sorted);
  };

  const indexOfLastProduct = currentPage * productsPerPage;
  const indexOfFirstProduct = indexOfLastProduct - productsPerPage;
  const currentProducts = filteredProducts.slice(
    indexOfFirstProduct,
    indexOfLastProduct
  );
  const totalPages = Math.ceil(filteredProducts.length / productsPerPage);

  const paginate = (pageNumber) => setCurrentPage(pageNumber);

  const handleClearFilters = () => {
    setSelectedCategory("all");
    setSortBy("newest");
    setFilteredProducts(products);
    setCurrentPage(1);
  };

  const currentSortLabel =
    sortOptions.find((opt) => opt.value === sortBy)?.label || "ใหม่ล่าสุด";

  if (loading) return <LoadingSpinner />;

  return (
    <div className="min-h-screen bg-slate-50">
      <div className="mx-auto max-w-7xl px-4 py-6 lg:px-8 lg:py-8">
        <div className="mb-6 flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div className="flex flex-wrap items-center gap-4">
            <Link
              to="/store-manager/dashboard"
              className="inline-flex items-center rounded-full border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-700 shadow-sm hover:bg-slate-50"
            >
              ← กลับไปหน้าแดชบอร์ด
            </Link>
            <div>
              <h1 className="text-2xl font-semibold text-slate-900">
                จัดการสินค้าทั้งหมด
              </h1>
              <p className="mt-1 text-sm text-slate-500">
                ดู แก้ไข และจัดการรายการสินค้าทั้งหมดในร้าน GOODTEA
              </p>
            </div>
          </div>
          <Link
            to="/store-manager/add-product"
            className="inline-flex items-center justify-center rounded-full bg-emerald-600 px-6 py-2.5 text-sm font-semibold text-white shadow-md hover:bg-emerald-700 hover:shadow-lg transition"
          >
            เพิ่มสินค้า
          </Link>
        </div>

        <div className="flex flex-col gap-8 lg:flex-row">
          <aside className="w-full lg:w-64 xl:w-72">
            <div className="rounded-2xl border border-slate-100 bg-white p-5 shadow-sm">
              <h2 className="text-base font-semibold text-slate-900">
                หมวดหมู่
              </h2>
              <p className="mt-1 text-xs text-slate-500">
                เลือกหมวดหมู่เพื่อกรองรายการสินค้า
              </p>

              <div className="mt-4 space-y-4 text-sm">
                {categorySidebar.map((group) => (
                  <div key={group.key}>
                    {group.type === "all" ? (
                      <button
                        onClick={() => applyCategoryFilter("all")}
                        className={`w-full rounded-xl px-3 py-2 text-left font-medium ${
                          selectedCategory === "all"
                            ? "bg-emerald-600 text-white"
                            : "bg-slate-50 text-slate-700 hover:bg-slate-100"
                        }`}
                      >
                        {group.label}
                      </button>
                    ) : (
                      <>
                        <button
                          type="button"
                          onClick={() => applyCategoryFilter(group.key)}
                          className={`w-full rounded-lg px-2 py-1 text-left text-xs font-semibold uppercase tracking-wide ${
                            selectedCategory === group.key
                              ? "text-emerald-700"
                              : "text-slate-500 hover:text-emerald-700"
                          }`}
                        >
                          {group.label}
                        </button>
                        <div className="mt-1 space-y-1">
                          {(categories[group.key] || []).map((sub) => (
                            <button
                              key={sub}
                              onClick={() => applyCategoryFilter(sub)}
                              className={`w-full rounded-lg px-3 py-1.5 text-left ${
                                selectedCategory === sub
                                  ? "bg-emerald-50 text-emerald-700 font-medium"
                                  : "text-slate-700 hover:bg-slate-50"
                              }`}
                            >
                              {sub}
                            </button>
                          ))}
                        </div>
                      </>
                    )}
                  </div>
                ))}
              </div>

              <button
                onClick={handleClearFilters}
                className="mt-6 w-full rounded-full border border-slate-200 bg-slate-50 px-4 py-2 text-sm font-medium text-slate-600 hover:bg-slate-100"
              >
                รีเซ็ตฟิลเตอร์
              </button>
            </div>
          </aside>

          <section className="flex-1">
            <div className="mb-4 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
              <div className="text-sm text-slate-500">
                พบสินค้า{" "}
                <span className="font-semibold text-slate-800">
                  {filteredProducts.length}
                </span>{" "}
                ชิ้น
                {selectedCategory !== "all" && (
                  <span className="ml-1">
                    ในหมวด{" "}
                    <span className="font-medium text-slate-800">
                      {selectedCategory}
                    </span>
                  </span>
                )}
              </div>

              <div className="relative w-full max-w-xs" ref={sortRef}>
                <button
                  onClick={() => setOpenSort(!openSort)}
                  className="flex w-full items-center justify-between rounded-full border border-slate-200 bg-white px-4 py-2 text-sm text-slate-700 shadow-sm hover:bg-slate-50"
                >
                  <span>จัดเรียงตาม: {currentSortLabel}</span>
                  <ChevronDownIcon className="h-4 w-4 text-slate-400" />
                </button>
                {openSort && (
                  <div className="absolute right-0 z-50 mt-2 w-full rounded-xl border border-slate-100 bg-white p-2 text-sm shadow-lg">
                    {sortOptions.map((option) => (
                      <button
                        key={option.value}
                        onClick={() => {
                          handleSort(option.value);
                          setOpenSort(false);
                        }}
                        className={`flex w-full items-center rounded-lg px-3 py-2 text-left hover:bg-slate-50 ${
                          sortBy === option.value
                            ? "font-medium text-emerald-700"
                            : "text-slate-700"
                        }`}
                      >
                        {option.label}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {currentProducts.length > 0 ? (
              <div className="grid gap-6 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-3 xl:grid-cols-4">
                {currentProducts.map((product) => (
                  <ProductCard key={product.id} product={product} />
                ))}
              </div>
            ) : (
              <div className="py-16 text-center">
                <p className="text-base text-slate-500">
                  ไม่พบสินค้าที่ค้นหา
                </p>
              </div>
            )}

            {totalPages > 1 && (
              <div className="mt-10 flex justify-center">
                <nav className="flex items-center gap-2 text-sm">
                  <button
                    onClick={() => paginate(currentPage - 1)}
                    disabled={currentPage === 1}
                    className="rounded-full border border-slate-200 px-4 py-2 text-slate-600 hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    ก่อนหน้า
                  </button>
                  {[...Array(Math.min(5, totalPages))].map((_, index) => {
                    let pageNumber = index + 1;
                    if (totalPages > 5) {
                      if (currentPage > 3) pageNumber = currentPage - 2 + index;
                      if (currentPage > totalPages - 3) {
                        pageNumber = totalPages - 4 + index;
                      }
                    }
                    if (pageNumber > 0 && pageNumber <= totalPages) {
                      const active = currentPage === pageNumber;
                      return (
                        <button
                          key={pageNumber}
                          onClick={() => paginate(pageNumber)}
                          className={`rounded-full px-3 py-2 transition-colors ${
                            active
                              ? "bg-emerald-600 text-white shadow-md"
                              : "border border-slate-200 text-slate-700 hover:bg-slate-50"
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
                    className="rounded-full border border-slate-200 px-4 py-2 text-slate-600 hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    ถัดไป
                  </button>
                </nav>
              </div>
            )}
          </section>
        </div>
      </div>
    </div>
  );
};

export default AdminProductpage;
