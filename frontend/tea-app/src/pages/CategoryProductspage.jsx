// src/pages/CategoryProductsPage.js

import React, { useState, useEffect, useRef } from "react";
import { useParams } from "react-router-dom";
import ProductCard from "../components/ProductCard";
import LoadingSpinner from "../components/LoadingSpinner";
import { ChevronDownIcon } from "@heroicons/react/outline";
import { useNavigate } from "react-router-dom"; 

const CategoryProductspage = () => {
  const { categoryName } = useParams();
  const decodedCategory = decodeURIComponent(categoryName);

  const [products, setProducts] = useState([]);
  const [filteredProducts, setFilteredProducts] = useState([]);

  const [sortBy, setSortBy] = useState("newest");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [currentPage, setCurrentPage] = useState(1);
  const productsPerPage = 12;

  const sortRef = useRef(null);
  const [openSort, setOpenSort] = useState(false);
  const navigate = useNavigate();

  // แมประหว่าง category_id -> ชื่อหมวด
  const categoryIdToName = {
    4: "ชาเขียว",
    5: "ชาอู่หลง",
    6: "ชาดำ",
    3: "กาชงชา",
    8: "ที่กรองชา",
    9: "ถ้วยชา",
  };

  // ---------------------------
  // Load products from API
  // ---------------------------
  useEffect(() => {
    const fetchProducts = async () => {
      try {
        setLoading(true);
        const response = await fetch("/api/v1/products");
        if (!response.ok) throw new Error("โหลดสินค้าไม่สำเร็จ");

        const json = await response.json();
        const productsArray = json.products || [];

        // normalize fields
        const normalized = productsArray.map((p) => {
          const category = categoryIdToName[p.category_id] || "ชา";
          const rawImg = p.image_url?.String || "";

          const normalizedImg = rawImg.startsWith("http")
            ? rawImg
            : rawImg.startsWith("/")
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
            category,
            rating: 5,
            reviews: 0,
            isNew: false,
          };
        });

        setProducts(normalized);

        // 🟢 Filter ตาม category จาก URL
        const filtered = normalized.filter(
          (p) => p.category.toLowerCase() === decodedCategory.toLowerCase()
        );

        setFilteredProducts(filtered);
        setCurrentPage(1);
      } catch (err) {
        setError(err.message);
        setProducts([]);
        setFilteredProducts([]);
      } finally {
        setLoading(false);
      }
    };

    fetchProducts();
  }, [decodedCategory]);

  // ---------------------------
  // Sorting
  // ---------------------------
  const handleSort = (value) => {
    setSortBy(value);
    const sorted = [...filteredProducts];

    switch (value) {
      case "price-low":
        sorted.sort((a, b) => a.price - b.price);
        break;
      case "price-high":
        sorted.sort((a, b) => b.price - a.price);
        break;
      case "popular":
        sorted.sort((a, b) => b.reviews - a.reviews);
        break;
      default: // newest
        sorted.sort((a, b) => b.id - a.id);
    }

    setFilteredProducts(sorted);
  };

  // ---------------------------
  // Pagination
  // ---------------------------
  const indexOfLast = currentPage * productsPerPage;
  const indexOfFirst = indexOfLast - productsPerPage;
  const currentProducts = filteredProducts.slice(indexOfFirst, indexOfLast);
  const totalPages = Math.ceil(filteredProducts.length / productsPerPage);

  const paginate = (num) => setCurrentPage(num);

  // Close sort dropdown when clicking outside
  useEffect(() => {
    const handler = (e) => {
      if (sortRef.current && !sortRef.current.contains(e.target)) {
        setOpenSort(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  if (loading) return <LoadingSpinner />;

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="container mx-auto px-4 py-8">
        {/* Header */}
        <h1 className="text-3xl font-bold mb-4">
          หมวดหมู่: <span className="text-green-900">{decodedCategory}</span>
        </h1>
        <button
        type="button"
        onClick={() => navigate("/")}
        className="text-sm text-white  px-4 py-2 rounded bg-gray-500 hover:bg-gray-700 mb-6"
      >
        ← ย้อนกลับ
      </button>

        {error && (
          <div className="bg-red-100 text-red-600 p-3 rounded mb-4">{error}</div>
        )}

        {/* Sort Filter */}
        <div className="bg-white rounded-lg shadow-md p-6 mb-8 flex gap-4">
          <div className="relative" ref={sortRef}>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              จัดเรียงตาม
            </label>
            <button
              onClick={() => setOpenSort(!openSort)}
              className="px-4 py-2 border border-gray-300 rounded-lg w-[250px] flex justify-between items-center"
            >
              {sortBy === "newest"
                ? "ใหม่ล่าสุด"
                : sortBy === "price-low"
                ? "ราคาต่ำ-สูง"
                : sortBy === "price-high"
                ? "ราคาสูง-ต่ำ"
                : "ยอดนิยม"}
              <ChevronDownIcon className="w-5 h-5" />
            </button>

            {openSort && (
              <div className="absolute bg-white shadow-lg rounded-lg p-3 w-[250px] mt-2 z-50">
                <div
                  className="p-2 hover:bg-gray-200 cursor-pointer"
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
        </div>

        {/* Product Grid */}
        {currentProducts.length > 0 ? (
          <div className="grid md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
            {currentProducts.map((p) => (
              <ProductCard key={p.id} product={p} />
            ))}
          </div>
        ) : (
          <p className="text-center text-gray-500 text-lg py-10">
            ไม่พบสินค้าในหมวดหมู่นี้
          </p>
        )}

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex justify-center mt-10 space-x-2">
            <button
              onClick={() => paginate(currentPage - 1)}
              disabled={currentPage === 1}
              className="px-4 py-2 border border-gray-300 rounded-lg disabled:opacity-50"
            >
              ก่อนหน้า
            </button>

            {[...Array(totalPages)].map((_, i) => (
              <button
                key={i + 1}
                onClick={() => paginate(i + 1)}
                className={`px-4 py-2 rounded-lg ${
                  currentPage === i + 1
                    ? "bg-viridian-600 text-white"
                    : "border border-gray-300"
                }`}
              >
                {i + 1}
              </button>
            ))}

            <button
              onClick={() => paginate(currentPage + 1)}
              disabled={currentPage === totalPages}
              className="px-4 py-2 border border-gray-300 rounded-lg disabled:opacity-50"
            >
              ถัดไป
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

export default CategoryProductspage;
