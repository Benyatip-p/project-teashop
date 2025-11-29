import React, { useState, useEffect, useRef } from "react";
import { useParams, useNavigate } from "react-router-dom";
import ProductCard from "../components/ProductCard";
import LoadingSpinner from "../components/LoadingSpinner";
import { ChevronDownIcon } from "@heroicons/react/outline";

const categoryIdToName = {
  4: "ชาเขียว",
  5: "ชาอู่หลง",
  6: "ชาดำ",
  3: "กาชงชา",
  8: "ที่กรองชา",
  9: "ถ้วยชา",
};

const CategoryProductspage = () => {
  const { categoryName } = useParams();
  const decodedCategory = decodeURIComponent(categoryName || "");
  const navigate = useNavigate();

  const [filteredProducts, setFilteredProducts] = useState([]);
  const [sortBy, setSortBy] = useState("newest");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [currentPage, setCurrentPage] = useState(1);
  const productsPerPage = 12;

  const sortRef = useRef(null);
  const [openSort, setOpenSort] = useState(false);

  useEffect(() => {
    const fetchProducts = async () => {
      try {
        setLoading(true);
        setError(null);

        const response = await fetch("/api/v1/products");
        if (!response.ok) throw new Error("โหลดสินค้าไม่สำเร็จ");

        const json = await response.json();
        const productsArray = json.products || [];

        const normalized = productsArray.map(p => {
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

        const filtered = normalized.filter(
          p => p.category.toLowerCase() === decodedCategory.toLowerCase()
        );

        setFilteredProducts(filtered);
        setCurrentPage(1);
      } catch (err) {
        setError(err.message || "เกิดข้อผิดพลาดในการโหลดสินค้า");
        setFilteredProducts([]);
      } finally {
        setLoading(false);
      }
    };

    fetchProducts();
  }, [decodedCategory]);

  const handleSort = value => {
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
      default:
        sorted.sort((a, b) => b.id - a.id);
    }

    setFilteredProducts(sorted);
    setCurrentPage(1);
  };

  const indexOfLast = currentPage * productsPerPage;
  const indexOfFirst = indexOfLast - productsPerPage;
  const currentProducts = filteredProducts.slice(indexOfFirst, indexOfLast);
  const totalPages = Math.ceil(filteredProducts.length / productsPerPage);

  const paginate = num => setCurrentPage(num);

  useEffect(() => {
    const handler = e => {
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
        <h1 className="mb-4 text-3xl font-bold">
          หมวดหมู่: <span className="text-green-900">{decodedCategory}</span>
        </h1>

        <button
          type="button"
          onClick={() => navigate("/")}
          className="mb-6 rounded bg-gray-500 px-4 py-2 text-sm text-white hover:bg-gray-700"
        >
          ← ย้อนกลับ
        </button>

        {error && (
          <div className="mb-4 rounded bg-red-100 p-3 text-red-600">
            {error}
          </div>
        )}

        <div className="mb-8 flex gap-4 rounded-lg bg-white p-6 shadow-md">
          <div className="relative" ref={sortRef}>
            <label className="mb-1 block text-sm font-medium text-gray-700">
              จัดเรียงตาม
            </label>
            <button
              type="button"
              onClick={() => setOpenSort(prev => !prev)}
              className="flex w-[250px] items-center justify-between rounded-lg border border-gray-300 px-4 py-2"
            >
              {sortBy === "newest"
                ? "ใหม่ล่าสุด"
                : sortBy === "price-low"
                ? "ราคาต่ำ-สูง"
                : sortBy === "price-high"
                ? "ราคาสูง-ต่ำ"
                : "ยอดนิยม"}
              <ChevronDownIcon className="h-5 w-5" />
            </button>

            {openSort && (
              <div className="absolute z-50 mt-2 w-[250px] rounded-lg bg-white p-3 shadow-lg">
                <button
                  type="button"
                  className="block w-full cursor-pointer rounded p-2 text-left hover:bg-gray-200"
                  onClick={() => {
                    handleSort("newest");
                    setOpenSort(false);
                  }}
                >
                  ใหม่ล่าสุด
                </button>
                <button
                  type="button"
                  className="block w-full cursor-pointer rounded p-2 text-left hover:bg-gray-200"
                  onClick={() => {
                    handleSort("price-low");
                    setOpenSort(false);
                  }}
                >
                  ราคาต่ำ-สูง
                </button>
                <button
                  type="button"
                  className="block w-full cursor-pointer rounded p-2 text-left hover:bg-gray-200"
                  onClick={() => {
                    handleSort("price-high");
                    setOpenSort(false);
                  }}
                >
                  ราคาสูง-ต่ำ
                </button>
                <button
                  type="button"
                  className="block w-full cursor-pointer rounded p-2 text-left hover:bg-gray-200"
                  onClick={() => {
                    handleSort("popular");
                    setOpenSort(false);
                  }}
                >
                  ยอดนิยม
                </button>
              </div>
            )}
          </div>
        </div>

        {currentProducts.length > 0 ? (
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
            {currentProducts.map(p => (
              <ProductCard key={p.id} product={p} />
            ))}
          </div>
        ) : (
          <p className="py-10 text-center text-lg text-gray-500">
            ไม่พบสินค้าในหมวดหมู่นี้
          </p>
        )}

        {totalPages > 1 && (
          <div className="mt-10 flex justify-center space-x-2">
            <button
              type="button"
              onClick={() => paginate(currentPage - 1)}
              disabled={currentPage === 1}
              className="rounded-lg border border-gray-300 px-4 py-2 disabled:opacity-50"
            >
              ก่อนหน้า
            </button>

            {Array.from({ length: totalPages }).map((_, i) => (
              <button
                key={i + 1}
                type="button"
                onClick={() => paginate(i + 1)}
                className={`rounded-lg px-4 py-2 ${
                  currentPage === i + 1
                    ? "bg-viridian-600 text-white"
                    : "border border-gray-300"
                }`}
              >
                {i + 1}
              </button>
            ))}

            <button
              type="button"
              onClick={() => paginate(currentPage + 1)}
              disabled={currentPage === totalPages}
              className="rounded-lg border border-gray-300 px-4 py-2 disabled:opacity-50"
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
