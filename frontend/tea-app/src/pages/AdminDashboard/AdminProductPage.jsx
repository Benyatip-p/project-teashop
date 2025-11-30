import React, { useState, useEffect } from "react"
import { Link } from "react-router-dom"
import api from "../../api/api"
import LoadingSpinner from "../../components/LoadingSpinner"
import AdminLayout from "../../components/AdminLayout"
import AdminProductTable from "./AdminProductTable"

const CATEGORY_ID_TO_NAME = {
  4: "ชาเขียว",
  5: "ชาอู่หลง",
  6: "ชาดำ",
  3: "กาชงชา",
  8: "ที่กรองชา",
  9: "ถ้วยชา",
}

const categories = {
  ชา: ["ชาเขียว", "ชาขาว", "ชาอู่หลง", "ชาดำ"],
  กาชงชา: [],
  อุปกรณ์ชา: ["ที่กรองชา", "ถ้วยชา"],
}


const productsPerPage = 12

const AdminProductpage = () => {
  const [products, setProducts] = useState([])
  const [filteredProducts, setFilteredProducts] = useState([])
  const [selectedCategory, setSelectedCategory] = useState("all")
  const [loading, setLoading] = useState(true)
  const [currentPage, setCurrentPage] = useState(1)
  //const [openSort, setOpenSort] = useState(false)

  //const sortRef = useRef(null)

  // useEffect(() => {
  //   const handler = e => {
  //     if (sortRef.current && !sortRef.current.contains(e.target)) setOpenSort(false)
  //   }
  //   document.addEventListener("mousedown", handler)
  //   return () => document.removeEventListener("mousedown", handler)
  // }, [])

  useEffect(() => {
    const fetchProducts = async () => {
      try {
        setLoading(true)
        const res = await api.get("/products")
        const productsArray = res.data.products || []

        const normalized = productsArray.map(p => {
          const categoryName =
            CATEGORY_ID_TO_NAME[p.category_id] || p.category_name || "Uncategorized"
          const coverImage =
            p.image_url ||
            p.coverImage ||
            "https://shop.chaipoint.com/cdn/shop/files/TeaBagsListingImages-25.jpg?v=1694165024"

          return {
            ...p,
            title: p.name,
            coverImage,
            category: categoryName,
            price: p.price,
            originalPrice: p.price,
            discount: null,
            rating: 5,
            reviews: p.review_count || 0,
            isNew: false,
          }
        })

        setProducts(normalized)
        setFilteredProducts(normalized)
      } catch (err) {
        console.error("เกิดข้อผิดพลาดในการดึงข้อมูลสินค้า:", err)
      } finally {
        setLoading(false)
      }
    }

    fetchProducts()
  }, [])

  const applyCategoryFilter = category => {
    setSelectedCategory(category)

    if (category === "all") {
      setFilteredProducts(products)
    } else if (categories[category] !== undefined) {
      if (categories[category].length > 0) {
        const subCats = categories[category].map(c => c.toLowerCase())
        const filtered = products.filter(p =>
          subCats.includes((p.category || "").toLowerCase())
        )
        setFilteredProducts(filtered)
      } else {
        const filtered = products.filter(
          p => (p.category || "").toLowerCase() === category.toLowerCase()
        )
        setFilteredProducts(filtered)
      }
    } else {
      const filtered = products.filter(
        p => (p.category || "").toLowerCase() === category.toLowerCase()
      )
      setFilteredProducts(filtered)
    }

    setCurrentPage(1)
  }


  const handleDeleted = id => {
    setProducts(prev => prev.filter(p => p.id !== id))
    setFilteredProducts(prev => prev.filter(p => p.id !== id))
  }

  const indexOfLastProduct = currentPage * productsPerPage
  const indexOfFirstProduct = indexOfLastProduct - productsPerPage
  const currentProducts = filteredProducts.slice(indexOfFirstProduct, indexOfLastProduct)
  const totalPages = Math.ceil(filteredProducts.length / productsPerPage)

  const paginate = pageNumber => setCurrentPage(pageNumber)


  if (loading) {
    return (
      <AdminLayout>
        <div className="px-4 py-6 lg:px-8 lg:py-8">
          <LoadingSpinner />
        </div>
      </AdminLayout>
    )
  }

  return (
    <AdminLayout>
      <div className="px-4 py-6 lg:px-8 lg:py-8">
        <div className="mb-6 flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div className="flex flex-wrap items-center gap-4">
            <Link
              to="/admin/dashboard"
              className="rounded-full border bg-white px-4 py-2 text-sm shadow-sm hover:bg-slate-50"
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
            to="/admin/create-products"
            className="rounded-full bg-emerald-600 px-6 py-2.5 text-sm font-semibold text-white shadow-md hover:bg-emerald-700"
          >
            เพิ่มสินค้า
          </Link>
        </div>

        <div className="flex flex-col gap-8 lg:flex-row">
          <aside className="w-full flex-none md:sticky md:top-24 md:self-start lg:w-64 xl:w-72">
            <div className="rounded-2xl border bg-white p-5 shadow-sm">
              <p className="mb-4 text-base font-semibold text-gray-900">
                หมวดหมู่
              </p>

              <button
                onClick={() => applyCategoryFilter("all")}
                className={`mb-3 w-full rounded-lg px-3 py-2 text-left text-sm ${selectedCategory === "all"
                  ? "bg-viridian-600 text-white"
                  : "text-gray-800 hover:bg-gray-100"
                  }`}
              >
                รายการสินค้าทั้งหมด
              </button>

              <div className="space-y-6">
                {Object.entries(categories).map(([parent, subs]) => (
                  <div key={parent} className="border-t border-gray-200 pt-4">
                    <button
                      onClick={() => applyCategoryFilter(parent)}
                      className={`w-full rounded-lg px-2 py-1.5 text-left text-sm font-semibold ${selectedCategory === parent
                        ? "bg-viridian-50 text-viridian-700"
                        : "text-gray-900 hover:bg-gray-100"
                        }`}
                    >
                      {parent}
                    </button>

                    {subs.length > 0 && (
                      <div className="mt-2 space-y-1 pl-4">
                        {subs.map(sub => (
                          <button
                            key={sub}
                            onClick={() => applyCategoryFilter(sub)}
                            className={`w-full rounded-lg px-2 py-1.5 text-left text-sm ${selectedCategory === sub
                              ? "bg-viridian-600 text-white"
                              : "text-gray-700 hover:bg-gray-100"
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

              <div className="mt-6 border-t border-gray-200 pt-4">
                <button
                  onClick={() => {
                    setSelectedCategory("all")
                    setFilteredProducts(products)
                    setCurrentPage(1)
                  }}
                  className="w-full rounded-lg border border-gray-300 px-4 py-2 text-sm text-gray-700 hover:bg-gray-50"
                >
                  รีเซ็ตฟิลเตอร์
                </button>
              </div>
            </div>
          </aside>

          <section className="flex-1">
            <div className="mb-4">
              <div className="text-sm text-slate-500">
                พบสินค้า{" "}
                <span className="font-semibold text-slate-800">
                  {filteredProducts.length}
                </span>{" "}
                ชิ้น
                {selectedCategory !== "all" && ` ในหมวด ${selectedCategory}`}
              </div>
            </div>

            <AdminProductTable
              products={currentProducts}
              onDeleted={handleDeleted}
            />

            {totalPages > 1 && (
              <div className="mt-10 flex justify-center">
                <nav className="flex items-center gap-2 text-sm">
                  <button
                    onClick={() => paginate(currentPage - 1)}
                    disabled={currentPage === 1}
                    className="rounded-full border px-4 py-2 hover:bg-slate-50 disabled:opacity-40"
                  >
                    ก่อนหน้า
                  </button>

                  {[...Array(totalPages)].map((_, i) => {
                    const active = currentPage === i + 1
                    return (
                      <button
                        key={i}
                        onClick={() => paginate(i + 1)}
                        className={`rounded-full px-3 py-2 ${active
                          ? "bg-emerald-600 text-white"
                          : "border hover:bg-slate-50"
                          }`}
                      >
                        {i + 1}
                      </button>
                    )
                  })}

                  <button
                    onClick={() => paginate(currentPage + 1)}
                    disabled={currentPage === totalPages}
                    className="rounded-full border px-4 py-2 hover:bg-slate-50 disabled:opacity-40"
                  >
                    ถัดไป
                  </button>
                </nav>
              </div>
            )}
          </section>
        </div>
      </div>
    </AdminLayout>
  )
}

export default AdminProductpage
