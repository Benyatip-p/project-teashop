// src/pages/EditTeaPage/EditTeaPage.jsx
import React, { useState, useEffect } from "react"
import { useParams, useNavigate, Link } from "react-router-dom"
import api from "../../api/api"
import AdminLayout from "../../components/AdminLayout"
import LoadingSpinner from "../../components/LoadingSpinner"

const EditTeaPage = () => {
  const { id } = useParams()
  const navigate = useNavigate()

  const [name, setName] = useState("")
  const [categories, setCategories] = useState([])
  const [categoryId, setCategoryId] = useState("")
  const [imageUrl, setImageUrl] = useState("")
  const [variants, setVariants] = useState([
    { id: null, weight: "", price: 0, stock: 0 },
  ])
  const [initialVariantIds, setInitialVariantIds] = useState([])
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState("")

  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true)
        setError("")

        const productRes = await api.get(`/products/${id}`)
        const product = productRes.data.product || productRes.data

        let catList = []
        try {
          const catRes = await api.get("/categories")
          catList = catRes.data.categories || catRes.data || []
        } catch {
          catList = []
        }

        let variantList = []
        try {
          const vRes = await api.get(`/variants/product/${id}`)
          const raw = vRes.data.variants || vRes.data || []
          variantList = raw.map(v => ({
            id: v.id,
            weight: v.weight ?? "",
            price: v.price ?? 0,
            stock: v.stock ?? 0,
          }))
        } catch {
          variantList = []
        }

        setCategories(catList)
        setName(product.name || product.title || "")
        setCategoryId(product.category_id ? String(product.category_id) : "")
        setImageUrl(
          product.image_url ||
          product.coverImage ||
          "https://shop.chaipoint.com/cdn/shop/files/TeaBagsListingImages-25.jpg?v=1694165024"
        )

        if (variantList.length > 0) {
          setVariants(variantList)
          setInitialVariantIds(
            variantList.map(v => v.id).filter(vId => vId != null)
          )
        } else {
          const fallbackVariant = {
            id: null,
            weight: "",
            price: product.price ?? 0,
            stock: product.stock ?? 0,
          }
          setVariants([fallbackVariant])
          setInitialVariantIds([])
        }
      } catch {
        setError("ไม่สามารถดึงข้อมูลสินค้าที่ต้องการแก้ไขได้")
      } finally {
        setLoading(false)
      }
    }

    fetchData()
  }, [id])

  const handleVariantChange = (index, field, value) => {
    setVariants(prev =>
      prev.map((v, i) =>
        i === index
          ? {
            ...v,
            [field]:
              field === "weight"
                ? value
                : value === ""
                  ? ""
                  : Number(value),
          }
          : v
      )
    )
  }

  const handleAddVariant = () => {
    setVariants(prev => [
      ...prev,
      { id: null, weight: "", price: 0, stock: 0 },
    ])
  }

  const handleRemoveVariant = index => {
    setVariants(prev =>
      prev.length <= 1 ? prev : prev.filter((_, i) => i !== index)
    )
  }

  const handleSubmit = async e => {
    e.preventDefault()
    try {
      setSaving(true)
      setError("")

      const baseVariant = variants[0] || { price: 0, stock: 0 }

      await api.put(`/products/${id}`, {
        name,
        category_id: categoryId ? Number(categoryId) : null,
        price: Number(baseVariant.price || 0),
        stock: Number(baseVariant.stock || 0),
        image_url: imageUrl,
      })

      const currentVariantIds = variants
        .map(v => v.id)
        .filter(vId => vId != null)

      const toDeactivate = initialVariantIds.filter(
        vId => !currentVariantIds.includes(vId)
      )

      for (const variant of variants) {
        const payload = {
          weight: Number(variant.weight || 0),
          price: Number(variant.price || 0),
          stock: Number(variant.stock || 0),
          is_active: true,
        }

        if (variant.id) {
          await api.put(`/variants/${variant.id}`, payload)
        } else {
          await api.post(`/variants/product/${id}`, payload)
        }
      }

      for (const vId of toDeactivate) {
        await api.put(`/variants/${vId}`, { is_active: false })
      }

      navigate("/admin/products")
    } catch (err) {
      setError(
        err?.response?.data?.detail || "เกิดข้อผิดพลาดขณะบันทึกข้อมูลสินค้า"
      )
    } finally {
      setSaving(false)
    }
  }

  if (loading) {
    return (
      <AdminLayout>
        <div className="px-4 py-6 lg:px-8 lg:py-8">
          <LoadingSpinner />
        </div>
      </AdminLayout>
    )
  }

  const selectedCategoryName =
    categories.find(c => String(c.id) === String(categoryId))?.name || ""

  const previewPrice = variants[0]?.price || 0

  return (
    <AdminLayout>
      <div className="px-4 py-6 lg:px-8 lg:py-8">
        <div className="mb-6 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Link
              to="/admin/products"
              className="rounded-full border bg-white px-4 py-2 text-sm shadow-sm hover:bg-slate-50"
            >
              ← กลับไปหน้าจัดการสินค้าทั้งหมด
            </Link>
            <div>
              <h1 className="text-2xl font-semibold text-slate-900">
                แก้ไขสินค้า
              </h1>
              <p className="mt-1 text-sm text-slate-500">
                ปรับชื่อ ราคา รูปภาพ และรายละเอียดสินค้าในร้าน GOODTEA
              </p>
            </div>
          </div>
        </div>

        {error && (
          <div className="mb-4 rounded-xl bg-rose-50 px-4 py-3 text-sm text-rose-700">
            {error}
          </div>
        )}

        <form
          onSubmit={handleSubmit}
          className="grid gap-6 lg:grid-cols-[minmax(0,2fr)_minmax(0,1.4fr)]"
        >
          <div className="rounded-2xl border bg-white p-6 shadow-sm">
            <div className="space-y-4">
              <div>
                <label className="mb-1 block text-sm font-medium text-slate-700">
                  ชื่อสินค้า
                </label>
                <input
                  type="text"
                  value={name}
                  onChange={e => setName(e.target.value)}
                  className="w-full rounded-xl border border-slate-200 px-3 py-2 text-sm outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-200"
                  required
                />
              </div>

              <div>
                <label className="mb-1 block text-sm font-medium text-slate-700">
                  หมวดหมู่
                </label>
                <select
                  value={categoryId}
                  onChange={e => setCategoryId(e.target.value)}
                  className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-200"
                >
                  <option value="">เลือกหมวดหมู่จากระบบ</option>
                  {categories.map(cat => (
                    <option key={cat.id} value={cat.id}>
                      {cat.name}
                    </option>
                  ))}
                </select>
                <p className="mt-1 text-xs text-slate-400">
                  เลือกจากรายการด้านบน หรือเพิ่มหมวดหมู่ใหม่ในภายหลังได้
                </p>
              </div>

              <div className="rounded-xl border border-slate-200 p-3">
                {/* ส่วนหัวตาราง: ซ่อนบนมือถือ (hidden) แสดงบนจอใหญ่ (sm:grid) */}
                <div className="hidden sm:grid grid-cols-[1.2fr,1fr,1fr,auto] gap-3 text-xs font-semibold text-slate-500 mb-2">
                  <span>น้ำหนัก (กรัม)</span>
                  <span>ราคา (บาท)</span>
                  <span>สต็อก</span>
                  <span />
                </div>

                <div className="space-y-4 sm:space-y-2">
                  {variants.map((variant, index) => (
                    <div
                      key={variant.id ?? index}
                      // แก้ไข Grid: มือถือเป็น 2 คอลัมน์, จอใหญ่เป็น 4 คอลัมน์เหมือนเดิม
                      // เพิ่ม bg-slate-50 บนมือถือเพื่อให้แยกแต่ละรายการได้ง่ายขึ้น
                      className="grid grid-cols-2 gap-3 rounded-lg border border-slate-100 bg-slate-50 p-3 sm:grid-cols-[1.2fr,1fr,1fr,auto] sm:border-0 sm:bg-white sm:p-0"
                    >
                      {/* น้ำหนัก */}
                      <div className="col-span-2 sm:col-span-1">
                        <label className="mb-1 block text-xs font-medium text-slate-500 sm:hidden">
                          น้ำหนัก (กรัม)
                        </label>
                        <input
                          type="number"
                          min="0"
                          value={variant.weight}
                          onChange={e =>
                            handleVariantChange(index, "weight", e.target.value)
                          }
                          className="w-full rounded-xl border border-slate-200 px-3 py-2 text-sm outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-200 bg-white"
                          placeholder="เช่น 50"
                        />
                      </div>

                      {/* ราคา */}
                      <div className="col-span-1">
                        <label className="mb-1 block text-xs font-medium text-slate-500 sm:hidden">
                          ราคา
                        </label>
                        <input
                          type="number"
                          min="0"
                          value={variant.price}
                          onChange={e =>
                            handleVariantChange(index, "price", e.target.value)
                          }
                          className="w-full rounded-xl border border-slate-200 px-3 py-2 text-sm outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-200 bg-white"
                          placeholder="ราคา"
                        />
                      </div>

                      {/* สต็อก */}
                      <div className="col-span-1">
                        <label className="mb-1 block text-xs font-medium text-slate-500 sm:hidden">
                          สต็อก
                        </label>
                        <input
                          type="number"
                          min="0"
                          value={variant.stock}
                          onChange={e =>
                            handleVariantChange(index, "stock", e.target.value)
                          }
                          className="w-full rounded-xl border border-slate-200 px-3 py-2 text-sm outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-200 bg-white"
                          placeholder="สต็อก"
                        />
                      </div>

                      {/* ปุ่มลบ */}
                      <div className="col-span-2 flex items-center justify-end sm:col-span-1">
                        {variants.length > 1 && (
                          <button
                            type="button"
                            onClick={() => handleRemoveVariant(index)}
                            className="rounded-full bg-rose-50 px-3 py-1.5 text-xs font-medium text-rose-600 hover:bg-rose-100 w-full sm:w-auto"
                          >
                            ลบรายการนี้
                          </button>
                        )}
                      </div>
                    </div>
                  ))}
                </div>

                <button
                  type="button"
                  onClick={handleAddVariant}
                  className="mt-3 w-full rounded-xl border border-dashed border-emerald-300 px-3 py-2 text-sm font-medium text-emerald-700 hover:bg-emerald-50"
                >
                  + เพิ่มขนาดสินค้า
                </button>
              </div>

              <div>
                <label className="mb-1 block text-sm font-medium text-slate-700">
                  ลิงก์รูปสินค้า (URL)
                </label>
                <input
                  type="text"
                  value={imageUrl}
                  onChange={e => setImageUrl(e.target.value)}
                  className="w-full rounded-xl border border-slate-200 px-3 py-2 text-sm outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-200"
                  placeholder="https://..."
                />
                <p className="mt-1 text-xs text-slate-400">
                  แนะนำรูป 800×800px ขึ้นไป
                </p>
              </div>

              <div className="mt-6 flex gap-3">
                <button
                  type="button"
                  onClick={() => navigate("/admin/products")}
                  className="rounded-full border border-slate-200 bg-white px-5 py-2.5 text-sm text-slate-700 hover:bg-slate-50"
                >
                  ยกเลิก
                </button>
                <button
                  type="submit"
                  disabled={saving}
                  className="rounded-full bg-emerald-600 px-6 py-2.5 text-sm font-semibold text-white shadow-sm hover:bg-emerald-700 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {saving ? "กำลังบันทึก..." : "บันทึกสินค้า"}
                </button>
              </div>
            </div>
          </div>

          <div className="rounded-2xl border bg-emerald-50/60 p-6 shadow-sm">
            <h2 className="text-sm font-semibold text-emerald-800">
              ตัวอย่างดูรูปสินค้า
            </h2>
            <p className="mt-1 text-xs text-emerald-700/80">
              ระบบจะแสดงตัวอย่างจากลิงก์ด้านซ้ายแบบเรียลไทม์
            </p>

            <div className="mt-6 flex h-full items-center justify-center">
              <div className="flex w-full max-w-xs flex-col items-center gap-4 rounded-2xl bg-white p-4 shadow-sm">
                <div className="h-48 w-full overflow-hidden rounded-xl bg-emerald-50">
                  {imageUrl ? (
                    <img
                      src={imageUrl}
                      alt={name}
                      className="h-full w-full object-contain"
                    />
                  ) : (
                    <div className="flex h-full items-center justify-center text-xs text-slate-400">
                      ไม่มีตัวอย่างรูปภาพ
                    </div>
                  )}
                </div>
                <div className="w-full space-y-1 text-center">
                  <div className="text-sm font-semibold text-slate-900">
                    {name || "ชื่อสินค้า"}
                  </div>
                  <div className="text-xs text-slate-500">
                    {selectedCategoryName || "หมวดหมู่"}
                  </div>
                  <div className="text-sm font-semibold text-emerald-700">
                    ฿{previewPrice}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </form>
      </div>
    </AdminLayout>
  )
}

export default EditTeaPage
