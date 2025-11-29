import React, { useState, useEffect } from "react"
import { useNavigate, Link } from "react-router-dom"
import api from "../../api/api"
import AdminLayout from "../../components/AdminLayout"
import LoadingSpinner from "../../components/LoadingSpinner"

const CreateTeaPage = () => {
  const navigate = useNavigate()

  const [name, setName] = useState("")
  const [categories, setCategories] = useState([])
  const [categoryId, setCategoryId] = useState("")
  const [imageUrl, setImageUrl] = useState("")
  const [imagePreview, setImagePreview] = useState("")
  const [variants, setVariants] = useState([{ weight: "", price: 0, stock: 0 }])
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [error, setError] = useState("")

  useEffect(() => {
    const fetchCategories = async () => {
      try {
        setLoading(true)
        setError("")
        const catRes = await api.get("/categories")
        const catList = catRes.data.categories || catRes.data || []
        setCategories(catList)
      } catch {
        setCategories([])
      } finally {
        setLoading(false)
      }
    }

    fetchCategories()
  }, [])

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
    setVariants(prev => [...prev, { weight: "", price: 0, stock: 0 }])
  }

  const handleRemoveVariant = index => {
    setVariants(prev =>
      prev.length <= 1 ? prev : prev.filter((_, i) => i !== index)
    )
  }

  const handleImageChange = async e => {
    const file = e.target.files?.[0]
    if (!file) return

    setImagePreview(URL.createObjectURL(file))

    try {
      setUploading(true)
      setError("")
      const formData = new FormData()
      formData.append("file", file)
      const res = await api.post("/upload", formData, {
        headers: { "Content-Type": "multipart/form-data" },
      })
      const url = res.data.url || res.data.image_url || ""
      setImageUrl(url)
    } catch {
      setError("อัปโหลดรูปภาพไม่สำเร็จ โปรดลองอีกครั้ง")
      setImageUrl("")
    } finally {
      setUploading(false)
    }
  }

  const handleSubmit = async e => {
    e.preventDefault()
    try {
      setSaving(true)
      setError("")

      const baseVariant = variants[0] || { price: 0, stock: 0 }

      const productRes = await api.post("/products", {
        name,
        category_id: categoryId ? Number(categoryId) : null,
        price: Number(baseVariant.price || 0),
        stock: Number(baseVariant.stock || 0),
        image_url: imageUrl,
      })

      const createdProduct =
        productRes.data.product || productRes.data || null
      const productId = createdProduct?.id

      if (!productId) {
        throw new Error("ไม่พบรหัสสินค้าที่สร้างใหม่")
      }

      for (const variant of variants) {
        const payload = {
          weight: Number(variant.weight || 0),
          price: Number(variant.price || 0),
          stock: Number(variant.stock || 0),
          is_active: true,
        }
        await api.post(`/variants/product/${productId}`, payload)
      }

      navigate("/admin/products")
    } catch (err) {
      setError(
        err?.response?.data?.detail ||
          err?.message ||
          "เกิดข้อผิดพลาดขณะบันทึกข้อมูลสินค้า"
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
  const previewSrc =
    imagePreview ||
    imageUrl ||
    "https://shop.chaipoint.com/cdn/shop/files/TeaBagsListingImages-25.jpg?v=1694165024"

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
                เพิ่มสินค้าใหม่
              </h1>
              <p className="mt-1 text-sm text-slate-500">
                สร้างสินค้าใหม่สำหรับร้าน GOODTEA กำหนดชื่อ หมวดหมู่ ราคา และรูปภาพ
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
                  หากยังไม่มีหมวดหมู่ สามารถไปเพิ่มภายหลังได้
                </p>
              </div>

              <div className="space-y-2">
                <label className="mb-1 block text-sm font-medium text-slate-700">
                  ขนาดสินค้า / ราคา / สต็อก
                </label>

                <div className="rounded-xl border border-slate-200 p-3">
                  <div className="grid grid-cols-[1.2fr,1fr,1fr,auto] gap-3 text-xs font-semibold text-slate-500">
                    <span>น้ำหนัก (กรัม)</span>
                    <span>ราคา (บาท)</span>
                    <span>สต็อก</span>
                    <span />
                  </div>

                  <div className="mt-2 space-y-2">
                    {variants.map((variant, index) => (
                      <div
                        key={index}
                        className="grid grid-cols-[1.2fr,1fr,1fr,auto] gap-3"
                      >
                        <input
                          type="number"
                          min="0"
                          value={variant.weight}
                          onChange={e =>
                            handleVariantChange(
                              index,
                              "weight",
                              e.target.value
                            )
                          }
                          className="rounded-xl border border-slate-200 px-3 py-2 text-sm outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-200"
                          placeholder="เช่น 50"
                        />
                        <input
                          type="number"
                          min="0"
                          value={variant.price}
                          onChange={e =>
                            handleVariantChange(
                              index,
                              "price",
                              e.target.value
                            )
                          }
                          className="rounded-xl border border-slate-200 px-3 py-2 text-sm outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-200"
                          placeholder="ราคา"
                        />
                        <input
                          type="number"
                          min="0"
                          value={variant.stock}
                          onChange={e =>
                            handleVariantChange(
                              index,
                              "stock",
                              e.target.value
                            )
                          }
                          className="rounded-xl border border-slate-200 px-3 py-2 text-sm outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-200"
                          placeholder="สต็อก"
                        />
                        <div className="flex items-center justify-end">
                          {variants.length > 1 && (
                            <button
                              type="button"
                              onClick={() => handleRemoveVariant(index)}
                              className="rounded-full bg-rose-50 px-3 py-1.5 text-xs font-medium text-rose-600 hover:bg-rose-100"
                            >
                              ลบ
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
              </div>

              <div>
                <label className="mb-1 block text-sm font-medium text-slate-700">
                  อัปโหลดรูปสินค้า
                </label>
                <input
                  type="file"
                  accept="image/*"
                  onChange={handleImageChange}
                  className="w-full text-sm"
                />
                <p className="mt-1 text-xs text-slate-400">
                  รองรับไฟล์ภาพ เช่น .jpg, .png ขนาดแนะนำ 800×800px ขึ้นไป
                </p>
                {uploading && (
                  <p className="mt-1 text-xs text-emerald-600">
                    กำลังอัปโหลดรูปภาพ...
                  </p>
                )}
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
                  disabled={saving || uploading || !imageUrl}
                  className="rounded-full bg-emerald-600 px-6 py-2.5 text-sm font-semibold text-white shadow-sm hover:bg-emerald-700 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {saving ? "กำลังบันทึก..." : "บันทึกสินค้าใหม่"}
                </button>
              </div>
            </div>
          </div>

          <div className="rounded-2xl border bg-emerald-50/60 p-6 shadow-sm">
            <h2 className="text-sm font-semibold text-emerald-800">
              ตัวอย่างดูรูปสินค้า
            </h2>
            <p className="mt-1 text-xs text-emerald-700/80">
              ระบบจะแสดงตัวอย่างจากรูปที่อัปโหลดแบบเรียลไทม์
            </p>

            <div className="mt-6 flex h-full items-center justify-center">
              <div className="flex w-full max-w-xs flex-col items-center gap-4 rounded-2xl bg-white p-4 shadow-sm">
                <div className="h-48 w-full overflow-hidden rounded-xl bg-emerald-50">
                  {previewSrc ? (
                    <img
                      src={previewSrc}
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

export default CreateTeaPage
