import React, { useState } from "react"
import { Link } from "react-router-dom"
import api from "../../api/api"
import DeleteConfirmationModal from "../../components/DeleteConfirmationModal"

const CATEGORY_ID_TO_NAME = {
  1: "ชาใบ",
  2: "อุปกรณ์ชงชา",
  3: "กาชงชา",
  4: "ชาเขียว",
  5: "ชาอู่หลง",
  6: "ชาดำ",
  7: "ชาขาว",
  8: "ที่กรองชา",
  9: "ถ้วยชา",
}

const resolveImageSrc = coverImage => {
  if (!coverImage) return "/images/placeholder.jpg"
  if (/^https?:\/\//.test(coverImage)) return coverImage
  const filename = coverImage.split("/").pop()
  return `/images/products/${filename}`
}

const AdminProductTable = ({ products, onDeleted }) => {
  const [deleteModal, setDeleteModal] = useState({
    isOpen: false,
    product: null,
  })

  const handleDeleteClick = product => {
    setDeleteModal({
      isOpen: true,
      product: product,
    })
  }

  const handleDeleteConfirm = async () => {
    const product = deleteModal.product
    if (!product) return

    try {
      await api.delete(`/products/${product.id}`)
      if (onDeleted) onDeleted(product.id)
      setDeleteModal({ isOpen: false, product: null })
    } catch (err) {
      alert(err?.response?.data?.detail || "เกิดข้อผิดพลาดในการลบสินค้า")
      setDeleteModal({ isOpen: false, product: null })
    }
  }

  const handleDeleteCancel = () => {
    setDeleteModal({ isOpen: false, product: null })
  }

  return (
    <div className="overflow-x-auto rounded-2xl border bg-white shadow-sm">
      <table className="min-w-full text-sm">
        <thead className="bg-slate-50 text-xs font-semibold text-slate-500">
          <tr>
            <th className="px-4 py-3 text-left">สินค้า</th>
            <th className="px-4 py-3 text-left">หมวดหมู่</th>
            <th className="px-4 py-3 text-center">รีวิว</th>
            <th className="px-4 py-3 text-right">การจัดการ</th>
          </tr>
        </thead>

        <tbody className="divide-y divide-slate-100">
          {products.map(product => {
            const imageSrc = resolveImageSrc(product.coverImage)
            const categoryName =
              CATEGORY_ID_TO_NAME[product.category_id] ||
              CATEGORY_ID_TO_NAME[product.categoryId] ||
              product.category ||
              "ไม่ระบุหมวดหมู่"

            return (
              <tr key={product.id} className="hover:bg-slate-50/60">
                <td className="px-4 py-3">
                  <div className="flex items-center gap-3">
                    <div className="h-12 w-12 overflow-hidden rounded-lg bg-slate-100">
                      <img src={imageSrc} alt={product.title} className="h-full w-full object-cover" />
                    </div>
                    <div>
                      <div className="text-sm font-medium text-slate-900">
                        {product.title || "ไม่มีชื่อสินค้า"}
                      </div>
                    </div>
                  </div>
                </td>

                <td className="px-4 py-3 text-sm text-slate-700">
                  {categoryName}
                </td>

                <td className="px-4 py-3 text-center text-xs text-slate-500">
                  {product.reviews || 0} รีวิว
                </td>

                <td className="px-4 py-3">
                  <div className="flex justify-end gap-2">
                    <Link
                      to={`/admin/update-products/${product.id}`}
                      className="rounded-full bg-emerald-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-emerald-700"
                    >
                      แก้ไข
                    </Link>
                    <button
                      onClick={() => handleDeleteClick(product)}
                      className="rounded-full bg-rose-50 px-3 py-1.5 text-xs font-semibold text-rose-600 hover:bg-rose-100"
                    >
                      ลบ
                    </button>
                  </div>
                </td>
              </tr>
            )
          })}

          {products.length === 0 && (
            <tr>
              <td colSpan={4} className="px-4 py-8 text-center text-sm text-slate-400">
                ไม่มีสินค้าในหมวดนี้
              </td>
            </tr>
          )}
        </tbody>
      </table>

      <DeleteConfirmationModal
        isOpen={deleteModal.isOpen}
        onClose={handleDeleteCancel}
        onConfirm={handleDeleteConfirm}
        product={deleteModal.product}
      />
    </div>
  )
}

export default AdminProductTable
