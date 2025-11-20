import { useState } from "react";

const BookEditForm = ({ book, onBack, onBookUpdated }) => {
  const [formData, setFormData] = useState(book);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [successMessage, setSuccessMessage] = useState("");

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: type === "checkbox" ? checked : value,
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    // ยืนยันก่อนบันทึก
    const confirmed = window.confirm("คุณแน่ใจหรือไม่ว่าต้องการบันทึกการแก้ไขนี้?");
    if (!confirmed) return;

    setIsSubmitting(true);

    try {
      const res = await fetch(`http://localhost:8080/api/v1/books/${book.id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: formData.title.trim(),
          author: formData.author.trim(),
          isbn: formData.isbn.trim(),
          year: parseInt(formData.year),
          price: parseFloat(formData.price),
          category: formData.category || "",
          original_price: formData.original_price
            ? parseFloat(formData.original_price)
            : null,
          discount: formData.discount ? parseInt(formData.discount) : 0,
          cover_image: formData.cover_image || "",
          rating: formData.rating ? parseFloat(formData.rating) : 0,
          reviews_count: formData.reviews_count
            ? parseInt(formData.reviews_count)
            : 0,
          is_new: !!formData.is_new,
          pages: formData.pages ? parseInt(formData.pages) : null,
          language: formData.language || "",
          publisher: formData.publisher || "",
          description: formData.description || "",
        }),
      });

      if (!res.ok) throw new Error("อัปเดตข้อมูลหนังสือล้มเหลว");

      const updated = await res.json();
      setSuccessMessage(`✅ แก้ไขหนังสือ "${updated.title}" สำเร็จแล้ว!`);
      onBookUpdated(updated);
    } catch (err) {
      alert(err.message);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="max-w-3xl mx-auto bg-white p-8 rounded-xl shadow">
      <h2 className="text-2xl font-bold mb-4">แก้ไขหนังสือ: {book.title}</h2>

      <form onSubmit={handleSubmit} className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* ฟิลด์ชื่อหนังสือ */}
        <div className="col-span-1">
          <label className="block text-sm font-medium text-gray-700 mb-1">ชื่อหนังสือ</label>
          <input
            name="title"
            value={formData.title || ""}
            onChange={handleChange}
            className="w-full px-4 py-2 border rounded-lg border-gray-300"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">ผู้แต่ง</label>
          <input
            name="author"
            value={formData.author || ""}
            onChange={handleChange}
            className="w-full px-4 py-2 border rounded-lg border-gray-300"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">ISBN</label>
          <input
            name="isbn"
            value={formData.isbn || ""}
            onChange={handleChange}
            className="w-full px-4 py-2 border rounded-lg border-gray-300"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">ปีที่พิมพ์</label>
          <input
            type="number"
            name="year"
            value={formData.year || ""}
            onChange={handleChange}
            className="w-full px-4 py-2 border rounded-lg border-gray-300"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">ราคา</label>
          <input
            type="number"
            name="price"
            value={formData.price || ""}
            onChange={handleChange}
            className="w-full px-4 py-2 border rounded-lg border-gray-300"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">ราคาปกติ</label>
          <input
            type="number"
            name="original_price"
            value={formData.original_price || ""}
            onChange={handleChange}
            className="w-full px-4 py-2 border rounded-lg border-gray-300"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">ส่วนลด (%)</label>
          <input
            type="number"
            name="discount"
            value={formData.discount || ""}
            onChange={handleChange}
            className="w-full px-4 py-2 border rounded-lg border-gray-300"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">หมวดหมู่</label>
          <input
            name="category"
            value={formData.category || ""}
            onChange={handleChange}
            className="w-full px-4 py-2 border rounded-lg border-gray-300"
          />
        </div>

        <div className="md:col-span-2">
          <label className="block text-sm font-medium text-gray-700 mb-1">URL รูปปก</label>
          <input
            name="cover_image"
            value={formData.cover_image || ""}
            onChange={handleChange}
            className="w-full px-4 py-2 border rounded-lg border-gray-300"
          />
          {formData.cover_image && (
            <img
              src={formData.cover_image}
              alt="cover"
              className="mt-3 h-48 object-cover rounded-lg shadow"
            />
          )}
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">คะแนน (rating)</label>
          <input
            type="number"
            step="0.1"
            name="rating"
            value={formData.rating || ""}
            onChange={handleChange}
            className="w-full px-4 py-2 border rounded-lg border-gray-300"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">จำนวนรีวิว</label>
          <input
            type="number"
            name="reviews_count"
            value={formData.reviews_count || ""}
            onChange={handleChange}
            className="w-full px-4 py-2 border rounded-lg border-gray-300"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">จำนวนหน้า</label>
          <input
            type="number"
            name="pages"
            value={formData.pages || ""}
            onChange={handleChange}
            className="w-full px-4 py-2 border rounded-lg border-gray-300"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">ภาษา</label>
          <input
            name="language"
            value={formData.language || ""}
            onChange={handleChange}
            className="w-full px-4 py-2 border rounded-lg border-gray-300"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">สำนักพิมพ์</label>
          <input
            name="publisher"
            value={formData.publisher || ""}
            onChange={handleChange}
            className="w-full px-4 py-2 border rounded-lg border-gray-300"
          />
        </div>

        <div className="flex items-center space-x-2">
          <input
            type="checkbox"
            name="is_new"
            checked={!!formData.is_new}
            onChange={handleChange}
            className="h-4 w-4 text-viridian-600 border-gray-300 rounded"
          />
          <label className="text-gray-700">เป็นหนังสือใหม่</label>
        </div>

        <div className="md:col-span-2">
          <label className="block text-sm font-medium text-gray-700 mb-1">คำอธิบาย</label>
          <textarea
            name="description"
            value={formData.description || ""}
            onChange={handleChange}
            rows={4}
            className="w-full px-4 py-2 border rounded-lg border-gray-300"
          />
        </div>

        {/* ปุ่มและข้อความ success */}
        <div className="md:col-span-2 flex flex-col gap-2 mt-6">
          {successMessage && (
            <div className="text-green-700 bg-green-50 border border-green-400 px-4 py-2 rounded-lg text-center">
              {successMessage}
            </div>
          )}
          <div className="flex gap-4">
            <button
              type="submit"
              disabled={isSubmitting}
              className={`flex-1 py-3 px-6 rounded-lg font-semibold text-white ${
                isSubmitting ? "bg-gray-400" : "bg-yellow-500 hover:bg-yellow-600"
              }`}
            >
              {isSubmitting ? "กำลังบันทึก..." : "บันทึกการแก้ไข"}
            </button>
            <button
              type="button"
              onClick={onBack} // เรียก callback ที่ parent ส่งมา
              className="px-6 py-3 border-2 border-gray-300 rounded-lg font-semibold text-gray-700 hover:bg-gray-50"
            >
              ย้อนกลับ
            </button>
          </div>
        </div>
      </form>
    </div>
  );
};

export default BookEditForm;