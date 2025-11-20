import React, { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";

const EditTeaPage = () => {
  const { id } = useParams();
  const navigate = useNavigate();

  const [product, setProduct] = useState(null);
  const [loading, setLoading] = useState(true);

useEffect(() => {
  fetch(`/api/v1/products/${id}`)
    .then((res) => res.json())
    .then((data) => {
      const productData = {
        ...data,
        coverImage: data.image_url || data.coverImage || "https://shop.chaipoint.com/cdn/shop/files/TeaBagsListingImages-25.jpg?v=1694165024",
        title: data.name || data.title,
        category: data.category_name || data.category,
        price: data.price,
      };
      setProduct(productData);
      setLoading(false);
    })
    .catch(() => {
      alert("โหลดข้อมูลสินค้าไม่สำเร็จ");
      setLoading(false);
    });
}, [id]);

  if (loading) return <p className="p-6 text-center">กำลังโหลดข้อมูล...</p>;
  if (!product) return <p className="p-6 text-center text-red-600">ไม่พบข้อมูลสินค้า</p>;

  const handleSubmit = async (e) => {
    e.preventDefault();

    const body = {
      name: product.title,
      category_id: product.category_id || product.categoryId,
      description: product.description,
      price: product.price,
      stock: product.stock,
      image_url: product.coverImage,
      is_active: product.is_active ?? true,
    };

    const res = await fetch(`/api/v1/products/${id}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    if (!res.ok) return alert("แก้ไขสินค้าไม่สำเร็จ");

    alert("อัปเดตข้อมูลสินค้าเรียบร้อย!");
    navigate("/store-manager/products");
  };

  return (
    <div className="max-w-5xl mx-auto p-6">
      <h1 className="text-3xl font-bold mb-6">แก้ไขสินค้า</h1>

      {/* ----- Edit Form ----- */}
      <form onSubmit={handleSubmit} className="bg-white p-6 rounded-xl shadow">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">

          {/* LEFT SIDE — FORM */}
          <div className="md:col-span-2 space-y-4">

            <div>
              <label className="font-semibold">ชื่อสินค้า</label>
              <input
                type="text"
                className="w-full mt-1 p-2 border rounded"
                value={product.title}
                onChange={(e) => setProduct({ ...product, title: e.target.value })}
              />
            </div>

            <div>
              <label className="font-semibold">หมวดหมู่</label>
              <input
                type="text"
                className="w-full mt-1 p-2 border rounded"
                value={product.category}
                onChange={(e) => setProduct({ ...product, category: e.target.value })}
              />
            </div>

            <div>
              <label className="font-semibold">ราคา</label>
              <input
                type="number"
                className="w-full mt-1 p-2 border rounded"
                value={product.price}
                onChange={(e) => setProduct({ ...product, price: Number(e.target.value) })}
              />
            </div>

            <div>
              <label className="font-semibold">สต็อก</label>
              <input
                type="number"
                className="w-full mt-1 p-2 border rounded"
                value={product.stock}
                onChange={(e) => setProduct({ ...product, stock: Number(e.target.value) })}
              />
            </div>

            <div>
              <label className="font-semibold">ลิงก์รูปภาพ (Image URL)</label>
              <input
                type="text"
                className="w-full mt-1 p-2 border rounded"
                value={product.coverImage}
                onChange={(e) => setProduct({ ...product, coverImage: e.target.value })}
              />
            </div>

          </div>

          {/* RIGHT SIDE — IMAGE PREVIEW */}
          <div className="flex flex-col items-center">
            <p className="font-medium mb-2">ตัวอย่างรูปภาพ</p>

            <img
              src={product.coverImage}
              alt="preview"
              className="w-48 h-48 object-cover rounded-lg border shadow"
            />
          </div>

        </div>

        <button
          type="submit"
          className="w-full mt-6 bg-green-600 text-white p-3 rounded-lg text-lg font-semibold hover:bg-green-700"
        >
          บันทึกการแก้ไข
        </button>
      </form>
    </div>
  );
};

export default EditTeaPage;
