// src/pages/DeleteBookPage.jsx
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { TrashIcon, BookOpenIcon, ArrowLeftIcon, XIcon } from "@heroicons/react/outline";

const DeleteBookPage = () => {
  const navigate = useNavigate();
  const [books, setBooks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [bookToDelete, setBookToDelete] = useState(null);

  useEffect(() => {
    if (localStorage.getItem("isAdminAuthenticated") !== "true") {
      navigate("/login");
    }
  }, [navigate]);

  useEffect(() => {
    const fetchBooks = async () => {
      try {
        const res = await fetch("http://localhost:8081/products");
        if (!res.ok) throw new Error("โหลด products ล้มเหลว");
        const data = await res.json();
        setBooks(data);
      } catch (error) {
        console.error(error);
        alert(error.message);
      } finally {
        setLoading(false);
      }
    };
    fetchBooks();
  }, []);

  const confirmDelete = async () => {
    if (!bookToDelete) return;
    try {
      const res = await fetch(`http://localhost:8081/products/${bookToDelete.id}`, {
        method: "DELETE",
      });
      if (!res.ok) throw new Error("ลบหนังสือล้มเหลว");
      setBooks((prev) => prev.filter((b) => b.id !== bookToDelete.id));
      alert(`ลบหนังสือ "${bookToDelete.title}" เรียบร้อยแล้ว`);
      setBookToDelete(null);
    } catch (error) {
      console.error(error);
      alert(error.message);
    }
  };

  if (loading) return <p className="text-center py-10">กำลังโหลด...</p>;

  return (
    <div className="min-h-screen bg-gray-50 relative">
      <header className="bg-gradient-to-r from-viridian-600 to-green-700 text-white shadow-lg">
        <div className="container mx-auto px-4 py-6 flex items-center space-x-3">
          <BookOpenIcon className="h-8 w-8" />
          <h1 className="text-2xl font-bold">ลบหนังสือ</h1>
        </div>
      </header>

      <div className="container mx-auto px-4 py-4">
        <button
          onClick={() => navigate("/store-manager/dashboard")}
          className="flex items-center space-x-2 px-4 py-2 bg-gray-800 text-white rounded-lg hover:bg-gray-900 transition"
        >
          <ArrowLeftIcon className="h-5 w-5" />
          <span>ย้อนกลับ</span>
        </button>
      </div>

      <div className="container mx-auto px-4 py-4">
        {books.length === 0 ? (
          <p className="text-center text-gray-500">ไม่มีหนังสือให้ลบ</p>
        ) : (
          <div className="grid grid-cols-2 lg:grid-cols-5 gap-6">
            {books.map((book) => (
              <div
                key={book.id}
                className="bg-white p-4 rounded-xl shadow flex flex-col justify-between"
              >
                {book.cover_image ? (
                  <img
                    src={book.cover_image}
                    alt={book.title}
                    className="w-full h-48 object-cover rounded-lg mb-4"
                  />
                ) : (
                  <div className="w-full h-48 bg-gray-200 flex items-center justify-center rounded-lg mb-4 text-gray-400">
                    ไม่มีรูปปก
                  </div>
                )}

                <div className="flex-1">
                  <h3 className="text-xl font-semibold mb-1">{book.title}</h3>
                  <p className="text-gray-500 mb-2">ผู้แต่ง: {book.author}</p>
                  {book.category && (
                    <p className="text-gray-400 text-sm mb-2">หมวดหมู่: {book.category}</p>
                  )}
                  {book.price && (
                    <p className="text-gray-700 font-medium">ราคา: {book.price} บาท</p>
                  )}
                </div>

                <button
                  onClick={() => setBookToDelete(book)}
                  className="flex items-center justify-center px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition mt-4"
                >
                  <TrashIcon className="h-5 w-5 mr-2" />
                  ลบหนังสือ
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {bookToDelete && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-xl shadow-lg max-w-sm w-full p-6 relative">
            <button
              onClick={() => setBookToDelete(null)}
              className="absolute top-3 right-3 text-gray-500 hover:text-gray-800"
            >
              <XIcon className="h-6 w-6" />
            </button>
            <h2 className="text-lg font-semibold mb-4">ยืนยันการลบ</h2>
            <p className="mb-6">
              คุณแน่ใจว่าต้องการลบหนังสือ "{bookToDelete.title}" หรือไม่?
            </p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setBookToDelete(null)}
                className="px-4 py-2 rounded-lg bg-gray-300 hover:bg-gray-400"
              >
                ยกเลิก
              </button>
              <button
                onClick={confirmDelete}
                className="px-4 py-2 rounded-lg bg-red-600 text-white hover:bg-red-700"
              >
                ลบเลย
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default DeleteBookPage;
