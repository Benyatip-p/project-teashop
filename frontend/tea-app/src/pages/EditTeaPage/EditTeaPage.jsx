import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { BookOpenIcon, ArrowLeftIcon } from "@heroicons/react/outline";
import BookList from "./TeaList";
import BookEditForm from "./TeaEditForm";

const EditBookPage = () => {
  const navigate = useNavigate();
  const [books, setBooks] = useState([]);
  const [selectedBook, setSelectedBook] = useState(null);
  const [loading, setLoading] = useState(true);

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
      } catch (err) {
        alert(err.message);
      } finally {
        setLoading(false);
      }
    };
    fetchBooks();
  }, []);

  if (loading) return <p className="text-center py-10">กำลังโหลด...</p>;

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="bg-gradient-to-r from-viridian-600 to-green-700 text-white shadow-lg">
        <div className="container mx-auto px-4 py-6 flex items-center space-x-3">
          <BookOpenIcon className="h-8 w-8" />
          <h1 className="text-2xl font-bold">edit products</h1>
        </div>
      </header>

      <div className="container mx-auto px-4 py-8">
        <button
          onClick={() => navigate(-1)}
          className="mb-4 flex items-center text-gray-700 hover:text-viridian-700"
        >
          <ArrowLeftIcon className="h-5 w-5 mr-2" />
          ย้อนกลับ
        </button>

        {!selectedBook ? (
          <BookList books={books} onSelectBook={setSelectedBook} />
        ) : (
          <BookEditForm
  book={selectedBook}
  onBack={() => setSelectedBook(null)} // กลับไป productsList
  onBookUpdated={(updated) =>
    setBooks((prev) => prev.map((b) => (b.id === updated.id ? updated : b)))
  }
/>
        )}
      </div>
    </div>
  );
};

export default EditBookPage;