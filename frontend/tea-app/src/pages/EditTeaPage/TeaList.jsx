import { PencilIcon } from "@heroicons/react/outline";

const BookList = ({ books, onSelectBook }) => {
  return (
    <div>
      <h2 className="text-xl font-semibold mb-4">
        เลือกรายการหนังสือที่ต้องการแก้ไข
      </h2>
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-6">
        {books.map((book) => (
          <div
            key={book.id}
            className="bg-white p-6 rounded-xl shadow flex flex-col justify-between"
          >
            <div>
              {book.cover_image && (
                <img
                  src={book.cover_image}
                  alt={book.title}
                  className="w-full h-48 object-cover rounded-lg mb-4"
                />
              )}
              <h3 className="text-lg font-semibold mb-1">{book.title}</h3>
              <p className="text-gray-500 mb-4">ผู้แต่ง: {book.author}</p>
            </div>
            <button
              onClick={() => onSelectBook(book)}
              className="flex items-center justify-center px-4 py-2 bg-yellow-500 text-white rounded-lg hover:bg-yellow-600 transition"
            >
              <PencilIcon className="h-5 w-5 mr-2" />
              แก้ไข
            </button>
          </div>
        ))}
      </div>
    </div>
  );
};

export default BookList;