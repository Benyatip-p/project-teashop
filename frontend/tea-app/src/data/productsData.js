// Sample book data for the bookstore
export const productsData = [
  {
    id: 1,
    title: 'Red Tea Berry',
    category: 'Red Tea',
    brand: 'Tea House',
    price: 299,
    originalPrice: 399,
    coverImage: '/images/products/berryTea.jpg',
    rating: 4.5,
    reviews: 54,
    discount: 25,
    isbn: '978-0-7432-7356-1',
    quantity: 50,
    mfyear: 1/12/2025,
    expyear: 25/6/2027,
    description: 'ชาแดงผสมเบอร์รี่รวมสูตรพิเศษ เพิ่มความสดชื่นและต้านอนุมูลอิสระ'
  },
  {
    id: 2,
    title: 'Black Tea chamomile',
    category: 'Black Tea',
    brand: 'Tea House',
    price: 189,
    originalPrice: 299,
    coverImage: '/images/products/chamomileTea.jpg',
    rating: 4.5,
    reviews: 24,
    discount: 25,
    isbn: '978-0-7432-7356-2',
    quantity: 50,
    mfyear: 1/12/2025,
    expyear: 25/6/2027,
    description: 'ชาดำผสมคาโมมายล์สูตรพิเศษ เพิ่มความผ่อนคลายและช่วยให้นอนหลับสบาย'
  },
  {
    id: 3,
    title: 'Black Tea Mint',
    category: 'Black Tea',
    brand: 'Tea House',
    price: 250,
    originalPrice: 415,
    coverImage: '/images/products/mintTea.jpg',
    rating: 4.5,
    reviews: 5,
    discount: 25,
    isbn: '978-0-7432-7356-3',
    quantity: 50,
    mfyear: 1/12/2025,
    expyear: 25/6/2027,
    description: 'ชาดำผสมมิ้นต์สูตรพิเศษ เพิ่มความสดชื่นและช่วยย่อยอาหาร'
  },
  {
    id: 4,
    title: 'Black Tea Lemon',
    category: 'Black Tea',
    brand: 'Tea House',
    price: 299,
    originalPrice: 399,
    coverImage: '/images/products/lemonTea.jpg',
    rating: 4.5,
    reviews: 34,
    discount: 25,
    isbn: '978-0-7432-7356-4',
    quantity: 50,
    mfyear: 1/12/2025,
    expyear: 25/6/2027,
    description: 'ชาดำผสมเลมอนสูตรพิเศษ เพิ่มความสดชื่นและช่วยย่อยอาหาร'
  },
  {
    id: 5,
    title: 'Organic Green Tea',
    category: 'Green Tea',
    brand: 'Tea House',
    price: 700,
    originalPrice: 780,
    coverImage: '/images/products/greentea.jpg',
    rating: 4.9,
    reviews: 44,
    discount: '',
    isbn: '978-0-7432-7356-5',
    quantity: 125,
    mfyear: 1/12/2025,
    expyear: 25/6/2027,
    description: 'ชาเขียวออร์แกนิคคุณภาพสูงจากธรรมชาติ ช่วยกระตุ้นการเผาผลาญและต้านอนุมูลอิสระ'
  },
  {
    id: 6,
    title: 'Matcha Green Tea Latte',
    category: 'Matcha',
    brand: 'Tea House',
    price: 400,
    originalPrice: 490,
    coverImage: '/images/products/matchaTea.jpg',
    rating: 4.5,
    reviews: 34,
    discount: 25,
    isbn: '978-0-7432-7356-6',
    quantity: 250,
    mfyear: 1/12/2025,
    expyear: 25/6/2027,
    description: 'มัทฉะเกรดพรีเมียม ช่วยเพิ่มพลังงานและสมาธิ พร้อมสารต้านอนุมูลอิสระสูง'
  },
  {
    id: 7,
    title: 'Blue Chinese Tea Pot',
    category: 'Small Pot',
    brand: 'Tea House',
    price: 700,
    originalPrice: 790,
    coverImage: '/images/products/smteapot.jpg',
    rating: 4.5,
    reviews: 34,
    discount: 25,
    isbn: '978-0-7432-7356-7',
    quantity: 250,
    mfyear: '' ,
    expyear: '',
    description: 'กาน้ำชาจีนขนาดเล็ก สีฟ้า ผลิตจากเซรามิกคุณภาพดี ทนความร้อนสูง เหมาะสำหรับชงชาเขียวและชาดำ'
  },
  {
    id: 8,
    title: 'Stone Tea Pot',
    category: 'Medium Pot',
    brand: 'Tea House',
    price: 590,
    originalPrice: 670,
    coverImage: '/images/products/mdteapot.jpg',
    rating: 4.5,
    reviews: 34,
    discount: 25,
    isbn: '978-0-7432-7356-8',
    quantity: 250,
    mfyear: '',
    expyear: '',
    description: 'กาน้ำชาหินขนาดกลาง ผลิตจากหินธรรมชาติ ทนความร้อนสูง เหมาะสำหรับชงชาหลากหลายประเภท'
  },
  {
    id: 9,
    title: 'Black Chinese Tea Pot',
    category: 'Large Pot',
    brand: 'Tea House',
    price: 1090,
    originalPrice: 1190,
    coverImage: '/images/products/lgteapot.jpg',
    rating: 4.5,
    reviews: 34,
    discount: 25,
    isbn: '978-0-7432-7356-9',
    quantity: 250,
    mfyear: '',
    expyear: '',
    description: 'กาน้ำชาจีนขนาดใหญ่ สีดำ ผลิตจากเซรามิกคุณภาพดี ทนความร้อนสูง เหมาะสำหรับชงชาเขียวและชาดำ'
  }
];

// Function to get all products
export const getAllProducts = () => {
  return productsData;
};

// Function to get a single product by ID
export const getProductById = (id) => {
  return productsData.find(product => product.id === parseInt(id));
};

// Function to get products by category
export const getProductsByCategory = (category) => {
  if (!category || category === 'all') return productsData;
  return productsData.filter(product => product.category === category);
};

// Function to search products
export const searchProducts = (query) => {
  const lowercaseQuery = query.toLowerCase();
  return productsData.filter(product => 
    product.title.toLowerCase().includes(lowercaseQuery) ||
    product.author.toLowerCase().includes(lowercaseQuery) ||
    product.category.toLowerCase().includes(lowercaseQuery)
  );
};

// Function to get featured products
export const getFeaturedProducts = (limit = 3) => {
  return  productsData
    .filter(product => product.rating >= 4.5)
    .slice(0, limit);
};

// Function to get new products
export const getNewProducts = (limit = 4) => {
  return productsData
    .filter(product => product.isNew)
    .slice(0, limit);
};

// Function to get discounted products
export const getDiscountedProducts = (limit = 4) => {
  return  productsData
    .filter(product => product.discount)
    .sort((a, b) => (b.discount || 0) - (a.discount || 0))
    .slice(0, limit);
};

export default productsData;