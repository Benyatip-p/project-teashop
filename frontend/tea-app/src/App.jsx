import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';

// Components
import Navbar from './components/Navbar';
import Footer from './components/Footer';
import NotFound from './components/Notfound';
import { ShopProvider } from "./context/ShopContext";

// Pages
import Homepage from './pages/Homepage';
import ContactPage from './pages/Contactpage';
import Aboutpage from './pages/Aboutpage';
import Productpage from './pages/Productpage';
import Favoritepage from './pages/Favoritepage';
import Cartpage from './pages/Cartpage';
import Profilepage from './pages/Profilepage';
import ProductDetailpage from './pages/ProductDetailpage';

function App() {
 return (
  <ShopProvider>
   <Router>
     <Routes>
       {/* Admin Routes - No Navbar/Footer
       <Route path="/login" element={<LoginPage />} />
       <Route path="/store-manager/add-book" element={<AddBookPage />} />
       <Route path="/store-manager/all-books" element={<AllBookPage />} /> */}
       
       {/* Public Routes - With Navbar/Footer */}
       <Route path="*" element={
         <div className="flex flex-col min-h-screen">
           <Navbar />
           <main className="flex-grow bg-gray-50">
             <Routes>
               <Route path="/" element={<Homepage />} />
               <Route path="/products" element={<Productpage />} />
               <Route path="/about" element={<Aboutpage />} />
               <Route path="/contact" element={<ContactPage />} />
               <Route path="/products/:id" element={<ProductDetailpage />} />
               <Route path="/favorites" element={<Favoritepage />} />
               <Route path="/cart" element={<Cartpage />} />
               <Route path="/profile" element={<Profilepage />} />
               <Route path="*" element={<NotFound />} />
             </Routes>
           </main>
           <Footer />
         </div>
       } />
     </Routes>
   </Router>
  </ShopProvider>
 );
}

export default App;