import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';

// Components
import Navbar from './components/Navbar';
import Footer from './components/Footer';
import NotFound from './components/Notfound';

// Pages
import Homepage from './pages/Homepage';
import ContactPage from './pages/Contactpage';
import Aboutpage from './pages/Aboutpage';

function App() {
 return (
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
               <Route path="/about" element={<Aboutpage />} />
               <Route path="/contact" element={<ContactPage />} />
               <Route path="*" element={<NotFound />} />
             </Routes>
           </main>
           <Footer />
         </div>
       } />
     </Routes>
   </Router>
 );
}

export default App;